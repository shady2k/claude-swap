"""A local HTTP proxy that carries one account's traffic to its real proxy.

An account may name a proxy that urllib cannot speak to: it can tunnel through
an ``http://`` proxy but cannot open TLS to the proxy itself (``https://``),
and it speaks no SOCKS. :class:`Bridge` closes that gap without teaching
cswap's request path a second transport — it listens on ``127.0.0.1:0`` and
speaks the plain HTTP proxy protocol to everything local (``urllib`` inside
cswap, and Claude Code when a launch points its ``*_PROXY`` variables at the
bridge), while every connection it accepts is opened through the account's
proxy:

- ``https://[user:pass@]host[:port]``: TLS to the proxy — the system trust
  store, SNI = the proxy's host, :func:`default_context` — then one
  ``CONNECT target:port`` carrying ``Proxy-Authorization`` when the URL has
  credentials, then the bytes are copied in both directions. TLS to the
  target therefore runs through that tunnel untouched: TLS-over-TLS with this
  process never terminating the inner connection. Plain HTTP requests instead
  go to the TLS proxy in absolute form, without a tunnel.
- ``socks5h://[user:pass@]host[:port]`` and its alias ``socks5://`` (RFC
  1928): a domain target travels as ``ATYP=0x03`` and is never resolved here,
  so the proxy does the DNS (an IP literal uses ``ATYP=0x01``/``0x04``); user
  name and password travel by RFC 1929 when the URL has them.

Fail-closed is the whole point: a connection that cannot be opened through
the account's proxy is refused to the local client — ``407`` for rejected
credentials, a 3xx the proxy answered to ``CONNECT``, ``502``/``504`` otherwise
— and is never opened directly. The refusals carry static text: the account's
URL, its credentials and the proxy's own reply text never travel back to a client.
:func:`connect` is the same tunnel without the local server, for the launch's
pre-start ``probe`` and for tests.

The module is a leaf: it imports nothing from the package, and the route is
whatever object carries ``scheme``/``host``/``port``/``username``/``password``
(:class:`account_proxy.ProxyRoute` in practice). Nothing here is a general
proxy either: the one route given to the constructor is the only way out, a
request body is copied as bytes rather than parsed, and the listener answers
loopback only.
"""

from __future__ import annotations

import base64
import ipaddress
import socket
import ssl
import threading
import urllib.error
import urllib.parse

#: Seconds one connection to the account's proxy (TLS handshake, ``CONNECT``
#: or the SOCKS5 greeting) may take. A launch's pre-start probe passes its own,
#: shorter budget.
TIMEOUT_S = 10.0

#: Largest request head the local side is read before it is refused. Clients
#: send a request line and a handful of headers; this only bounds a malformed
#: one.
MAX_HEAD_BYTES = 64 * 1024

#: Default port of each scheme this module can drive.
DEFAULT_PORTS = {"https": 443, "socks5h": 1080, "socks5": 1080}

#: How long ``accept`` waits before the serving loop looks at its stop flag.
_ACCEPT_POLL_S = 0.2

#: Bytes one copy step carries.
_BUFFER_BYTES = 64 * 1024

#: Hop-by-hop headers a forwarded ``http://`` request loses: they describe the
#: client's connection to us, not the one this bridge opened.
#: ``Transfer-Encoding`` is not here although RFC 7230 calls it hop-by-hop: the
#: body below the head is copied byte for byte, so removing the header would
#: leave a chunked body no origin could read.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
    }
)

#: SOCKS5 reply codes of RFC 1928, for the refusal message. The text is ours;
#: only the number travels.
_SOCKS5_REPLIES = {
    1: "general SOCKS server failure",
    2: "connections not allowed by the ruleset",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class BridgeError(Exception):
    """A connection the account's proxy did not open.

    ``kind`` is one of ``"auth"`` (the proxy rejected the URL's credentials),
    ``"redirect"`` (it answered a 3xx instead of a tunnel), ``"refused"`` (it
    answered another status or SOCKS5 reply), ``"timeout"`` (it stopped
    answering), ``"network"`` (another socket error), and ``"unreachable"``
    (an incomplete or invalid proxy reply). ``status`` holds the HTTP code of
    a refusal, if any, without the proxy's phrase.

    The message never carries the URL, its credentials or the proxy's own
    reply text.
    """

    def __init__(self, kind: str, message: str, status: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.status = status


class TLSSetupError(urllib.error.URLError):
    """TLS to the proxy failed before the origin request could be sent."""


class _BadRequest(Exception):
    """The local client sent something this bridge will not forward."""


def default_context() -> ssl.SSLContext:
    """The TLS context a connection to an ``https://`` proxy uses.

    ``ssl.create_default_context()``: the system trust store, certificate and
    host-name verification on, with SNI set from the proxy's host. Tests
    replace this module attribute with a context that trusts their own CA —
    nothing in production does.
    """
    return ssl.create_default_context()


#: The plain ``ssl.SSLContext`` class, whatever replaced it in ``ssl``.
#: ``truststore.inject_into_ssl()`` — which ``cli.main`` calls — sets
#: ``ssl.SSLContext`` to a subclass whose ``wrap_socket`` verifies the peer
#: itself, so the plain class is found through the replacement's MRO rather
#: than captured at import time (the injection may already have happened).
_PLAIN_SSL_CONTEXT = next(
    (
        base
        for base in ssl.SSLContext.__mro__
        if base.__module__ == "ssl" and base.__name__ == "SSLContext"
    ),
    ssl.SSLContext,
)


def connect(
    route,
    host: str,
    port: int,
    timeout: float = TIMEOUT_S,
    context: ssl.SSLContext | None = None,
) -> socket.socket:
    """A socket to ``host:port`` opened through ``route``'s proxy.

    The returned socket carries the target's bytes: for an ``https://`` proxy
    it is that proxy's TLS connection (the target TLS session, if any, runs
    through it), for a SOCKS5 one the proxy's plain connection to the target.
    Both are blocking with no timeout once the tunnel is open.

    Raises:
        BridgeError: the proxy answered and did not open the tunnel.
        OSError: the proxy could not be reached at all, or stopped answering
            — including :class:`ssl.SSLCertVerificationError` and the other TLS
            failures, which are the caller's business (a refused proxy
            certificate is not an unreachable host).
    """
    tunnel, _rest = _connect(route, host, port, timeout, context)
    return tunnel


def _connect(
    route,
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext | None,
    bridge: Bridge | None = None,
) -> tuple[socket.socket, bytes]:
    scheme = _scheme_of(route)
    timeout = TIMEOUT_S if not timeout or timeout <= 0 else timeout
    if scheme == "https":
        return _https_tunnel(route, host, port, timeout, context, bridge)
    if scheme in ("socks5h", "socks5"):
        return _socks5_tunnel(route, host, port, timeout, bridge), b""
    raise ValueError(f"no tunnel exists for a {scheme}:// proxy")


class Bridge:
    """A loopback HTTP proxy forwarding every connection through one route.

    ``Bridge(route)`` binds ``127.0.0.1:0`` and starts serving; ``url`` is the
    address a client is pointed at and ``port`` the same without the scheme.
    :meth:`close` (or the context manager) stops the loop, drops every live
    connection and joins the threads, so nothing outlives the block.

    ``failure`` is the first upstream error this bridge recorded, for callers
    that drive it from the same process and need the typed reason rather than
    the status a local client saw: :meth:`account_proxy.ProxyRoute.open` opens
    one bridge per request and re-raises it. A long-lived bridge (a launch's)
    never reads it — the child only sees the status codes.
    """

    def __init__(
        self,
        route,
        timeout: float = TIMEOUT_S,
        context: ssl.SSLContext | None = None,
    ):
        self._route = route
        self._timeout = TIMEOUT_S if not timeout or timeout <= 0 else timeout
        self._context = context
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._workers: list[threading.Thread] = []
        self._failure: BaseException | None = None
        self._closed = False
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen(64)
            self._listener.settimeout(_ACCEPT_POLL_S)
        except BaseException:
            self._listener.close()
            raise
        self._thread = threading.Thread(
            target=self._serve, name="proxy-bridge", daemon=True
        )
        self._thread.start()

    # -- public surface ---------------------------------------------------

    @property
    def host(self) -> str:
        """The loopback address the bridge listens on."""
        return "127.0.0.1"

    @property
    def port(self) -> int:
        """The port bound for this bridge, chosen by the OS."""
        return self._listener.getsockname()[1]

    @property
    def url(self) -> str:
        """``http://127.0.0.1:<port>`` — what a client is pointed at."""
        return f"http://{self.host}:{self.port}"

    @property
    def failure(self) -> BaseException | None:
        """The first upstream error this bridge recorded, if any."""
        with self._lock:
            return self._failure

    def close(self) -> None:
        """Stop serving, drop every connection and join the threads."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
        _close_socket(self._listener)
        self._thread.join(5.0)
        with self._lock:
            connections = list(self._connections)
            workers = list(self._workers)
        for connection in connections:
            _close_socket(connection)
        for worker in workers:
            worker.join(5.0)

    def __enter__(self) -> "Bridge":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- serving ----------------------------------------------------------

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _address = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                self._track(client)
            except OSError:
                _close_socket(client)
                return
            worker = threading.Thread(
                target=self._handle,
                args=(client,),
                name="proxy-bridge-connection",
                daemon=True,
            )
            with self._lock:
                # A launch's bridge serves many connections; finished workers
                # are dropped so their threads do not accumulate.
                self._workers = [item for item in self._workers if item.is_alive()]
                self._workers.append(worker)
            worker.start()

    def _handle(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        upload: threading.Thread | None = None
        try:
            # The listener polls, so an accepted socket can carry that timeout
            # in some interpreter/OS combinations; a connection here must
            # block for as long as its peer does, or an idle moment reads as
            # end-of-stream and truncates the reply being copied. It runs
            # inside the ``try`` because :meth:`close` closes this socket from
            # the thread that owns the bridge, which fails the call.
            client.settimeout(None)
            head, rest = _read_head(client)
            request = _parse_head(head)
            forward_absolute = False
            if request.method == "CONNECT":
                host, port = _authority(request.target)
                upstream, received = _connect(
                    self._route, host, port, self._timeout, self._context, self
                )
                client.sendall(
                    b"HTTP/1.1 200 Connection Established\r\n\r\n" + received
                )
                if rest:
                    upstream.sendall(rest)
            else:
                forward_absolute = _scheme_of(self._route) == "https"
                host, port, head = _absolute_form(
                    request, self._route if forward_absolute else None
                )
                if forward_absolute:
                    upstream = _dial_https(
                        self._route, self._timeout, self._context, self
                    )
                    upstream.settimeout(None)
                else:
                    upstream, _ = _connect(
                        self._route, host, port, self._timeout, self._context, self
                    )
                upstream.sendall(head + rest)
            upload = threading.Thread(
                target=_pump, args=(client, upstream), daemon=True
            )
            upload.start()
            if forward_absolute:
                _forward_http_response(upstream, client)
            _pump(upstream, client)
            if not forward_absolute:
                upload.join()
                upload = None
        except _BadRequest:
            _respond(client, 400, "Bad Request")
        except (BridgeError, OSError) as e:
            if self._stop.is_set():
                return
            if isinstance(e, ssl.SSLError):
                self._record(TLSSetupError(e) if upstream is None else e)
                _respond(client, 502, "Bad Gateway")
            else:
                error = (
                    e if isinstance(e, BridgeError) else _connection_failure(e)
                )
                self._record(error)
                _respond(client, _status_of(error), _reason_of(error))
        finally:
            # A final HTTP response can arrive while upload is waiting for
            # the body. Reply (including any refusal) and close before joining.
            _drop(client, self)
            _drop(upstream, self)
            if upload is not None:
                upload.join()

    def _record(self, error: BaseException) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = error

    def _track(self, connection: socket.socket) -> None:
        with self._lock:
            if self._stop.is_set():
                raise OSError("bridge is closed")
            self._connections.add(connection)

    def _wrap_tls(
        self, raw: socket.socket, context: ssl.SSLContext, host: str
    ) -> ssl.SSLSocket:
        """TLS to the proxy, handshaken, tracked so :meth:`close` can end it.

        A plain ``ssl.SSLContext`` hands back the TLS socket before the
        handshake: the descriptor is tracked under this lock and the handshake
        then runs outside it, so ``close()`` ends a handshake a silent proxy
        never answers.

        A subclass verifies the peer inside ``wrap_socket()`` and ignores
        ``do_handshake_on_connect=False`` — ``truststore 0.10.4``, which
        ``cli.main`` injects into ``ssl``, verifies the chain of the socket it
        just built and refuses one with no certificate yet ("Peer sent no
        certificates to verify"). Such a context therefore has to run the
        handshake itself; its socket replaces ``raw`` here as soon as it
        exists, and a ``close()`` that already happened ends it at once.

        Raises with neither a tracked socket nor an open descriptor left
        behind.
        """
        if type(context) is not _PLAIN_SSL_CONTEXT:
            with self._lock:
                if self._stop.is_set():
                    raise OSError("bridge is closed")
            try:
                tls = context.wrap_socket(raw, server_hostname=host)
            except BaseException:
                self._untrack(raw)
                raise
            with self._lock:
                self._connections.discard(raw)
                self._connections.add(tls)
                stopped = self._stop.is_set()
            if stopped:
                self._untrack(tls)
                _close_socket(tls)
                raise OSError("bridge is closed")
            return tls
        with self._lock:
            if self._stop.is_set():
                raise OSError("bridge is closed")
            tls = context.wrap_socket(
                raw, server_hostname=host, do_handshake_on_connect=False
            )
            self._connections.discard(raw)
            self._connections.add(tls)
        try:
            tls.do_handshake()
        except BaseException:
            self._untrack(tls)
            _close_socket(tls)
            raise
        return tls

    def _untrack(self, connection: socket.socket) -> None:
        with self._lock:
            self._connections.discard(connection)


class _Request:
    """One parsed local request line and the headers that followed it."""

    __slots__ = ("method", "target", "version", "headers")

    def __init__(self, method, target, version, headers):
        self.method = method
        self.target = target
        self.version = version
        self.headers = headers


def _read_head(
    connection: socket.socket, data: bytes = b""
) -> tuple[bytes, bytes]:
    """Read through the blank line, keeping any bytes beyond it."""
    while True:
        end = data.find(b"\r\n\r\n")
        if end != -1 and end + 4 <= MAX_HEAD_BYTES:
            return data[:end + 4], data[end + 4:]
        if len(data) >= MAX_HEAD_BYTES:
            raise _BadRequest("head too large")
        chunk = connection.recv(4096)
        if not chunk:
            raise _BadRequest("incomplete head")
        data += chunk


def _parse_head(head: bytes) -> _Request:
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) != 3:
        raise _BadRequest("request line")
    method, target, version = parts
    headers = []
    for line in lines[1:]:
        if not line:
            break
        name, separator, value = line.decode("latin-1").partition(":")
        if not separator:
            raise _BadRequest("header line")
        headers.append((name.strip(), value.strip()))
    return _Request(method.upper(), target, version, headers)


def _authority(value: str) -> tuple[str, int]:
    """``host:port`` / ``[v6]:port`` from a ``CONNECT`` target."""
    try:
        parts = urllib.parse.urlsplit("//" + value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise _BadRequest("authority") from None
    if not host:
        raise _BadRequest("authority")
    return host, port if port is not None else 443


def _absolute_form(request: _Request, https_route=None) -> tuple[str, int, bytes]:
    """A plain HTTP request in the form its next peer uses.

    To a TLS proxy this goes in absolute form with that proxy's credentials.
    A SOCKS5 tunnel goes straight to the origin, which needs origin form.
    HTTPS targets must use CONNECT; a plain request cannot speak origin TLS.
    """
    try:
        parts = urllib.parse.urlsplit(request.target)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise _BadRequest("absolute URL") from None
    if parts.scheme != "http" or not host:
        raise _BadRequest("absolute URL")
    if port is None:
        port = 80
    selector = parts.path or "/"
    if parts.query:
        selector += "?" + parts.query
    target = request.target if https_route is not None else selector
    lines = [f"{request.method} {target} {request.version}"]
    names = {name.lower() for name, _value in request.headers}
    if "host" not in names:
        authority = f"[{host}]" if ":" in host else host
        lines.append(f"Host: {authority}:{port}")
    for name, value in request.headers:
        if name.lower() in _HOP_BY_HOP or name.lower().startswith("proxy-"):
            continue
        lines.append(f"{name}: {value}")
    if https_route is not None:
        authorization = _authorization(https_route)
        if authorization is not None:
            lines.append(f"Proxy-Authorization: {authorization}")
    lines.append("Connection: close")
    return host, port, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def _forward_http_response(source: socket.socket, destination: socket.socket) -> None:
    """Forward the response head and its tail, except for 407."""
    rest = b""
    while True:
        head, rest, status = _response_head(source, rest)
        if status == 407:
            raise _refusal(status)
        if 100 <= status < 200 and status != 101:
            destination.sendall(head)
            continue
        destination.sendall(head + rest)
        return


def _pump(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            data = source.recv(_BUFFER_BYTES)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    # SSLSocket.shutdown() disposes of TLS state used by the other pump.
    if not isinstance(destination, ssl.SSLSocket):
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _respond(connection: socket.socket, status: int, reason: str) -> None:
    """Answer the local client with a static status line."""
    try:
        connection.sendall(
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii")
        )
    except OSError:
        pass


def _status_of(error: BridgeError) -> int:
    """The status a local client sees for an upstream refusal.

    The proxy's own code travels on when it was a client or server error, so
    a local client can tell a blocked target (403) from broken credentials
    (407) without reading this module's text.
    """
    if error.kind == "auth":
        return 407
    if error.status is not None and 300 <= error.status <= 599:
        return error.status
    if error.kind in ("unreachable", "timeout"):
        return 504
    return 502


def _reason_of(error: BridgeError) -> str:
    if error.kind == "auth":
        return "Proxy Authentication Required"
    if error.kind == "redirect":
        return "Found"
    if error.kind in ("unreachable", "timeout"):
        return "Gateway Timeout"
    return "Bad Gateway"


def _connection_failure(error: OSError) -> BridgeError:
    if isinstance(error, TimeoutError):
        return BridgeError("timeout", "the account's proxy connection hit a timeout")
    return BridgeError(
        "network", "the account's proxy connection failed (network error)"
    )


def _drop(connection: socket.socket | None, bridge: Bridge | None) -> None:
    if connection is not None:
        if bridge is not None:
            bridge._untrack(connection)
        _close_socket(connection)


def _close_socket(connection: socket.socket | None) -> None:
    if connection is None:
        return
    try:
        socket.socket.shutdown(connection, socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        connection.close()
    except OSError:
        pass


def _scheme_of(route) -> str:
    return (getattr(route, "scheme", "http") or "http").lower()


def _port_of(route) -> int:
    port = getattr(route, "port", None)
    if isinstance(port, int) and port > 0:
        return port
    return DEFAULT_PORTS.get(_scheme_of(route), 443)


def _credentials(route) -> tuple[str, str] | None:
    username = getattr(route, "username", None)
    if username is None:
        return None
    return str(username), str(getattr(route, "password", None) or "")


def _authorization(route) -> str | None:
    """The ``Proxy-Authorization`` value, or ``None`` without a user name."""
    credentials = _credentials(route)
    if credentials is None:
        return None
    pair = f"{credentials[0]}:{credentials[1]}".encode()
    return "Basic " + base64.b64encode(pair).decode("ascii")


def _authority_of(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _dial(route, timeout: float, bridge: Bridge | None) -> socket.socket:
    connection = socket.create_connection(
        (route.host, _port_of(route)), timeout=timeout
    )
    if bridge is not None:
        try:
            bridge._track(connection)
        except OSError:
            _close_socket(connection)
            raise
    return connection


def _dial_https(
    route, timeout: float, context: ssl.SSLContext | None, bridge: Bridge | None
) -> ssl.SSLSocket:
    context = context or default_context()
    raw = _dial(route, timeout, bridge)
    if bridge is None:
        try:
            return context.wrap_socket(raw, server_hostname=route.host)
        except BaseException:
            _close_socket(raw)
            raise

    # The handshake happens inside _wrap_tls, which leaves nothing tracked or
    # open when it raises; closing ``raw`` here covers a socket it detached.
    try:
        return bridge._wrap_tls(raw, context, route.host)
    except BaseException:
        _drop(raw, bridge)
        raise


def _https_tunnel(
    route,
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext | None,
    bridge: Bridge | None,
) -> tuple[ssl.SSLSocket, bytes]:
    """TLS to the proxy, then one CONNECT; retain any first tunnel bytes."""
    tls = _dial_https(route, timeout, context, bridge)
    try:
        authority = _authority_of(host, port)
        lines = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
        ]
        authorization = _authorization(route)
        if authorization is not None:
            lines.append(f"Proxy-Authorization: {authorization}")
        tls.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        _head, rest, status = _response_head(tls)
        if status == 200:
            tls.settimeout(None)
            return tls, rest
        raise _refusal(status)
    except BaseException:
        _drop(tls, bridge)
        raise


def _response_head(
    connection: socket.socket, rest: bytes = b""
) -> tuple[bytes, bytes, int]:
    try:
        head, rest = _read_head(connection, rest)
    except _BadRequest:
        raise BridgeError(
            "unreachable", "the account's proxy did not send a complete HTTP reply"
        ) from None
    line = head.split(b"\r\n", 1)[0].split(b" ", 2)
    if len(line) < 2 or not line[0].startswith(b"HTTP/") or (
        len(line[1]) != 3 or not line[1].isdigit()
    ):
        raise BridgeError(
            "unreachable", "the account's proxy did not answer a proxy reply"
        )
    return head, rest, int(line[1])


def _refusal(status: int) -> BridgeError:
    """A typed refusal, without any server-supplied text."""
    if status == 407:
        return BridgeError(
            "auth",
            "the proxy rejected the credentials in its URL (HTTP 407)",
            status=status,
        )
    if 300 <= status < 400:
        return BridgeError(
            "redirect",
            f"the proxy answered HTTP {status} to CONNECT",
            status=status,
        )
    return BridgeError(
        "refused",
        f"the proxy answered HTTP {status} to CONNECT instead of opening "
        "the tunnel",
        status=status,
    )


def _socks5_tunnel(
    route, host: str, port: int, timeout: float, bridge: Bridge | None
) -> socket.socket:
    """A SOCKS5 ``CONNECT`` with remote DNS and optional RFC 1929 auth."""
    socks = _dial(route, timeout, bridge)
    try:
        credentials = _credentials(route)
        methods = [0x00] if credentials is None else [0x00, 0x02]
        socks.sendall(bytes([5, len(methods), *methods]))
        version, method = _recv_exact(socks, 2)
        if version != 5:
            raise BridgeError(
                "unreachable", "the proxy did not answer a SOCKS5 greeting"
            )
        if method == 0xFF or (method == 0x02 and credentials is None):
            raise BridgeError(
                "auth", "the SOCKS5 proxy refused every authentication method"
            )
        if method == 0x02:
            _socks5_authenticate(socks, *credentials)
        elif method != 0x00:
            raise BridgeError(
                "unreachable",
                "the SOCKS5 proxy chose an authentication method this bridge "
                "does not speak",
            )
        socks.sendall(
            bytes([5, 1, 0])
            + _socks5_address(host)
            + (port & 0xFFFF).to_bytes(2, "big")
        )
        version, reply, _reserved, address_type = _recv_exact(socks, 4)
        if version != 5:
            raise BridgeError(
                "unreachable", "the proxy did not answer a SOCKS5 reply"
            )
        _discard_socks5_address(socks, address_type)
        if reply != 0:
            raise BridgeError(
                "refused",
                "the SOCKS5 proxy did not open the tunnel "
                f"({_SOCKS5_REPLIES.get(reply, f'reply {reply}')})",
            )
        socks.settimeout(None)
        return socks
    except BaseException:
        _drop(socks, bridge)
        raise


def _socks5_authenticate(socks: socket.socket, username: str, password: str) -> None:
    """RFC 1929 user name/password sub-negotiation."""
    user = _socks5_text(username)
    secret = _socks5_text(password)
    socks.sendall(bytes([1, len(user)]) + user + bytes([len(secret)]) + secret)
    version, status = _recv_exact(socks, 2)
    if version != 1 or status != 0:
        raise BridgeError(
            "auth", "the SOCKS5 proxy rejected the user name or password"
        )


def _socks5_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 255:
        # RFC 1929 gives the length one byte; a longer field cannot be sent.
        raise BridgeError(
            "auth", "the SOCKS5 user name or password is too long to send"
        )
    return encoded


def _socks5_address(host: str) -> bytes:
    """``ATYP`` + address for a SOCKS5 request, resolving nothing.

    A domain is sent as text (``ATYP=0x03``): the proxy does the DNS, which is
    the whole point of ``socks5h``. An IP literal needs no name and goes as
    the matching address type.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return (b"\x01" if address.version == 4 else b"\x04") + address.packed
    try:
        name = host.encode("idna")
    except UnicodeError:
        raise BridgeError(
            "unreachable", "the target's host name cannot be sent as a domain"
        ) from None
    if not name or len(name) > 255:
        raise BridgeError(
            "unreachable", "the target's host name is too long for SOCKS5"
        )
    return b"\x03" + bytes([len(name)]) + name


def _discard_socks5_address(socks: socket.socket, address_type: int) -> None:
    """Read the bound address a SOCKS5 reply carries; nothing uses it."""
    if address_type == 0x01:
        _recv_exact(socks, 4)
    elif address_type == 0x04:
        _recv_exact(socks, 16)
    elif address_type == 0x03:
        (length,) = _recv_exact(socks, 1)
        _recv_exact(socks, length)
    else:
        raise BridgeError(
            "unreachable", "the SOCKS5 proxy answered an unknown address type"
        )
    _recv_exact(socks, 2)  # bound port


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    """Exactly ``size`` bytes, or a refusal instead of a short read."""
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise BridgeError(
                "unreachable", "the account's proxy closed the connection"
            )
        data += chunk
    return data

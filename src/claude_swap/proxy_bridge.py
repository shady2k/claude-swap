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
  process never terminating the inner connection.
- ``socks5h://[user:pass@]host[:port]`` and its alias ``socks5://`` (RFC
  1928): a domain target travels as ``ATYP=0x03`` and is never resolved here,
  so the proxy does the DNS (an IP literal uses ``ATYP=0x01``/``0x04``); user
  name and password travel by RFC 1929 when the URL has them.

Fail-closed is the whole point: a connection that cannot be opened through
the account's proxy is refused to the local client — ``407`` for rejected
credentials, a 3xx the proxy itself answered, ``502``/``504`` otherwise — and
is never opened directly. The refusals carry static text: the account's URL,
its credentials and the proxy's own reply text never travel back to a client.
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
    answered another status or SOCKS5 reply) and ``"unreachable"`` (the proxy
    closed the connection, answered something that is not the protocol, or
    named an address this bridge cannot send). ``status`` is the HTTP status of
    a refused ``CONNECT`` when there was one, so a caller can report the code
    without the proxy's phrase.

    The message never carries the URL, its credentials or the proxy's own
    reply text.
    """

    def __init__(self, kind: str, message: str, status: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.status = status


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
    scheme = _scheme_of(route)
    timeout = TIMEOUT_S if not timeout or timeout <= 0 else timeout
    if scheme == "https":
        return _https_tunnel(route, host, port, timeout, context)
    if scheme in ("socks5h", "socks5"):
        return _socks5_tunnel(route, host, port, timeout)
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
            self._track(client)
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
        # The listener polls, so an accepted socket can carry that timeout in
        # some interpreter/OS combinations; a connection here must block for
        # as long as its peer does, or an idle moment reads as end-of-stream
        # and truncates the reply being copied.
        client.settimeout(None)
        upstream: socket.socket | None = None
        try:
            request = _parse_head(_read_head(client))
            if request.method == "CONNECT":
                host, port = _authority(request.target)
                upstream = self._open(host, port)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                host, port, head = _absolute_form(request)
                upstream = self._open(host, port)
                upstream.sendall(head)
            _relay(client, upstream)
        except _BadRequest:
            _respond(client, 400, "Bad Request")
        except BridgeError as e:
            self._record(e)
            _respond(client, _status_of(e), _reason_of(e))
        except ssl.SSLError as e:
            # A proxy certificate this process refused, or a TLS failure while
            # speaking to it. The client can only be told "bad gateway"; the
            # typed error stays available through ``failure``.
            self._record(e)
            _respond(client, 502, "Bad Gateway")
        except OSError as e:
            self._record(
                BridgeError(
                    "unreachable",
                    "the account's proxy did not answer on its address "
                    f"({type(e).__name__})",
                )
            )
            _respond(client, 504, "Gateway Timeout")
        finally:
            if upstream is not None:
                self._untrack(upstream)
                _close_socket(upstream)
            self._untrack(client)
            _close_socket(client)

    def _open(self, host: str, port: int) -> socket.socket:
        try:
            upstream = connect(
                self._route, host, port, timeout=self._timeout, context=self._context
            )
        except BridgeError:
            raise
        except ssl.SSLError:
            raise
        except OSError as e:
            raise BridgeError(
                "unreachable",
                "the account's proxy did not answer on its address "
                f"({type(e).__name__})",
            ) from None
        self._track(upstream)
        return upstream

    def _record(self, error: BaseException) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = error

    def _track(self, connection: socket.socket) -> None:
        with self._lock:
            self._connections.add(connection)

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


def _read_head(connection: socket.socket) -> bytes:
    """The local request head, up to and including its blank line."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_HEAD_BYTES:
            raise _BadRequest("request head too large")
    if not data:
        raise _BadRequest("no request")
    return data


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


def _absolute_form(request: _Request) -> tuple[str, int, bytes]:
    """The target of an absolute-form request, and its head in origin form.

    An ``http://`` URL arrives as a whole — ``urllib`` sends one when the
    target is plain — so the bridge opens a tunnel to that origin through the
    account's proxy and writes the same request there in origin form, where
    the proxy is no longer part of the exchange.

    An ``https://`` target never arrives this way: every client tunnels it with
    ``CONNECT``, and writing a plaintext request into a TLS port would fail
    confusingly. Such a request is answered ``400`` instead.
    """
    parts = urllib.parse.urlsplit(request.target)
    if parts.scheme != "http" or not parts.hostname:
        raise _BadRequest("absolute URL")
    host = parts.hostname
    try:
        port = parts.port
    except ValueError:
        raise _BadRequest("port") from None
    if port is None:
        port = 80
    selector = parts.path or "/"
    if parts.query:
        selector += "?" + parts.query
    lines = [f"{request.method} {selector} {request.version}"]
    names = {name.lower() for name, _value in request.headers}
    if "host" not in names:
        authority = f"[{host}]" if ":" in host else host
        lines.append(f"Host: {authority}:{port}")
    for name, value in request.headers:
        if name.lower() in _HOP_BY_HOP:
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    return host, port, ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def _relay(left: socket.socket, right: socket.socket) -> None:
    """Copy bytes both ways until both directions are closed."""
    workers = [
        threading.Thread(target=_pump, args=(left, right), daemon=True),
        threading.Thread(target=_pump, args=(right, left), daemon=True),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()


def _pump(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            data = source.recv(_BUFFER_BYTES)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
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
    if error.kind == "unreachable":
        return 504
    return 502


def _reason_of(error: BridgeError) -> str:
    if error.kind == "auth":
        return "Proxy Authentication Required"
    if error.kind == "redirect":
        return "Found"
    if error.kind == "unreachable":
        return "Gateway Timeout"
    return "Bad Gateway"


def _close_socket(connection: socket.socket | None) -> None:
    if connection is None:
        return
    try:
        connection.shutdown(socket.SHUT_RDWR)
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


def _https_tunnel(
    route,
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext | None,
) -> socket.socket:
    """TLS to the proxy, one ``CONNECT``, and the TLS connection back."""
    raw = socket.create_connection((route.host, _port_of(route)), timeout=timeout)
    try:
        raw.settimeout(timeout)
        tls = (context or default_context()).wrap_socket(
            raw, server_hostname=route.host
        )
    except BaseException:
        raw.close()
        raise
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
        status = _connect_status(_read_head(tls))
        if status == 200:
            tls.settimeout(None)
            return tls
        raise _refusal(status)
    except BaseException:
        _close_socket(tls)
        raise


def _connect_status(head: bytes) -> int:
    """The status code of a proxy's ``CONNECT`` reply."""
    line = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
    if len(line) < 2 or not line[1].isdigit():
        raise BridgeError(
            "unreachable", "the account's proxy did not answer a proxy reply"
        )
    return int(line[1])


def _refusal(status: int) -> BridgeError:
    """The typed refusal for a non-200 ``CONNECT`` reply."""
    if status == 407:
        return BridgeError(
            "auth",
            "the proxy rejected the credentials in its URL (HTTP 407)",
            status=status,
        )
    if 300 <= status < 400:
        return BridgeError(
            "redirect",
            f"the proxy answered HTTP {status} to CONNECT instead of opening "
            "the tunnel",
            status=status,
        )
    return BridgeError(
        "refused",
        f"the proxy answered HTTP {status} to CONNECT instead of opening "
        "the tunnel",
        status=status,
    )


def _socks5_tunnel(route, host: str, port: int, timeout: float) -> socket.socket:
    """A SOCKS5 ``CONNECT`` with remote DNS and optional RFC 1929 auth."""
    socks = socket.create_connection(
        (route.host, _port_of(route)), timeout=timeout
    )
    try:
        socks.settimeout(timeout)
        credentials = _credentials(route)
        methods = [0x00] if credentials is None else [0x00, 0x02]
        socks.sendall(bytes([5, len(methods), *methods]))
        version, method = _recv_exact(socks, 2)
        if version != 5:
            raise BridgeError(
                "unreachable", "the proxy did not answer a SOCKS5 greeting"
            )
        if method == 0xFF:
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
        _close_socket(socks)
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

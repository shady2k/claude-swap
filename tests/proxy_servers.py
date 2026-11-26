"""Loopback proxies and origins the proxy tests run against.

Everything here binds ``127.0.0.1:0`` and reaches nothing but another loopback
socket, so the suite's network guard (``tests/conftest.py``) is never the
reason a test passes. The one exception is deliberate: a SOCKS5 request names
its target as a domain, and if the code under test resolved that name locally
the guard would refuse the lookup and the test would fail — which is exactly
the remote-DNS property it is there to prove.

The certificates in ``tests/fixtures/proxy_bridge`` are a throwaway CA and two
leaf certificates for ``127.0.0.1``/``localhost``, made with:

    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \\
        -days 3650 -subj "/CN=claude-swap test CA" \\
        -addext "basicConstraints=critical,CA:TRUE" \\
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \\
        -subj "/CN=127.0.0.1"
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \\
        -CAcreateserial -out server.pem -days 3650 -extfile server.ext

``server.ext`` is ``subjectAltName=IP:127.0.0.1,DNS:localhost`` with
``basicConstraints=critical,CA:FALSE``, ``keyUsage=critical,digitalSignature,
keyEncipherment`` and ``extendedKeyUsage=serverAuth``. ``untrusted.pem`` and
``untrusted.key`` are a second, self-signed pair for the same names that no
test trust store contains, so a certificate it presents is refused.
"""

from __future__ import annotations

import http.server
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from claude_swap import account_proxy, proxy_bridge

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "proxy_bridge"

_CA_FILE = FIXTURE_DIR / "ca.pem"
_SERVER_CERT = FIXTURE_DIR / "server.pem"
_SERVER_KEY = FIXTURE_DIR / "server.key"
_UNTRUSTED_CERT = FIXTURE_DIR / "untrusted.pem"
_UNTRUSTED_KEY = FIXTURE_DIR / "untrusted.key"

#: Seconds a fake server waits for the next bytes of a conversation.
_TIMEOUT_S = 10.0


#: The plain ``ssl.SSLContext`` class, whatever replaced it in ``ssl``.
#: ``truststore.inject_into_ssl()`` — which ``cli.main`` calls — swaps
#: ``ssl.SSLContext`` for the rest of the process with a subclass whose
#: ``wrap_socket`` verifies the peer against the OS store: it cannot serve TLS
#: at all, and it ignores a context's own trust anchors. Nothing undoes that,
#: and the injection may happen before this module is even imported, so the
#: plain class is found through the replacement's MRO instead of being
#: captured at import time.
_PLAIN_CONTEXT = next(
    (
        base
        for base in ssl.SSLContext.__mro__
        if base.__module__ == "ssl" and base.__name__ == "SSLContext"
    ),
    ssl.SSLContext,
)


def server_context() -> ssl.SSLContext:
    """A TLS server context presenting the trusted fixture certificate."""
    context = _PLAIN_CONTEXT(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(_SERVER_CERT, _SERVER_KEY)
    return context


def untrusted_context() -> ssl.SSLContext:
    """A TLS server context presenting a certificate no test store trusts."""
    context = _PLAIN_CONTEXT(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(_UNTRUSTED_CERT, _UNTRUSTED_KEY)
    return context


def client_context() -> ssl.SSLContext:
    """A client context that trusts the fixture CA and nothing else."""
    context = _PLAIN_CONTEXT(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(_CA_FILE))
    return context


class VerifyingContext(_PLAIN_CONTEXT):
    """A client context that verifies the peer inside ``wrap_socket``.

    ``truststore 0.10.4`` — which ``cli.main`` injects into ``ssl`` — builds
    the socket and then verifies the peer off it whatever
    ``do_handshake_on_connect`` says, refusing one whose handshake has not
    happened with "Peer sent no certificates to verify". Reproducing that here
    makes the macOS and Windows path measurable on any platform: a handshake
    that has not run is visible as a missing peer certificate.
    """

    def wrap_socket(self, sock, *args, **kwargs):
        tls = super().wrap_socket(sock, *args, **kwargs)
        try:
            try:
                certificate = tls.getpeercert()
            except ValueError:
                # 3.14 refuses ``getpeercert`` until the handshake is done;
                # truststore reads the same fact off an empty chain.
                certificate = None
            if certificate is None:
                raise ssl.SSLCertVerificationError(
                    "Peer sent no certificates to verify"
                )
        except Exception:
            tls.close()
            raise
        return tls


def verifying_context() -> ssl.SSLContext:
    """A context trusting the fixture CA that verifies in ``wrap_socket``."""
    context = VerifyingContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(_CA_FILE))
    return context


def trust_fixture_ca(monkeypatch, context: ssl.SSLContext | None = None) -> None:
    """Pin this test's TLS trust to the fixture CA, on both ends.

    Two contexts matter: the one ``proxy_bridge`` builds for an ``https://``
    proxy, and the one ``http.client`` builds for the target of a tunneled
    request. Both are pinned here to ``context`` — a context loaded from
    ``ca.pem`` — so a test neither depends on — nor changes — the
    process-wide default, which another test in the same worker may already
    have replaced with the OS verifier. A certificate that context refuses is
    a real refusal, which is what the fail-closed tests measure.

    ``context`` is :func:`client_context` unless a test passes
    :func:`verifying_context` to stand in for ``truststore``'s own context.
    """
    context = context if context is not None else client_context()
    monkeypatch.setattr(proxy_bridge, "default_context", lambda: context)
    monkeypatch.setattr(
        account_proxy,
        "_OPENER",
        urllib.request.build_opener(
            account_proxy._NoRedirects(),
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        ),
    )


def relay(left: socket.socket, right: socket.socket) -> None:
    """Copy bytes both ways until both directions are closed."""
    threads = [
        threading.Thread(target=_pump, args=(left, right), daemon=True),
        threading.Thread(target=_pump, args=(right, left), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def _pump(source: socket.socket, target: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except OSError:
        pass
    if not isinstance(target, ssl.SSLSocket):
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _close(*sockets: socket.socket | None) -> None:
    for item in sockets:
        if item is None:
            continue
        try:
            item.close()
        except OSError:
            pass


def _read_head(connection: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str]]:
    lines = head.split(b"\r\n")
    method, target, _version = lines[0].decode("latin-1").split(" ")
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        name, _separator, value = line.decode("latin-1").partition(":")
        headers[name.strip().lower()] = value.strip()
    return method, target, headers


def _split_authority(value: str) -> tuple[str, int]:
    parts = urllib.parse.urlsplit("//" + value)
    return parts.hostname, parts.port if parts.port is not None else 443


class _Server:
    """A loopback listener that hands each connection to ``_handle``."""

    def __init__(self) -> None:
        self.records: list[dict] = []
        self._lock = threading.Lock()
        self._closed = False
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self._listener.settimeout(0.2)
        self._workers: list[threading.Thread] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._listener.getsockname()[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def paths(self, method: str | None = None) -> list[str]:
        with self._lock:
            return [
                record["target"]
                for record in self.records
                if method is None or record["method"] == method
            ]

    def only(self, method: str) -> dict:
        requests = [
            record
            for record in self.records
            if record.get("method") == method
        ]
        assert len(requests) == 1, requests
        return requests[0]

    def recorded(self) -> list[dict]:
        with self._lock:
            return list(self.records)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(5.0)
        for worker in self._workers:
            worker.join(5.0)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def record(self, entry: dict) -> None:
        with self._lock:
            self.records.append(entry)

    def _serve(self) -> None:
        while not self._closed:
            try:
                connection, _address = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            worker = threading.Thread(
                target=self._run, args=(connection,), daemon=True
            )
            self._workers.append(worker)
            worker.start()

    def _run(self, connection: socket.socket) -> None:
        try:
            self._handle(connection)
        except (OSError, ValueError):
            pass
        finally:
            _close(connection)


class HttpProxy(_Server):
    """A local HTTP proxy: ``CONNECT`` with an optional ``refuse`` status.

    ``tls`` makes it an ``https://`` proxy — TLS first, then the proxy
    protocol inside it, which is the shape ``proxy_bridge`` has to speak for
    that scheme. ``forward`` controls whether a ``CONNECT`` it accepted is
    actually opened to the target: ``probe`` tests only need the ``200``.
    """

    def __init__(
        self,
        *,
        tls: bool = False,
        refuse: int | None = None,
        forward: bool = True,
        refuse_plain_connect: bool = False,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self._tls = tls
        self._refuse = refuse
        self._forward = forward
        self._refuse_plain_connect = refuse_plain_connect
        self._context = context if context is not None else server_context()
        super().__init__()

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(_TIMEOUT_S)
        if not self._tls:
            self._converse(connection)
            return
        # ``wrap_socket`` detaches the raw socket and carries its descriptor
        # into the TLS one, so the TLS socket is what has to be closed here:
        # ``_run`` only still holds the detached original.
        tls = self._context.wrap_socket(connection, server_side=True)
        try:
            self._converse(tls)
        finally:
            _close(tls)

    def _converse(self, connection: socket.socket) -> None:
        head = _read_head(connection)
        if not head:
            return
        method, target, headers = _parse_head(head)
        self.record(
            {"method": method, "target": target, "headers": headers}
        )
        if self._refuse is not None:
            connection.sendall(
                f"HTTP/1.1 {self._refuse} Refused\r\n"
                "Location: http://refused.invalid/\r\n"
                "Content-Length: 7\r\n\r\nRefused".encode("ascii")
            )
            return
        if method != "CONNECT":
            self._forward_http(connection, target, head)
            return
        if self._refuse_plain_connect and _split_authority(target)[1] != 443:
            connection.sendall(
                b"HTTP/1.1 403 Refused\r\nContent-Length: 0\r\n\r\n"
            )
            return
        connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        if not self._forward:
            return
        host, port = _split_authority(target)
        upstream = socket.create_connection((host, port), timeout=_TIMEOUT_S)
        try:
            relay(connection, upstream)
        finally:
            _close(upstream)

    def _forward_http(self, client: socket.socket, target: str, received: bytes) -> None:
        url = urllib.parse.urlsplit(target)
        head, _, body = received.partition(b"\r\n\r\n")
        line, *headers = head.split(b"\r\n")
        path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
        line = line.replace(target.encode("latin-1"), path.encode("latin-1"), 1)
        headers = [item for item in headers if not item.lower().startswith(b"proxy-")]
        with socket.create_connection(
            (url.hostname, url.port or 80), timeout=_TIMEOUT_S
        ) as origin:
            origin.sendall(b"\r\n".join([line, *headers]) + b"\r\n\r\n" + body)
            upload = threading.Thread(target=_pump, args=(client, origin), daemon=True)
            upload.start()
            try:
                while chunk := origin.recv(65536):
                    client.sendall(chunk)
            finally:
                try:
                    socket.socket.shutdown(client, socket.SHUT_RDWR)
                except OSError:
                    pass
                _close(client)
                upload.join()


class Socks5Proxy(_Server):
    """A local SOCKS5 proxy (RFC 1928) with optional RFC 1929 credentials.

    Every request is recorded with the ``ATYP`` and address it carried, which
    is how a test sees a domain leave this machine as a domain: the network
    guard refuses a local lookup of anything but loopback, so a code path that
    resolved the target could not get this far.
    """

    def __init__(
        self,
        *,
        refuse: int | None = None,
        credentials: tuple[str, str] | None = None,
        forward: bool = True,
    ) -> None:
        self._refuse = refuse
        self._credentials = credentials
        self._forward = forward
        super().__init__()

    @property
    def url(self) -> str:
        return f"socks5h://127.0.0.1:{self.port}"

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(_TIMEOUT_S)
        version, methods = self._greet(connection)
        if version != 5:
            return
        method = 0x02 if self._credentials is not None else 0x00
        if method not in methods:
            connection.sendall(b"\x05\xff")
            return
        connection.sendall(bytes([5, method]))
        entry: dict = {"method": "CONNECT"}
        if method == 0x02:
            username, password = self._authenticate(connection)
            entry["username"] = username
            entry["password"] = password
        self._request(connection, entry)

    def _greet(self, connection: socket.socket) -> tuple[int, list[int]]:
        version, count = _recv(connection, 2)
        methods = list(_recv(connection, count))
        return version, methods

    def _authenticate(self, connection: socket.socket) -> tuple[str, str]:
        version, length = _recv(connection, 2)
        username = _recv(connection, length).decode("utf-8")
        (length,) = _recv(connection, 1)
        password = _recv(connection, length).decode("utf-8")
        expected_user, expected_password = self._credentials
        status = 0 if (username, password) == (
            expected_user,
            expected_password,
        ) else 1
        connection.sendall(bytes([version, status]))
        if status != 0:
            raise OSError("bad credentials")
        return username, password

    def _request(self, connection: socket.socket, entry: dict) -> None:
        version, command, _reserved, address_type = _recv(connection, 4)
        if version != 5 or command != 1:
            connection.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        if address_type == 3:
            (length,) = _recv(connection, 1)
            host = _recv(connection, length).decode("idna")
        elif address_type == 1:
            host = socket.inet_ntoa(_recv(connection, 4))
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, _recv(connection, 16))
        else:
            raise OSError("unknown address type")
        (port,) = struct.unpack("!H", _recv(connection, 2))
        entry.update({"atyp": address_type, "host": host, "port": port})
        self.record(entry)
        if self._refuse is not None:
            connection.sendall(bytes([5, self._refuse, 0, 1]) + b"\x00" * 6)
            return
        connection.sendall(bytes([5, 0, 0, 1]) + b"\x00" * 6)
        if not self._forward:
            return
        upstream = socket.create_connection((host, port), timeout=_TIMEOUT_S)
        try:
            relay(connection, upstream)
        finally:
            _close(upstream)


def _recv(connection: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise OSError("short read")
        data += chunk
    return data


class Origin:
    """A loopback HTTP or HTTPS origin answering one JSON body.

    ``hits`` counts the requests that reached it, so a test can prove a
    refused route never fell back to a direct connection. ``body_gate`` is a
    reply whose body is still in flight when a client's ``open`` returns: the
    head is written, then the origin waits for the event, and only then sends
    the body.

    Each request is recorded as ``method``, ``path``, ``headers`` (lower-case
    names, the last value of a repeated one) and ``hosts``: every ``Host``
    value the wire carried, in order, so a duplicated header is visible and
    not collapsed into one. This is what the origin *received*, which is the
    only place a wrong ``Host`` on a tunneled request shows up.
    """

    def __init__(
        self,
        body: bytes = b'{"ip": "1.2.3.4", "country": "US"}',
        *,
        tls: bool = False,
        status: int = 200,
        location: str | None = None,
        body_gate: threading.Event | None = None,
    ) -> None:
        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _record(self) -> None:
                with self.server.lock:
                    self.server.requests.append(
                        {
                            "method": self.command,
                            "path": self.path,
                            "headers": {
                                name.lower(): value
                                for name, value in self.headers.items()
                            },
                            "hosts": self.headers.get_all("Host") or [],
                        }
                    )

            def do_GET(self) -> None:
                with self.server.lock:
                    self.server.hits += 1
                self._record()
                self.send_response(self.server.status)
                self.send_header("Content-Type", "application/json")
                if self.server.location is not None:
                    self.send_header("Location", self.server.location)
                self.send_header("Content-Length", str(len(self.server.body)))
                self.end_headers()
                if self.server.body_gate is not None:
                    self.server.body_gate.wait(_TIMEOUT_S)
                self.wfile.write(self.server.body)

            def do_POST(self) -> None:
                self._record()
                body = self.rfile.read(int(self.headers["Content-Length"]))
                with self.server.lock:
                    self.server.received.append(body)
                self.do_GET()

            def log_message(self, *args) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _Handler
        )
        self._server.hits = 0
        self._server.lock = threading.Lock()
        self._server.requests = []
        self._server.body = body
        self._server.received = []
        self._server.status = status
        self._server.location = location
        self._server.body_gate = body_gate
        if tls:
            context = server_context()
            self._server.socket = context.wrap_socket(
                self._server.socket, server_side=True
            )
        self._tls = tls
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def hits(self) -> int:
        return self._server.hits

    @property
    def received(self) -> list[bytes]:
        with self._server.lock:
            return list(self._server.received)

    def only(self, method: str) -> dict:
        """The one recorded request of ``method``, failed on zero or several."""
        with self._server.lock:
            requests = [
                record
                for record in self._server.requests
                if record["method"] == method
            ]
        assert len(requests) == 1, requests
        return requests[0]

    @property
    def url(self) -> str:
        scheme = "https" if self._tls else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(5.0)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class SilentProxy(_Server):
    """A proxy that accepts a tunnel and then says nothing at all.

    A client reads it as a timeout rather than as a closed connection, which
    is what the ``timeout`` diagnostic needs.
    """

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(_TIMEOUT_S)
        if not _read_head(connection):
            return
        connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # Hold the connection open, answering nothing, until the server is
        # closed (which drops the socket).
        while not self._closed:
            try:
                if not connection.recv(4096):
                    break
                time.sleep(0.02)
            except TimeoutError:
                continue


class DeadProxy:
    """A loopback address with nothing listening, without assuming a port."""

    def __init__(self) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()


def proxy_for(scheme: str):
    """A loopback proxy speaking ``scheme``: the shape one route needs.

    ``http`` is the direct path (urllib's own ``CONNECT``/absolute form),
    ``https`` a TLS proxy and ``socks5h`` a SOCKS5 one — the two schemes that
    only ``proxy_bridge`` can reach. A test parametrized over the three then
    spells each route the same way, ``f"{scheme}://127.0.0.1:{proxy.port}"``.
    """
    if scheme == "http":
        return HttpProxy()
    if scheme == "https":
        return HttpProxy(tls=True)
    if scheme in ("socks5h", "socks5"):
        return Socks5Proxy()
    raise ValueError(f"no test proxy for {scheme!r}")

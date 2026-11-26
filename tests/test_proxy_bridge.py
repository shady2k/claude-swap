"""The local HTTP bridge, and the routes that need it.

Two layers are under test here:

- the *transport* — ``proxy_bridge`` reaching an ``https://`` proxy with TLS
  and RFC 1928/1929 SOCKS5, and the request that then travels it;
- the *route* — ``account_proxy.ProxyRoute.open``/``probe`` on those schemes,
  which is what every caller in cswap uses, including the fail-closed answers
  a refused tunnel has to give.

Every server is loopback and built here (``tests/proxy_servers.py``): a TLS
proxy, a SOCKS5 proxy and HTTP(S) origins, plus the throwaway certificate
fixtures they present. The SOCKS5 target is a *domain* — ``localhost`` — so
the suite's network guard refuses any lookup of it inside this process: a test
where the bridge resolved the target locally could not pass.
"""

from __future__ import annotations

import base64
import http.client
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from contextlib import suppress
from pathlib import Path

import pytest

from claude_swap import account_proxy, proxy_bridge
from tests import proxy_servers


def _wait_until_closed(port: int, timeout: float = 5.0) -> None:
    """Wait for a listening port to refuse connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=1)
        except OSError:
            return
        connection.close()
        time.sleep(0.02)
    raise AssertionError(f"port {port} still accepts connections")


def _capture_bridges(monkeypatch) -> list[tuple[proxy_bridge.Bridge, int]]:
    """Every bridge this test's code opens, with the port it listened on.

    The port is read here, while the bridge is still open: a closed bridge's
    listener can no longer name it.
    """
    created: list[tuple[proxy_bridge.Bridge, int]] = []
    real_bridge = proxy_bridge.Bridge

    class _Captured(real_bridge):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append((self, self.port))

    monkeypatch.setattr(proxy_bridge, "Bridge", _Captured)
    return created


class TestTheLocalListener:
    def test_it_listens_on_loopback_only_and_reports_its_address(
        self, monkeypatch
    ):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")
            with proxy_bridge.Bridge(route) as local:
                assert local.host == "127.0.0.1"
                assert local.url == f"http://127.0.0.1:{local.port}"
                probe = socket.create_connection(
                    ("127.0.0.1", local.port), timeout=5
                )
                probe.close()
                port = local.port
        _wait_until_closed(port)

    def test_closing_it_drops_the_connections_it_holds(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, forward=False) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")
            local = proxy_bridge.Bridge(route)
            held = socket.create_connection(("127.0.0.1", local.port), timeout=5)
            held.settimeout(5)
            local.close()
            # The peer sees the end of the stream: an orderly EOF, or a reset
            # when the listener's socket had unread data.
            with suppress(ConnectionResetError):
                assert held.recv(1) == b""
            held.close()

    @pytest.mark.parametrize("scheme", ["https", "socks5h"])
    def test_close_cancels_an_upstream_handshake(self, monkeypatch, scheme):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(5)
            route = account_proxy.parse(f"{scheme}://127.0.0.1:{listener.getsockname()[1]}")
            with proxy_bridge.Bridge(route) as local:
                with socket.create_connection((local.host, local.port), timeout=5) as client:
                    client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
                    peer, _ = listener.accept()
                    with peer:
                        peer.settimeout(5)
                        # Receiving the first handshake bytes puts the worker
                        # inside the protocol handshake before closing it.
                        assert peer.recv(4096)
                        started = time.monotonic()
                        local.close()
                        assert time.monotonic() - started < 1
                        with suppress(ConnectionResetError):
                            while peer.recv(4096):
                                pass
                        with suppress(ConnectionResetError):
                            assert client.recv(1) == b""
                        assert not local._connections
                        assert not local._thread.is_alive()
                        assert not any(worker.is_alive() for worker in local._workers)
                        assert local.failure is None

    def test_a_disallowed_scheme_is_refused_by_the_transport(self):
        class _Ftp:
            scheme = "ftp"
            host = "127.0.0.1"
            port = 21
            username = None
            password = None

        with pytest.raises(ValueError, match="ftp://"):
            proxy_bridge.connect(_Ftp(), "api.anthropic.com", 443)

    def test_the_listener_needs_no_authentication_to_be_used(self, monkeypatch):
        """The loopback side carries no credentials: the upstream URL's never
        reach a local client, and nothing local has to present them."""
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, forward=False) as upstream:
            route = account_proxy.parse(
                f"https://user:secret@127.0.0.1:{upstream.port}"
            )
            with proxy_bridge.Bridge(route) as local:
                connection = socket.create_connection(
                    ("127.0.0.1", local.port), timeout=5
                )
                connection.sendall(
                    b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n"
                )
                assert b"200" in connection.recv(1024)
                connection.close()
        assert upstream.only("CONNECT")["headers"]["proxy-authorization"]


class TestThroughAnHttpsProxy:
    def test_a_tls_target_travels_the_proxy_tls(self, monkeypatch):
        """TLS to the proxy, then the target's own TLS inside that tunnel."""
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin(tls=True) as origin:
            with proxy_servers.HttpProxy(tls=True) as upstream:
                route = account_proxy.parse(
                    f"https://user:pw@127.0.0.1:{upstream.port}"
                )
                request = urllib.request.Request(
                    f"https://localhost:{origin.port}/json"
                )

                with route.open(request, timeout=10) as response:
                    assert response.status == 200
                    assert response.read() == (
                        b'{"ip": "1.2.3.4", "country": "US"}'
                    )

        connect = upstream.only("CONNECT")
        assert connect["target"] == f"localhost:{origin.port}"
        expected = base64.b64encode(b"user:pw").decode()
        assert connect["headers"]["proxy-authorization"] == f"Basic {expected}"
        assert origin.hits == 1

    def test_a_context_that_verifies_in_wrap_socket_still_tunnels(
        self, monkeypatch
    ):
        """A context that verifies inside ``wrap_socket`` has to run the
        handshake itself: handed a socket before its handshake, it refuses a
        certificate it has not read yet, so every ``https://`` proxy failed
        with "Peer sent no certificates to verify" under ``truststore``."""
        proxy_servers.trust_fixture_ca(
            monkeypatch, proxy_servers.verifying_context()
        )
        with proxy_servers.Origin(tls=True) as origin:
            with proxy_servers.HttpProxy(tls=True) as upstream:
                route = account_proxy.parse(
                    f"https://user:pw@127.0.0.1:{upstream.port}"
                )
                request = urllib.request.Request(
                    f"https://localhost:{origin.port}/json"
                )

                with route.open(request, timeout=10) as response:
                    assert response.status == 200
                    assert response.read() == (
                        b'{"ip": "1.2.3.4", "country": "US"}'
                    )

        assert upstream.only("CONNECT")["target"] == f"localhost:{origin.port}"
        assert origin.hits == 1

    @pytest.mark.parametrize("scheme", ["https", "socks5h"])
    def test_plain_http_post_forwards_the_full_body(self, monkeypatch, scheme):
        proxy_servers.trust_fixture_ca(monkeypatch)
        proxy = (
            proxy_servers.HttpProxy(tls=True, refuse_plain_connect=True)
            if scheme == "https" else proxy_servers.Socks5Proxy()
        )
        body = b"body in the same write as the headers"
        with proxy as upstream, proxy_servers.Origin() as origin:
            credentials = "user:secret@" if scheme == "https" else ""
            route = account_proxy.parse(f"{scheme}://{credentials}127.0.0.1:{upstream.port}")
            with proxy_bridge.Bridge(route) as local:
                with socket.create_connection((local.host, local.port), timeout=5) as client:
                    client.sendall(
                        f"POST {origin.url}/json HTTP/1.1\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Proxy-Authorization: client-credentials\r\n"
                        "Proxy-Example: client-only\r\n\r\n".encode() + body
                    )
                    client.shutdown(socket.SHUT_WR)
                    with http.client.HTTPResponse(client) as response:
                        response.begin()
                        assert response.status == 200
                        assert response.read() == b'{"ip": "1.2.3.4", "country": "US"}'
            assert origin.received == [body]

        if scheme == "https":
            request = upstream.only("POST")
            assert request["target"] == f"{origin.url}/json"
            assert request["headers"]["proxy-authorization"] == (
                "Basic " + base64.b64encode(b"user:secret").decode()
            )
            assert "proxy-example" not in request["headers"]
            assert not upstream.paths("CONNECT")
        else:
            assert upstream.only("CONNECT")["port"] == origin.port

    def test_plain_http_can_wait_for_continue_before_sending_body(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        body = b"sent after continue"

        class _ContinueProxy(proxy_servers.HttpProxy):
            def _converse(self, connection):
                proxy_servers._read_head(connection)
                connection.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                self.record({"body": proxy_servers._recv(connection, len(body))})
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        with _ContinueProxy(tls=True) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")
            with proxy_bridge.Bridge(route) as local:
                with socket.create_connection((local.host, local.port), timeout=5) as client:
                    client.sendall(
                        "POST http://example.test/ HTTP/1.1\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Expect: 100-continue\r\n\r\n".encode()
                    )
                    assert proxy_bridge._read_head(client) == (
                        b"HTTP/1.1 100 Continue\r\n\r\n", b""
                    )
                    client.sendall(body)
                    with http.client.HTTPResponse(client) as response:
                        response.begin()
                        assert response.status == 200
                        assert response.read() == b""
            assert upstream.recorded() == [{"body": body}]

    def test_plain_http_proxy_refusal_carries_only_static_status(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, refuse=407) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")
            with proxy_bridge.Bridge(route) as local:
                with socket.create_connection((local.host, local.port), timeout=5) as client:
                    client.sendall(
                        b"POST http://example.test/ HTTP/1.1\r\n"
                        b"Content-Length: 10\r\nExpect: 100-continue\r\n\r\n"
                    )
                    with http.client.HTTPResponse(client) as response:
                        response.begin()
                        assert response.status == 407
                        assert response.getheader("Location") is None
                        assert response.read() == b""
                        assert "Refused" not in response.reason
                    assert client.recv(1) == b""
            assert isinstance(local.failure, proxy_bridge.BridgeError)
            assert local.failure.status == 407

    @pytest.mark.parametrize("scheme", ["https", "socks5h"])
    def test_plain_http_origin_redirect_keeps_headers_and_body(self, monkeypatch, scheme):
        proxy_servers.trust_fixture_ca(monkeypatch)
        proxy = (
            proxy_servers.HttpProxy(tls=True, refuse_plain_connect=True)
            if scheme == "https" else proxy_servers.Socks5Proxy()
        )
        body = b'{"moved": true}'
        location = "http://example.test/new"
        with proxy as upstream, proxy_servers.Origin(
            body=body, status=301, location=location
        ) as origin:
            route = account_proxy.parse(f"{scheme}://127.0.0.1:{upstream.port}")
            with proxy_bridge.Bridge(route) as local:
                with socket.create_connection((local.host, local.port), timeout=5) as client:
                    client.sendall(f"GET {origin.url}/old HTTP/1.1\r\n\r\n".encode())
                    with http.client.HTTPResponse(client) as response:
                        response.begin()
                        assert response.status == 301
                        assert response.getheader("Location") == location
                        assert response.getheader("Content-Type") == "application/json"
                        assert response.read() == body
            assert local.failure is None
            assert origin.hits == 1

    def test_connect_keeps_bytes_from_the_same_write_as_each_head(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        request_bytes = b"early client bytes"
        reply_bytes = b"early server bytes"

        class _EarlyReplyProxy(proxy_servers.HttpProxy):
            def _converse(self, connection):
                proxy_servers._read_head(connection)
                connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n" + reply_bytes)
                self.record({"data": proxy_servers._recv(connection, len(request_bytes))})
                connection.sendall(b"done")

        with _EarlyReplyProxy(tls=True) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")
            with proxy_bridge.Bridge(route) as local:
                with socket.create_connection((local.host, local.port), timeout=5) as client:
                    client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n" + request_bytes)
                    head, rest = proxy_bridge._read_head(client)
                    rest += proxy_servers._recv(client, len(reply_bytes) + len(b"done") - len(rest))
                    assert head == b"HTTP/1.1 200 Connection Established\r\n\r\n"
                    assert rest == reply_bytes + b"done"
            assert upstream.recorded() == [{"data": request_bytes}]

    def test_rejected_credentials_are_an_auth_refusal(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, refuse=407) as upstream:
            route = account_proxy.parse(
                f"https://user:pw@127.0.0.1:{upstream.port}"
            )
            request = urllib.request.Request("https://api.anthropic.com/v1/x")

            with pytest.raises(account_proxy.ProxyRouteError) as err:
                route.open(request, timeout=10)

        assert err.value.kind == account_proxy.PROXY_AUTH
        assert err.value.status == 407
        assert "pw" not in str(err.value)

    def test_a_redirect_is_its_own_kind(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, refuse=302) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")
            request = urllib.request.Request("https://api.anthropic.com/v1/x")

            with pytest.raises(account_proxy.ProxyRouteError) as err:
                route.open(request, timeout=10)

        assert err.value.kind == account_proxy.PROXY_REDIRECT
        assert err.value.status == 302

    def test_another_refusal_keeps_the_code_and_no_phrase(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, refuse=403) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")
            request = urllib.request.Request("https://api.anthropic.com/v1/x")

            with pytest.raises(account_proxy.ProxyRouteError) as err:
                route.open(request, timeout=10)

        assert err.value.kind == account_proxy.PROXY_UNREACHABLE
        assert err.value.status == 403
        assert "Refused" not in str(err.value)

    def test_a_proxy_certificate_the_process_refuses_stops_the_request(
        self, monkeypatch
    ):
        """Fail-closed on the proxy's own certificate: the account's URL is
        verified like any other endpoint, and the target is never reached."""
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin(tls=True) as origin:
            with proxy_servers.HttpProxy(
                tls=True, context=proxy_servers.untrusted_context()
            ) as upstream:
                route = account_proxy.parse(
                    f"https://user:pw@127.0.0.1:{upstream.port}"
                )
                request = urllib.request.Request(
                    f"https://localhost:{origin.port}/json"
                )

                with pytest.raises(urllib.error.URLError) as err:
                    route.open(request, timeout=10)
                assert isinstance(err.value.reason, ssl.SSLCertVerificationError)

        assert upstream.recorded() == []
        assert origin.hits == 0

    def test_a_dead_proxy_never_falls_back_to_a_direct_connection(
        self, monkeypatch
    ):
        proxy_servers.trust_fixture_ca(monkeypatch)
        dead = proxy_servers.DeadProxy()
        with proxy_servers.Origin(tls=True) as origin:
            route = account_proxy.parse(f"https://127.0.0.1:{dead.port}")
            request = urllib.request.Request(
                f"https://localhost:{origin.port}/json"
            )

            with pytest.raises(account_proxy.ProxyRouteError) as err:
                route.open(request, timeout=5)

        assert err.value.kind == account_proxy.PROXY_UNREACHABLE
        assert origin.hits == 0


class TestThroughASocks5Proxy:
    def test_a_domain_target_is_sent_as_a_domain(self, monkeypatch):
        """``socks5h`` means the proxy resolves it: the target name travels
        as ``ATYP=0x03`` and is never looked up here."""
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin(tls=True) as origin:
            with proxy_servers.Socks5Proxy() as upstream:
                route = account_proxy.parse(upstream.url)
                request = urllib.request.Request(
                    f"https://localhost:{origin.port}/json"
                )

                with route.open(request, timeout=10) as response:
                    assert response.status == 200

        request = upstream.only("CONNECT")
        assert request["atyp"] == 3
        assert request["host"] == "localhost"
        assert request["port"] == origin.port

    def test_an_address_target_uses_its_address_type(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin(tls=True) as origin:
            with proxy_servers.Socks5Proxy() as upstream:
                route = account_proxy.parse(upstream.url)
                request = urllib.request.Request(
                    f"https://127.0.0.1:{origin.port}/json"
                )

                with route.open(request, timeout=10) as response:
                    response.read()

        assert upstream.only("CONNECT")["atyp"] == 1

    def test_credentials_travel_by_rfc_1929(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin() as origin:
            with proxy_servers.Socks5Proxy(
                credentials=("us%er", "p@ss")
            ) as upstream:
                route = account_proxy.parse(
                    upstream.url.replace(
                        "socks5h://",
                        "socks5h://us%25er:p%40ss@",
                    )
                )
                request = urllib.request.Request(
                    f"http://localhost:{origin.port}/json"
                )

                with route.open(request, timeout=10) as response:
                    response.read()

        request = upstream.only("CONNECT")
        assert request["username"] == "us%er"
        assert request["password"] == "p@ss"

    def test_the_socks5_alias_is_the_same_transport(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin() as origin:
            with proxy_servers.Socks5Proxy() as upstream:
                route = account_proxy.parse(
                    upstream.url.replace("socks5h://", "socks5://")
                )
                assert route.scheme == "socks5"
                request = urllib.request.Request(
                    f"http://localhost:{origin.port}/json"
                )

                with route.open(request, timeout=10) as response:
                    assert response.status == 200

        assert upstream.only("CONNECT")["atyp"] == 3

    def test_a_refused_tunnel_is_fail_closed(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin() as origin:
            with proxy_servers.Socks5Proxy(refuse=5) as upstream:
                route = account_proxy.parse(upstream.url)
                request = urllib.request.Request(f"{origin.url}/json")

                with pytest.raises(account_proxy.ProxyRouteError) as err:
                    route.open(request, timeout=10)

        assert err.value.kind == account_proxy.PROXY_UNREACHABLE
        assert "connection refused" in str(err.value)
        assert origin.hits == 0

    def test_wrong_credentials_are_an_auth_refusal(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Socks5Proxy(
            credentials=("user", "right")
        ) as upstream:
            route = account_proxy.parse(
                upstream.url.replace(
                    "socks5h://", "socks5h://user:wrong@"
                )
            )
            request = urllib.request.Request("https://api.anthropic.com/v1/x")

            with pytest.raises(account_proxy.ProxyRouteError) as err:
                route.open(request, timeout=10)

        assert err.value.kind == account_proxy.PROXY_AUTH
        assert "wrong" not in str(err.value)


class TestProbe:
    """The launch's one pre-start tunnel, on the schemes that need a bridge."""

    def test_an_https_proxy_gets_the_probe_tunnel(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, forward=False) as upstream:
            route = account_proxy.parse(
                f"https://user:pw@127.0.0.1:{upstream.port}"
            )

            account_proxy.probe(route)

        connect = upstream.only("CONNECT")
        assert connect["target"] == (
            f"{account_proxy.PROBE_TARGET[0]}:{account_proxy.PROBE_TARGET[1]}"
        )
        assert connect["headers"]["proxy-authorization"]

    def test_a_socks5_proxy_resolves_the_probe_target_itself(
        self, monkeypatch
    ):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Socks5Proxy() as upstream:
            account_proxy.probe(account_proxy.parse(upstream.url))

        request = upstream.only("CONNECT")
        assert request["atyp"] == 3
        assert request["host"] == account_proxy.PROBE_TARGET[0]

    def test_a_refused_probe_is_a_refusal_not_a_retry(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, refuse=407) as upstream:
            route = account_proxy.parse(f"https://127.0.0.1:{upstream.port}")

            with pytest.raises(account_proxy.ProxyRouteError) as err:
                account_proxy.probe(route)

        assert err.value.kind == account_proxy.PROXY_AUTH

    def test_an_untrusted_proxy_certificate_refuses_the_launch(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(
            tls=True, context=proxy_servers.untrusted_context()
        ) as upstream:
            route = account_proxy.parse(
                f"https://user:secret@127.0.0.1:{upstream.port}"
            )

            with pytest.raises(account_proxy.ProxyRouteError) as err:
                account_proxy.probe(route)

        assert err.value.kind == account_proxy.PROXY_UNREACHABLE
        assert "TLS error" in str(err.value)
        assert "secret" not in str(err.value)


class TestTheSocks5Request:
    """The bytes of a SOCKS5 request, without a server in between."""

    @pytest.mark.parametrize(
        "host, expected",
        [
            ("1.2.3.4", b"\x01\x01\x02\x03\x04"),
            ("::1", b"\x04" + socket.inet_pton(socket.AF_INET6, "::1")),
            ("example.com", b"\x03\x0bexample.com"),
            (
                "почта.рф",
                b"\x03" + bytes([len("почта.рф".encode("idna"))])
                + "почта.рф".encode("idna"),
            ),
        ],
    )
    def test_the_address_type_follows_the_target(self, host, expected):
        assert proxy_bridge._socks5_address(host) == expected

    def test_a_name_too_long_for_the_field_is_refused(self):
        with pytest.raises(proxy_bridge.BridgeError):
            proxy_bridge._socks5_address("a" * 256 + ".example")

class TestTheBridgeInALaunchEnvironment:
    def test_it_hands_out_its_loopback_address(self, monkeypatch):
        """The child reads the bridge, and the account's URL stays here."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        with proxy_servers.HttpProxy(forward=False) as upstream:
            route = account_proxy.parse(
                f"https://user:secret@127.0.0.1:{upstream.port}"
            )
            with account_proxy.bridge(route) as local:
                env = account_proxy.launch_env(
                    route, "localhost", {"PATH": "/usr/bin"}, local
                )
                assert env["HTTPS_PROXY"] == local.url
                assert env["https_proxy"] == local.url
                assert env["ALL_PROXY"] == local.url
                assert env["NO_PROXY"] == "localhost"
                assert "secret" not in " ".join(env.values())

    def test_a_bridged_route_without_a_bridge_is_refused(self):
        route = account_proxy.parse("https://user:secret@127.0.0.1:3128")
        with pytest.raises(ValueError, match="bridge"):
            account_proxy.launch_env(route, "localhost", {})

    def test_an_http_route_keeps_its_own_url(self):
        route = account_proxy.parse("http://user:secret@127.0.0.1:3128")
        with account_proxy.bridge(route) as local:
            assert local is None
            env = account_proxy.launch_env(route, "localhost", {})
        assert env["HTTPS_PROXY"] == "http://user:secret@127.0.0.1:3128"


class TestARequestThatNeverLeaves:
    def test_an_unusable_route_raises_before_any_socket(self):
        route = account_proxy.unusable("the stored value is not a URL")
        with pytest.raises(account_proxy.ProxyRouteError) as err:
            route.open(urllib.request.Request("https://api.anthropic.com/x"))
        assert err.value.kind == account_proxy.PROXY_INVALID

    def test_a_request_url_is_unchanged_by_the_bridge(self, monkeypatch):
        """The bridge carries the request; it does not rewrite it for the
        caller, so a retry with a fresh request behaves the same."""
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin() as origin:
            with proxy_servers.HttpProxy(tls=True) as upstream:
                route = account_proxy.parse(
                    f"https://127.0.0.1:{upstream.port}"
                )
                request = urllib.request.Request(f"{origin.url}/json")
                original = request.full_url
                with route.open(request, timeout=10) as response:
                    response.read()

        assert request.full_url == original


class TestTheReplyBodyThatFollowsTheHead:
    """``open`` returns on the reply's head; the body still travels the bridge.

    Every caller reads the body after ``open`` has returned, which is where a
    bridge that closed with the call would truncate the reply — the shape of a
    real usage or OAuth answer.
    """

    def test_the_body_is_read_after_open_returns(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        body = b'{"ip": "1.2.3.4", "country": "US"}'
        released = threading.Event()
        created = _capture_bridges(monkeypatch)
        with proxy_servers.Origin(body=body, body_gate=released) as origin:
            with proxy_servers.HttpProxy(tls=True) as upstream:
                route = account_proxy.parse(
                    f"https://127.0.0.1:{upstream.port}"
                )
                request = urllib.request.Request(f"{origin.url}/json")
                with route.open(request, timeout=10) as response:
                    # The origin is still holding the body back: only a bridge
                    # that outlived ``open`` can deliver it.
                    assert origin.hits == 1
                    assert len(created) == 1
                    released.set()
                    assert response.read() == body
        bridge, port = created[0]
        assert bridge.failure is None
        # Closed with the response: nothing of the bridge is left listening
        # or running.
        assert not [
            thread
            for thread in threading.enumerate()
            if thread.name.startswith("proxy-bridge")
        ]
        _wait_until_closed(port)

    def test_a_failed_open_leaves_no_bridge_behind(self, monkeypatch):
        """No response to carry it, so the bridge is closed in the failure."""
        proxy_servers.trust_fixture_ca(monkeypatch)
        created = _capture_bridges(monkeypatch)
        with proxy_servers.HttpProxy(tls=True, refuse=407) as upstream:
            route = account_proxy.parse(
                f"https://user:pw@127.0.0.1:{upstream.port}"
            )
            with pytest.raises(account_proxy.ProxyRouteError):
                route.open(
                    urllib.request.Request("https://api.anthropic.com/v1/x"),
                    timeout=10,
                )
        assert isinstance(created[0][0].failure, proxy_bridge.BridgeError)
        _wait_until_closed(created[0][1])


def test_the_bridge_module_imports_nothing_from_the_package():
    """A leaf module: the route is duck-typed, so nothing here can regress
    into the dependency cycle ``account_proxy``/``session`` have."""
    source = (
        Path(__file__).parent.parent / "src" / "claude_swap" / "proxy_bridge.py"
    )
    assert "from claude_swap" not in source.read_text(encoding="utf-8")


def test_an_https_proxy_url_is_listened_to_by_the_route():
    """``ProxyRoute.needs_bridge`` is what every caller branches on."""
    assert account_proxy.parse("https://h:443").needs_bridge
    assert account_proxy.parse("socks5h://h:1080").needs_bridge
    assert account_proxy.parse("socks5://h:1080").needs_bridge
    assert not account_proxy.parse("http://h:80").needs_bridge
    assert not account_proxy.unusable("x").needs_bridge


def test_an_unexpected_error_from_the_bridge_is_unreachable():
    """A bridge that recorded something this module does not know is still a
    refusal, never a direct retry."""
    with pytest.raises(account_proxy.ProxyRouteError) as err:
        account_proxy.raise_failure(RuntimeError("boom"))
    assert err.value.kind == account_proxy.PROXY_UNREACHABLE
    assert "boom" not in str(err.value)


@pytest.mark.parametrize("error", [ssl.SSLCertVerificationError, ssl.SSLError])
def test_a_tls_error_from_the_bridge_is_wrapped_like_urllib(error):
    failure = error("fixture refusal")
    with pytest.raises(urllib.error.URLError) as err:
        account_proxy.raise_failure(failure)
    assert err.value.reason is failure


def test_the_two_tunnel_refusal_helpers_agree_on_the_code():
    reason = urllib.error.URLError(
        OSError("Tunnel connection failed: 502 Bad Gateway")
    ).reason
    assert account_proxy.tunnel_status(reason) == "502"
    assert account_proxy.tunnel_status(ConnectionRefusedError()) is None

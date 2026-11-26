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
import socket
import ssl
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
                assert socket.create_connection(
                    ("127.0.0.1", local.port), timeout=5
                )
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

    def test_an_http_target_becomes_a_tunnel_to_its_origin(self, monkeypatch):
        """A plain ``http://`` request is tunneled too, and rewritten."""
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.Origin() as origin:
            with proxy_servers.HttpProxy(tls=True) as upstream:
                route = account_proxy.parse(
                    f"https://127.0.0.1:{upstream.port}"
                )
                request = urllib.request.Request(f"{origin.url}/json")

                with route.open(request, timeout=10) as response:
                    assert response.status == 200

        assert upstream.paths("CONNECT") == [f"127.0.0.1:{origin.port}"]
        assert origin.hits == 1

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

                with pytest.raises(ssl.SSLCertVerificationError):
                    route.open(request, timeout=10)

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


def test_a_tls_error_from_the_bridge_is_passed_on():
    with pytest.raises(ssl.SSLCertVerificationError):
        account_proxy.raise_failure(
            ssl.SSLCertVerificationError("fixture refusal")
        )


def test_the_two_tunnel_refusal_helpers_agree_on_the_code():
    reason = urllib.error.URLError(
        OSError("Tunnel connection failed: 502 Bad Gateway")
    ).reason
    assert account_proxy.tunnel_status(reason) == "502"
    assert account_proxy.tunnel_status(ConnectionRefusedError()) is None

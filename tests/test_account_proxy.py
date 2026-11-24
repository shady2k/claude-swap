"""Per-account proxy: the setting, and the pinned route every request takes.

Two things are under test here, and they fail differently:

- the *setting* — who has a proxy, what happens to it on swap/move/remove,
  export and import, and that the password never leaves the process;
- the *route* — that a proxied account's requests (usage, token refresh and
  its retries, the profile and plan reads) reach the proxy and nothing else.

The second half is measured against local servers on loopback: one proxy that
records what it was asked, and one origin ("direct counter") that must stay at
zero hits whenever the account has a proxy. A direct connection by any of these
code paths would reach that origin and be counted, so a zero there is evidence
rather than the absence of a test.
"""

from __future__ import annotations

import base64
import json
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import account_proxy, oauth, subscription
from claude_swap.exceptions import ValidationError
from claude_swap.switcher import ClaudeAccountSwitcher

USAGE = {
    "five_hour": {"utilization": 10.0, "resets_at": None},
    "seven_day": {"utilization": 20.0, "resets_at": None},
}
TOKEN = {"access_token": "sk-new", "expires_in": 3600, "refresh_token": "rt-new"}
# One reply serves both ``/api/oauth/profile`` callers: the identity read
# (``account``) and the plan read (``organization.rate_limit_tier``).
PROFILE = {
    "account": {"uuid": "uuid-1", "email": "test@example.com"},
    "organization": {"uuid": None, "rate_limit_tier": "default_claude_max_5x"},
}

CREDS_OK = json.dumps({"claudeAiOauth": {
    "accessToken": "sk-live", "refreshToken": "rt-live", "expiresAt": 9999999999000,
}})
CREDS_EXPIRED = json.dumps({"claudeAiOauth": {
    "accessToken": "sk-old", "refreshToken": "rt-old", "expiresAt": 1000,
}})


# --- local servers -----------------------------------------------------------


class _Recorder(BaseHTTPRequestHandler):
    """Records each request and answers from the server's responder."""

    protocol_version = "HTTP/1.0"

    def _reply(self) -> None:
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        with server.lock:
            server.requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": body,
                }
            )
        if self.command == "CONNECT":
            # Answer the tunnel, then close: the client's TLS handshake fails,
            # which is all a test needs to see that the tunnel was attempted.
            self.send_response(200, "Connection Established")
            self.end_headers()
            return
        status, headers, payload = server.responder(self.command, self.path)
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _reply
    do_POST = _reply
    do_CONNECT = _reply

    def log_message(self, *args) -> None:  # keep the test output clean
        pass


class LocalServer:
    """A loopback HTTP server whose replies a test controls."""

    def __init__(self, responder=None, address: str = "127.0.0.1"):
        self.responder = responder or (lambda method, path: (200, {}, b"{}"))
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        self.httpd = ThreadingHTTPServer((address, 0), _Recorder)
        self.httpd.responder = self.responder
        self.httpd.requests = self.requests
        self.httpd.lock = self.lock
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> LocalServer:
        self.thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def paths(self, method: str = "") -> list[str]:
        with self.lock:
            return [
                r["path"] for r in self.requests if not method or r["method"] == method
            ]

    def only(self, method: str) -> dict:
        rows = [r for r in self.requests if r["method"] == method]
        assert len(rows) == 1, f"expected one {method}, got {len(rows)}"
        return rows[0]


class _CountingTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.hits.append(self.client_address)
        self.request.close()


class DirectCounter:
    """A listener that counts accepted connections and closes each one.

    Stands in for the origin: reaching it means something connected directly.
    """

    def __init__(self) -> None:
        self.hits: list[tuple] = []
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _CountingTCPHandler)
        self.server.daemon_threads = True
        self.server.hits = self.hits
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> DirectCounter:
        self.thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def port(self) -> int:
        return self.server.server_address[1]


def _proxy_responder(method: str, path: str):
    """What a working proxy answers for the endpoints cswap calls."""
    route = urllib.parse.urlsplit(path).path
    if route == "/v1/oauth/token":
        return 200, {"Content-Type": "application/json"}, json.dumps(TOKEN).encode()
    if route == "/api/oauth/usage":
        return 200, {"Content-Type": "application/json"}, json.dumps(USAGE).encode()
    if route == "/api/oauth/profile":
        return 200, {"Content-Type": "application/json"}, json.dumps(PROFILE).encode()
    return 404, {}, b"{}"


@pytest.fixture
def proxy():
    with LocalServer(_proxy_responder) as server:
        yield server


@pytest.fixture
def origin():
    """The direct counter as a live origin: a proxied request must not reach it."""
    with LocalServer(_proxy_responder) as server:
        yield server


@pytest.fixture
def direct_calls(monkeypatch):
    """The no-proxy branch as a counter: ``urlopen`` is what a plain fetch uses.

    ``tests/conftest.py`` replaces ``urllib.request.urlopen`` process-wide so
    no test reaches the network; this replaces it again with one that records
    the attempt and fails like an offline host would.
    """
    calls: list[str] = []

    def fake_urlopen(request, timeout=None):
        calls.append(request.full_url)
        raise urllib.error.URLError("direct connection attempted")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return calls


def _endpoints(monkeypatch, base: str) -> None:
    """Point every endpoint cswap calls at one local origin URL."""
    monkeypatch.setattr(oauth, "OAUTH_TOKEN_URL", base + "/v1/oauth/token")
    monkeypatch.setattr(oauth, "USAGE_URL", base + "/api/oauth/usage")
    monkeypatch.setattr(oauth, "PROFILE_URL", base + "/api/oauth/profile")
    monkeypatch.setattr(oauth, "USAGE_PROBE_URL", base + "/v1/messages")
    monkeypatch.setattr(subscription, "PROFILE_URL", base + "/api/oauth/profile")


# --- the setting: parsing and the stored value -------------------------------


class TestParse:
    def test_credentials_are_read_and_percent_decoded(self):
        route = account_proxy.parse("http://us%40er:p%40ss%3Aword@127.0.0.1:3128")
        assert route.host == "127.0.0.1"
        assert route.port == 3128
        assert route.username == "us@er"
        assert route.password == "p@ss:word"
        expected = base64.b64encode(b"us@er:p@ss:word").decode()
        assert route.authorization == f"Basic {expected}"

    def test_the_default_port_is_eighty(self):
        assert account_proxy.parse("http://proxy.example").port == 80

    def test_stored_form_is_canonical(self):
        route = account_proxy.parse("HTTP://user:p%40ss@Proxy.Example:3128/")
        assert route.text() == "http://user:p%40ss@proxy.example:3128"
        assert account_proxy.parse(route.text()).text() == route.text()

    def test_display_masks_the_password_and_text_keeps_it(self):
        route = account_proxy.parse("http://user:secret@127.0.0.1:3128")
        assert "secret" not in route.display()
        assert route.display() == "http://user:***@127.0.0.1:3128"
        assert "secret" in route.text()

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "127.0.0.1:3128",          # no scheme
            "https://127.0.0.1:3128",  # urllib cannot speak TLS to the proxy
            "socks5://127.0.0.1:1080",
            "http://",                 # no host
            "http://:3128",
            "http://127.0.0.1:0",
            "http://127.0.0.1:70000",
            "http://127.0.0.1:abc",
            "http://127.0.0.1:3128/path",
            "http://127.0.0.1:3128?x=1",
            "http://:secret@127.0.0.1:3128",   # no user name
        ],
    )
    def test_unusable_urls_are_refused(self, value):
        with pytest.raises(account_proxy.ProxyUrlError):
            account_proxy.parse(value)

    def test_the_error_never_repeats_the_password(self):
        with pytest.raises(account_proxy.ProxyUrlError) as err:
            account_proxy.parse("https://user:secret@127.0.0.1:3128")
        assert "secret" not in str(err.value)

    def test_absent_field_is_direct(self):
        assert account_proxy.route_for({"email": "a@b"}) is None
        assert account_proxy.route_for(None) is None

    def test_a_stored_value_that_does_not_parse_blocks_instead_of_going_direct(self):
        route = account_proxy.route_for(
            {"proxy": "https://user:secret@127.0.0.1:3128"}
        )
        assert route is not None and route.invalid
        assert "secret" not in route.display()  # the stored value is not echoed
        with pytest.raises(account_proxy.ProxyRouteError) as err:
            route.open(urllib.request.Request("http://127.0.0.1:1/"))
        assert err.value.kind == account_proxy.PROXY_INVALID


class TestRouteTransport:
    """The route itself, against a local proxy."""

    def test_an_http_request_arrives_at_the_proxy_in_absolute_form(self, proxy):
        route = account_proxy.parse(proxy.url)
        response = route.open(
            urllib.request.Request("http://origin.invalid/api/oauth/usage")
        )
        assert response.status == 200
        assert proxy.paths() == ["http://origin.invalid/api/oauth/usage"]

    def test_the_proxy_credentials_travel_as_proxy_authorization(self, proxy):
        route = account_proxy.parse(
            f"http://user:{urllib.parse.quote('p@ss')}@{proxy.url.split('//')[1]}"
        )
        route.open(
            urllib.request.Request("http://origin.invalid/api/oauth/usage")
        )
        header = proxy.only("GET")["headers"]["Proxy-Authorization"]
        assert header == "Basic " + base64.b64encode(b"user:p@ss").decode()

    def test_an_https_request_tunnels_with_the_credentials_and_nothing_else(self, proxy):
        """CONNECT carries the proxy's credentials, never the account's token."""
        route = account_proxy.parse(
            f"http://user:pw@{proxy.url.split('//')[1]}"
        )
        request = urllib.request.Request(
            "https://api.anthropic.com/api/oauth/usage",
            headers={"Authorization": "Bearer sk-secret"},
        )
        with pytest.raises(Exception):
            # The proxy answers the tunnel and closes; the TLS handshake is
            # what fails, and the tunnel request is what this test reads.
            route.open(request)
        connect = proxy.only("CONNECT")
        assert connect["path"] == "api.anthropic.com:443"
        header = connect["headers"]["Proxy-Authorization"]
        assert header == "Basic " + base64.b64encode(b"user:pw").decode()
        assert "sk-secret" not in json.dumps(connect["headers"])

    def test_a_407_is_its_own_kind(self):
        def refuses(method, path):
            return 407, {"Proxy-Authenticate": "Basic"}, b"no"

        with LocalServer(refuses) as proxy:
            route = account_proxy.parse(proxy.url)
            with pytest.raises(account_proxy.ProxyRouteError) as err:
                route.open(urllib.request.Request("http://origin.invalid/x"))
        assert err.value.kind == account_proxy.PROXY_AUTH

    def test_a_redirect_is_refused_rather_than_followed(self):
        def redirects(method, path):
            return 302, {"Location": "http://elsewhere.invalid/x"}, b""

        with LocalServer(redirects) as proxy:
            route = account_proxy.parse(proxy.url)
            with pytest.raises(account_proxy.ProxyRouteError) as err:
                route.open(urllib.request.Request("http://origin.invalid/x"))
            assert len(proxy.requests) == 1  # not followed
        assert err.value.kind == account_proxy.PROXY_REDIRECT

    def test_an_unreachable_proxy_raises_without_a_direct_attempt(
        self, direct_calls
    ):
        route = account_proxy.parse("http://127.0.0.1:9")
        with pytest.raises(urllib.error.URLError):
            route.open(urllib.request.Request("http://origin.invalid/x"))
        assert direct_calls == []

    @pytest.mark.parametrize("name", ["NO_PROXY", "no_proxy"])
    def test_no_proxy_does_not_bypass_the_route(
        self, proxy, origin, monkeypatch, name
    ):
        monkeypatch.setenv(name, "*")
        monkeypatch.setenv("HTTP_PROXY", origin.url)
        monkeypatch.setenv("HTTPS_PROXY", origin.url)
        route = account_proxy.parse(proxy.url)
        route.open(urllib.request.Request(f"{origin.url}/api/oauth/usage"))
        assert proxy.paths() == [f"{origin.url}/api/oauth/usage"]
        assert origin.requests == []


# --- the switcher: setting lifecycle ----------------------------------------


def _switcher(sample_sequence_data: dict) -> ClaudeAccountSwitcher:
    sample_sequence_data["accounts"]["1"]["email"] = "test@example.com"
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._write_json(switcher.sequence_file, sample_sequence_data)
    return switcher


class TestSettingLifecycle:
    def test_set_read_unset(self, temp_home: Path, sample_sequence_data: dict):
        s = _switcher(sample_sequence_data)
        num, masked = s.set_account_proxy("1", "http://user:pw@127.0.0.1:3128")
        assert num == "1"
        assert masked == "http://user:***@127.0.0.1:3128"

        stored = s._get_sequence_data()["accounts"]["1"]["proxy"]
        assert stored == "http://user:pw@127.0.0.1:3128"
        assert "pw" not in masked

        assert s.list_account_proxies() == [
            ("1", "http://user:***@127.0.0.1:3128", "test@example.com")
        ]

        s.clear_account_proxy("1")
        assert "proxy" not in s._get_sequence_data()["accounts"]["1"]
        assert s.list_account_proxies() == []
        s.clear_account_proxy("1")  # idempotent

    def test_a_rejected_url_writes_nothing(
        self, temp_home: Path, sample_sequence_data: dict
    ):
        s = _switcher(sample_sequence_data)
        before = s.sequence_file.read_bytes()
        with pytest.raises(ValidationError):
            s.set_account_proxy("1", "socks5://127.0.0.1:1080")
        assert s.sequence_file.read_bytes() == before

    def test_the_proxy_moves_with_the_account_on_swap_and_move(
        self, temp_home: Path, sample_sequence_data: dict
    ):
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://127.0.0.1:3128")
        s.swap_accounts("1", "2")
        data = s._get_sequence_data()
        assert data["accounts"]["2"]["proxy"] == "http://127.0.0.1:3128"
        assert "proxy" not in data["accounts"]["1"]

        s.move_account("2", "3")
        data = s._get_sequence_data()
        assert data["accounts"]["3"]["proxy"] == "http://127.0.0.1:3128"

    def test_removing_the_account_removes_the_proxy(
        self, temp_home: Path, sample_sequence_data: dict
    ):
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://127.0.0.1:3128")
        s.remove_account("1", assume_yes=True)
        data = s._get_sequence_data()
        assert "1" not in data["accounts"]
        assert "proxy" not in json.dumps(data)

    def test_readding_the_same_account_keeps_its_proxy(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict
    ):
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://127.0.0.1:3128")
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "sk-live", "refreshToken": "rt-live",
            "expiresAt": 9999999999000,
        }})
        with patch.object(s, "_read_capture_credentials", return_value=creds), \
             patch("claude_swap.oauth.fetch_oauth_profile", return_value=None):
            s.add_account(slot=1, assume_yes=True)
        assert s._get_sequence_data()["accounts"]["1"]["proxy"] == (
            "http://127.0.0.1:3128"
        )

    def test_add_stores_an_explicit_proxy(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict
    ):
        s = _switcher(sample_sequence_data)
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "sk-live", "refreshToken": "rt-live",
            "expiresAt": 9999999999000,
        }})
        with patch.object(s, "_read_capture_credentials", return_value=creds), \
             patch("claude_swap.oauth.fetch_oauth_profile", return_value=None):
            s.add_account(slot=2, assume_yes=True,
                          proxy="http://user:pw@127.0.0.1:3128")
        stored = s._get_sequence_data()["accounts"]["2"]["proxy"]
        assert stored == "http://user:pw@127.0.0.1:3128"

    def test_add_refuses_an_unusable_proxy_before_touching_anything(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict
    ):
        s = _switcher(sample_sequence_data)
        with pytest.raises(ValidationError):
            s.add_account(slot=3, proxy="https://127.0.0.1:3128")
        assert "3" not in s._get_sequence_data()["accounts"]


# --- the switcher: routing a request ----------------------------------------


def _info(num: int, creds: str, *, active: bool = False):
    return (num, "test@example.com", "", "", active, creds, "")


class TestRouting:
    def test_the_backup_refresh_and_the_usage_read_both_use_the_proxy(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        """A stored token is refreshed and used without a direct connection.

        The successor the token endpoint returned must reach the slot's backup
        — the grant is spent server-side the moment it is POSTed.
        """
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", f"http://user:pw@{proxy.url.split('//')[1]}")
        s._write_account_credentials("1", "test@example.com", CREDS_EXPIRED)

        record = s._fetch_account_usage(_info(1, CREDS_EXPIRED))

        assert record.error is None
        assert record.usage["five_hour"]["pct"] == 10.0
        assert proxy.paths("POST") == [origin.url + "/v1/oauth/token"]
        assert proxy.paths("GET") == [origin.url + "/api/oauth/usage"]
        assert "Proxy-Authorization" in proxy.only("POST")["headers"]
        assert origin.requests == [] and direct_calls == []
        saved = json.loads(s._read_account_credentials("1", "test@example.com"))
        assert saved["claudeAiOauth"]["accessToken"] == "sk-new"
        assert saved["claudeAiOauth"]["refreshToken"] == "rt-new"  # successor kept

    def test_an_account_without_a_proxy_goes_direct_as_before(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        """The control: no proxy set means the unchanged, direct path."""
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        record = s._fetch_account_usage(_info(1, CREDS_OK))
        assert record.error == "network"
        assert len(direct_calls) == 1
        assert proxy.requests == [] and origin.requests == []

    def test_each_slot_uses_its_own_proxy(
        self, temp_home: Path, sample_sequence_data: dict, origin,
        direct_calls, monkeypatch,
    ):
        _endpoints(monkeypatch, origin.url)
        with LocalServer(_proxy_responder) as first, LocalServer(_proxy_responder) as second:
            s = _switcher(sample_sequence_data)
            s.set_account_proxy("1", first.url)
            s.set_account_proxy("2", second.url)
            assert s._fetch_account_usage(_info(1, CREDS_OK)).error is None
            assert s._fetch_account_usage(_info(2, CREDS_OK)).error is None
            assert first.paths("GET") == [origin.url + "/api/oauth/usage"]
            assert second.paths("GET") == [origin.url + "/api/oauth/usage"]
        assert origin.requests == [] and direct_calls == []

    def test_a_rejected_proxy_credentials_read_is_an_error_not_a_dead_token(
        self, temp_home: Path, sample_sequence_data: dict, origin,
        direct_calls, monkeypatch,
    ):
        def refuses(method, path):
            return 407, {"Proxy-Authenticate": "Basic"}, b"no"

        with LocalServer(refuses) as proxy:
            _endpoints(monkeypatch, origin.url)
            s = _switcher(sample_sequence_data)
            s.set_account_proxy("1", proxy.url)
            record = s._fetch_account_usage(_info(1, CREDS_OK))
        assert record.error == account_proxy.PROXY_AUTH
        assert record.struck_fp is None  # the token was never judged
        assert origin.requests == [] and direct_calls == []

    def test_a_redirecting_proxy_is_an_error(self, temp_home, sample_sequence_data,
                                             origin, direct_calls, monkeypatch):
        def redirects(method, path):
            return 307, {"Location": "http://elsewhere.invalid/"}, b""

        with LocalServer(redirects) as proxy:
            _endpoints(monkeypatch, origin.url)
            s = _switcher(sample_sequence_data)
            s.set_account_proxy("1", proxy.url)
            record = s._fetch_account_usage(_info(1, CREDS_OK))
        assert record.error == account_proxy.PROXY_REDIRECT
        assert origin.requests == [] and direct_calls == []

    def test_an_unreachable_proxy_fails_without_a_direct_connection(
        self, temp_home: Path, sample_sequence_data: dict, origin,
        direct_calls, monkeypatch,
    ):
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://127.0.0.1:9")
        record = s._fetch_account_usage(_info(1, CREDS_OK))
        assert record.error == "network"
        assert origin.requests == [] and direct_calls == []

    def test_an_unusable_stored_value_blocks_the_request(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        """Proving the account is proxied is enough to forbid a direct one."""
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        data = s._get_sequence_data()
        data["accounts"]["1"]["proxy"] = "socks5://127.0.0.1:1080"
        s._write_json(s.sequence_file, data)
        record = s._fetch_account_usage(_info(1, CREDS_OK))
        assert record.error == account_proxy.PROXY_INVALID
        assert proxy.requests == [] and origin.requests == [] and direct_calls == []

    def test_the_active_refresh_and_usage_use_the_proxy(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict,
        proxy, origin, direct_calls, monkeypatch,
    ):
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", proxy.url)
        s._write_credentials(CREDS_EXPIRED)
        s._write_account_credentials("1", "test@example.com", CREDS_EXPIRED)

        record = s._fetch_active_usage("1", "test@example.com", CREDS_EXPIRED)

        assert record.error is None
        assert record.usage["five_hour"]["pct"] == 10.0
        assert proxy.paths("POST") == [origin.url + "/v1/oauth/token"]
        assert proxy.paths("GET") == [origin.url + "/api/oauth/usage"]
        assert origin.requests == [] and direct_calls == []
        assert "rt-new" in s._read_credentials()

    @pytest.mark.no_oauth_profile_fake
    def test_the_owner_lookup_follows_the_named_slot_not_the_tokens_owner(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict,
        proxy, origin, direct_calls, monkeypatch,
    ):
        """The documented residual risk, pinned so acceptance can weigh it.

        ``~/.claude.json`` names slot 1 and slot 1 has no proxy, while the live
        credential is really slot 2's and slot 2 does have one. The ownership
        lookup goes over the *named* slot's route — direct here — because the
        route, like the slot, is chosen by that file. Nothing is written: the
        answer only lets the toggle under the locks attribute the bytes, and a
        failed lookup leaves the ownership unresolved instead.
        """
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("2", proxy.url)
        s._write_credentials(CREDS_OK)          # live bytes: slot 2's login
        s._write_account_credentials("1", "test@example.com", CREDS_EXPIRED)
        before = s.sequence_file.read_bytes()

        resolved = s._prefetch_live_identity()

        assert resolved["resolved"] is None
        assert direct_calls == [origin.url + "/api/oauth/profile"]  # not the proxy
        assert proxy.requests == []
        assert s.sequence_file.read_bytes() == before
        assert s._read_account_credentials("1", "test@example.com") == CREDS_EXPIRED

    @pytest.mark.no_oauth_profile_fake
    def test_the_profile_and_plan_reads_use_the_proxy(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", proxy.url)
        route = s._account_route("1")

        profile = oauth.fetch_oauth_profile("sk-live", route=route)
        plan = subscription.fetch_plan("sk-live", route=route)

        assert profile == {"uuid": "uuid-1", "email": "test@example.com",
                           "organizationUuid": None}
        assert plan.plan["tier"] == "default_claude_max_5x"
        assert proxy.paths("GET") == [
            origin.url + "/api/oauth/profile",
            origin.url + "/api/oauth/profile",
        ]
        assert origin.requests == [] and direct_calls == []


    def test_status_json_shows_the_masked_proxy(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict,
    ):
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://user:secret@127.0.0.1:3128")
        s._write_credentials(CREDS_OK)
        payload = s._build_status_payload()
        assert payload["active"]["proxy"] == "http://user:***@127.0.0.1:3128"
        assert "secret" not in json.dumps(payload)


# --- transfer ---------------------------------------------------------------


class TestTransfer:
    def _export(self, s, tmp_path: Path) -> dict:
        from claude_swap import transfer

        dest = tmp_path / "export.json"
        transfer.export_accounts(s, str(dest))
        return json.loads(dest.read_text())

    def test_export_never_carries_the_proxy_and_says_so(
        self, temp_home: Path, sample_sequence_data: dict, tmp_path, capsys,
    ):
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://user:secret@127.0.0.1:3128")
        s._write_account_credentials("1", "test@example.com", CREDS_OK)
        s._write_account_config(
            "1", "test@example.com",
            json.dumps({"oauthAccount": {"emailAddress": "test@example.com"}}),
        )
        exported = self._export(s, tmp_path)
        assert "secret" not in json.dumps(exported)
        assert "proxy" not in json.dumps(exported)
        err = capsys.readouterr().err
        assert "Account-1" in err and "secret" not in err
        assert "cswap proxy" in err

    def test_import_keeps_the_local_proxy_for_the_same_account(
        self, temp_home: Path, sample_sequence_data: dict, tmp_path,
    ):
        from claude_swap import transfer

        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://127.0.0.1:3128")
        s._write_account_credentials("1", "test@example.com", CREDS_OK)
        s._write_account_config(
            "1", "test@example.com",
            json.dumps({"oauthAccount": {"emailAddress": "test@example.com"}}),
        )
        exported = self._export(s, tmp_path)

        s.clear_account_proxy("1")
        source = tmp_path / "in.json"
        source.write_text(json.dumps(exported))
        transfer.import_accounts(s, str(source), force=True)
        assert "proxy" not in s._get_sequence_data()["accounts"]["1"]

        s.set_account_proxy("1", "http://127.0.0.1:3128")
        transfer.import_accounts(s, str(source), force=True)
        assert s._get_sequence_data()["accounts"]["1"]["proxy"] == (
            "http://127.0.0.1:3128"
        )

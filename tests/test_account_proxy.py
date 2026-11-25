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
import http.client
import json
import logging
import socket
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from claude_swap import account_proxy, oauth, subscription
from claude_swap.exceptions import ValidationError
from claude_swap.locking import FileLock
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
            if server.connect is not None:
                status, phrase = server.connect
                self.send_response(status, phrase)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
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
    """A loopback HTTP server whose replies a test controls.

    ``connect``, when given, is the ``(status, phrase)`` a CONNECT gets
    instead of the default 200; the phrase is what the client would put in its
    error message, so a test can prove it does not travel further.
    """

    def __init__(
        self, responder=None, address: str = "127.0.0.1", connect=None
    ):
        self.responder = responder or (lambda method, path: (200, {}, b"{}"))
        self.connect = connect
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        self.httpd = ThreadingHTTPServer((address, 0), _Recorder)
        self.httpd.responder = self.responder
        self.httpd.connect = self.connect
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


@pytest.fixture
def dead_proxy():
    """A proxy address that cannot be reached, without assuming a port.

    A bound socket that never listens is unreachable: Linux refuses the
    connection, macOS times it out (measured on the macOS CI runner with
    CPython 3.12.10). Holding it for the test keeps anything else from taking
    the port. A fixed number (the old port 9) only refuses if nothing on this
    machine happens to be listening there, which would turn the test into
    whatever that is.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    try:
        yield SimpleNamespace(port=sock.getsockname()[1])
    finally:
        sock.close()


@pytest.fixture
def other_protocol_proxy():
    """A port that answers a CONNECT with another protocol's greeting.

    What an SSH, SMTP or TLS endpoint does when a proxy URL names its port:
    ``http.client`` reads the first line as a status line and raises
    ``BadStatusLine`` with that text inside.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    banner = "SSH-2.0-OpenSSH_9.6 proxy-password-in-banner"

    def answer() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:  # closed before the client connected
            return
        with connection:
            connection.recv(4096)
            connection.sendall(banner.encode() + b"\r\n")

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(
            url=f"http://127.0.0.1:{listener.getsockname()[1]}", banner=banner
        )
    finally:
        listener.close()
        thread.join(timeout=5)


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

    def test_an_explicit_null_is_damage_not_a_cleared_setting(self):
        """Only an ABSENT key means "direct"; ``"proxy": null`` must fail closed.

        ``--unset`` removes the key, so a null on disk was hand-edited or
        written by something that did not understand the field. Reading it as
        "no proxy" would silently return a proxied account to a direct
        connection — the one outcome the setting exists to forbid.
        """
        route = account_proxy.route_for({"email": "a@b", "proxy": None})
        assert route is not None and route.invalid
        assert account_proxy.describe({"proxy": None}) == (
            "invalid (the stored value is not a URL)"
        )

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
        self, dead_proxy, direct_calls
    ):
        route = account_proxy.parse(f"http://127.0.0.1:{dead_proxy.port}")
        with pytest.raises(urllib.error.URLError):
            route.open(urllib.request.Request("http://origin.invalid/x"))
        assert direct_calls == []

    @pytest.mark.parametrize(
        "reply, kind",
        [
            ((407, "Authentication required"), account_proxy.PROXY_AUTH),
            ((302, "See https://elsewhere.invalid/"), account_proxy.PROXY_REDIRECT),
            ((307, "Temporary redirect"), account_proxy.PROXY_REDIRECT),
            ((502, "Bad gateway"), None),
        ],
    )
    def test_a_refused_connect_tunnel_keeps_the_code_and_drops_the_phrase(
        self, reply, kind
    ):
        """http.client reports a refused CONNECT as ``OSError``, not HTTPError.

        Its message carries the proxy's own status phrase, which can name a
        credential. The route must classify 407/3xx like the plain-HTTP case
        and must never repeat that phrase in a message a caller can log.
        """
        phrase = reply[1]
        with LocalServer(connect=reply) as proxy:
            route = account_proxy.parse(proxy.url)
            request = urllib.request.Request(
                "https://api.anthropic.com/api/oauth/usage",
                headers={"Authorization": "Bearer sk-secret"},
            )
            if kind is None:
                with pytest.raises(urllib.error.URLError) as err:
                    route.open(request)
                assert "the proxy refused the CONNECT tunnel (HTTP 502)" in str(
                    err.value
                )
            else:
                with pytest.raises(account_proxy.ProxyRouteError) as err:
                    route.open(request)
                assert err.value.kind == kind
            assert proxy.paths("CONNECT") == ["api.anthropic.com:443"]
            assert phrase not in str(err.value)
            assert "sk-secret" not in str(err.value)

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
            ("1", "http://user:***@127.0.0.1:3128", "test@example.com", None)
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

    def test_the_proxy_commands_hold_the_account_lock(
        self, temp_home: Path, sample_sequence_data: dict, monkeypatch
    ):
        """Resolve → read → write is one step under the lock switch/swap take.

        The probe re-acquires the lock from inside the suspected span: flock
        is per open file description, so a second acquisition fails exactly
        while the span holds it. Deterministic, no threads and no timing.
        """
        s = _switcher(sample_sequence_data)
        held: list[bool] = []

        def probe(original):
            def wrapped(*args, **kwargs):
                handle = FileLock(s.lock_file, timeout=0.05)
                held.append(handle.acquire())
                handle.release()
                return original(*args, **kwargs)
            return wrapped

        writes: list[bool] = []
        real_write = ClaudeAccountSwitcher._write_json

        def write_probe(self, path, data):
            if path == self.sequence_file:
                handle = FileLock(self.lock_file, timeout=0.05)
                writes.append(handle.acquire())
                handle.release()
            return real_write(self, path, data)

        monkeypatch.setattr(
            ClaudeAccountSwitcher, "_resolve_for_policy_write",
            probe(ClaudeAccountSwitcher._resolve_for_policy_write),
        )
        monkeypatch.setattr(ClaudeAccountSwitcher, "_write_json", write_probe)

        s.set_account_proxy("1", "http://127.0.0.1:3128")
        s.clear_account_proxy("1")

        assert held == [False, False]       # resolved under the lock
        assert writes and not any(writes)   # and every write made under it

    def test_an_explicit_null_stored_value_fails_closed(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        data = s._get_sequence_data()
        data["accounts"]["1"]["proxy"] = None
        s._write_json(s.sequence_file, data)

        record = s._fetch_account_usage(_info(s, 1, CREDS_OK))

        assert record.error == account_proxy.PROXY_INVALID
        assert record.struck_fp is None  # the token was never judged
        assert proxy.requests == [] and origin.requests == []
        assert direct_calls == []

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

    def test_an_ordinary_add_to_a_free_slot_keeps_the_proxy(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict
    ):
        """``add --slot N`` moves the account, not the setting: a free target
        slot has no record of its own to read it from, and dropping it here
        would send the account direct on its next request."""
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://user:pw@127.0.0.1:3128")
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "sk-live", "refreshToken": "rt-live",
            "expiresAt": 9999999999000,
        }})
        with patch.object(s, "_read_capture_credentials", return_value=creds), \
             patch("claude_swap.oauth.fetch_oauth_profile", return_value=None):
            s.add_account(slot=4, assume_yes=True)
        data = s._get_sequence_data()
        assert "1" not in data["accounts"] and "1" not in data["sequence"]
        assert data["accounts"]["4"]["email"] == "test@example.com"
        assert data["accounts"]["4"]["proxy"] == "http://user:pw@127.0.0.1:3128"

    def test_a_damaged_null_proxy_survives_a_move_and_still_fails_closed(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict
    ):
        """``null`` is damage, not "no proxy": a move must carry the KEY, so
        the destination keeps refusing instead of quietly going direct."""
        s = _switcher(sample_sequence_data)
        data = s._get_sequence_data()
        data["accounts"]["1"][account_proxy.FIELD] = None
        s._write_json(s.sequence_file, data)
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "sk-live", "refreshToken": "rt-live",
            "expiresAt": 9999999999000,
        }})
        with patch.object(s, "_read_capture_credentials", return_value=creds), \
             patch("claude_swap.oauth.fetch_oauth_profile", return_value=None):
            s.add_account(slot=4, assume_yes=True)

        record = s._get_sequence_data()["accounts"]["4"]
        assert account_proxy.FIELD in record and record[account_proxy.FIELD] is None
        assert account_proxy.describe(record) == (
            "invalid (the stored value is not a URL)"
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


def _info(s: ClaudeAccountSwitcher, num: int, creds: str, *, active: bool = False):
    """One account's read snapshot, built the way ``_build_accounts_info`` does.

    The route comes from the registry, so a test that sets a proxy before
    calling this gets the pinned route the switcher itself would have taken.
    """
    account = (s._get_sequence_data() or {}).get("accounts", {}).get(str(num), {})
    return (
        num, account.get("email", "test@example.com"), "", "", active, creds, "",
        account_proxy.route_for(account),
    )


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

        record = s._fetch_account_usage(_info(s, 1, CREDS_EXPIRED))

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
        record = s._fetch_account_usage(_info(s, 1, CREDS_OK))
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
            assert s._fetch_account_usage(_info(s, 1, CREDS_OK)).error is None
            assert s._fetch_account_usage(_info(s, 2, CREDS_OK)).error is None
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
            record = s._fetch_account_usage(_info(s, 1, CREDS_OK))
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
            record = s._fetch_account_usage(_info(s, 1, CREDS_OK))
        assert record.error == account_proxy.PROXY_REDIRECT
        assert origin.requests == [] and direct_calls == []

    def test_an_unreachable_proxy_fails_without_a_direct_connection(
        self, temp_home: Path, sample_sequence_data: dict, origin, dead_proxy,
        direct_calls, monkeypatch,
    ):
        """An unreachable proxy is an error, and nothing goes direct.

        How the stack reports a bound socket that never listens depends on the
        OS: Linux refuses the connection, macOS times it out. Both mean
        nothing left the route, so either kind passes here; the kinds
        themselves are ``tests/test_oauth.py``'s subject.
        """
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", f"http://127.0.0.1:{dead_proxy.port}")
        record = s._fetch_account_usage(_info(s, 1, CREDS_OK))
        assert record.error in ("network", "timeout")
        assert origin.requests == [] and direct_calls == []

    @pytest.mark.parametrize(
        "status, kind",
        [
            (407, account_proxy.PROXY_AUTH),
            (302, account_proxy.PROXY_REDIRECT),
            (307, account_proxy.PROXY_REDIRECT),
        ],
    )
    def test_a_refused_connect_tunnel_is_reported_without_its_text_in_the_log(
        self, temp_home: Path, sample_sequence_data: dict, direct_calls,
        monkeypatch, caplog, status, kind,
    ):
        """An HTTPS request is tunnelled, and its refusal never reaches a log.

        The proxy's status phrase rides inside http.client's ``OSError``; the
        route keeps only the code, so the account gets its ``proxy-*`` kind and
        the debug line carries no text the proxy chose.
        """
        phrase = "Authentication required pw=topsecret"
        with LocalServer(connect=(status, phrase)) as proxy:
            s = _switcher(sample_sequence_data)
            s.set_account_proxy("1", proxy.url)
            with caplog.at_level(logging.DEBUG, logger="claude-swap"):
                record = s._fetch_account_usage(_info(s, 1, CREDS_OK))

        assert record.error == kind
        assert record.struck_fp is None
        assert proxy.paths("CONNECT") == ["api.anthropic.com:443"]
        assert "topsecret" not in caplog.text
        assert "topsecret" not in repr(record)
        assert direct_calls == []

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
        record = s._fetch_account_usage(_info(s, 1, CREDS_OK))
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

        record = s._fetch_account_usage(
            _info(s, 1, CREDS_EXPIRED, active=True)
        )

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
        route = account_proxy.route_for(s._get_sequence_data()["accounts"]["1"])

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


    def test_a_swap_after_the_snapshot_keeps_the_accounts_own_route(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        """The route travels with the account snapshot the token came from.

        ``cswap swap 1 2`` moves the proxied account to slot 2 and puts the
        unproxied one in slot 1. A request started from the snapshot taken
        before the swap must still use that account's proxy — looking the
        route up by slot number at send time would find slot 1's new owner,
        see no proxy, and connect directly.
        """
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", proxy.url)
        s._write_account_credentials("1", "test@example.com", CREDS_OK)
        info = s._build_accounts_info()[0]           # account 1: token + route

        data = s._get_sequence_data()
        data["accounts"]["1"], data["accounts"]["2"] = (
            data["accounts"]["2"], data["accounts"]["1"],
        )
        s._write_json(s.sequence_file, data)

        record = s._fetch_account_usage(info)

        assert record.error is None
        assert proxy.paths("GET") == [origin.url + "/api/oauth/usage"]
        assert origin.requests == [] and direct_calls == []

    @pytest.mark.no_oauth_profile_fake
    def test_a_swap_after_the_snapshot_keeps_the_plan_reads_route(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", proxy.url)
        s._write_account_credentials("1", "test@example.com", CREDS_OK)
        info = s._build_accounts_info()[:1]

        data = s._get_sequence_data()
        data["accounts"]["1"], data["accounts"]["2"] = (
            data["accounts"]["2"], data["accounts"]["1"],
        )
        s._write_json(s.sequence_file, data)

        s._collect_subscription_plans(info)

        assert proxy.paths("GET") == [origin.url + "/api/oauth/profile"]
        assert origin.requests == [] and direct_calls == []

    def test_a_move_between_the_gates_locked_read_and_its_post_keeps_the_route(
        self, temp_home: Path, sample_sequence_data: dict, proxy, origin,
        direct_calls, monkeypatch,
    ):
        """The backup gate's route is read under the same lock as its grant.

        The swap below lands after the gate released the lock and before its
        POST — the window the report names. Reading the route by slot number
        there would find the new slot-1 owner (no proxy) and POST the grant
        directly.
        """
        _endpoints(monkeypatch, origin.url)
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", proxy.url)
        s._write_account_credentials("1", "test@example.com", CREDS_EXPIRED)
        info = s._build_accounts_info()[0]

        real = s._live_login_holds
        moved: list[bool] = []

        def swap_then_answer(credentials):
            if not moved:
                moved.append(True)
                data = s._get_sequence_data()
                data["accounts"]["1"], data["accounts"]["2"] = (
                    data["accounts"]["2"], data["accounts"]["1"],
                )
                s._write_json(s.sequence_file, data)
            return real(credentials)

        monkeypatch.setattr(s, "_live_login_holds", swap_then_answer)

        record = s._fetch_account_usage(info)

        assert moved == [True]
        assert record.error is None
        assert proxy.paths("POST") == [origin.url + "/v1/oauth/token"]
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

    def test_json_shows_a_damaged_setting_rather_than_hiding_it(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict,
    ):
        """A null on disk is visible as invalid, not silently absent."""
        s = _switcher(sample_sequence_data)
        data = s._get_sequence_data()
        data["accounts"]["1"]["proxy"] = None
        s._write_json(s.sequence_file, data)
        s._write_credentials(CREDS_OK)

        payload = s._build_status_payload()

        assert payload["active"]["proxy"] == (
            "invalid (the stored value is not a URL)"
        )


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


class TestOwnershipUnderTheLock:
    """The snapshot's owner, route and credential are one locked read.

    Every slot mutation (`switch`, `swap`, `move`, the registry writers) takes
    the account lock, so a read that holds it cannot be split: no `swap` can
    replace the record (or the backup files keyed to it) between "who is in
    this slot" and "what credential does this slot hold". These tests probe
    those boundaries from inside them, the same way
    ``test_the_proxy_commands_hold_the_account_lock`` does: flock is per open
    file description, so a second acquisition fails exactly while the span
    holds it.
    """

    def test_the_snapshot_holds_the_account_lock_while_it_reads(
        self, temp_home: Path, sample_sequence_data: dict, monkeypatch
    ):
        s = _switcher(sample_sequence_data)
        held: list[bool] = []
        real = ClaudeAccountSwitcher._read_account_credentials

        def probe(self, *args, **kwargs):
            handle = FileLock(self.lock_file, timeout=0.05)
            held.append(handle.acquire())
            handle.release()
            return real(self, *args, **kwargs)

        monkeypatch.setattr(ClaudeAccountSwitcher, "_read_account_credentials", probe)
        s._build_accounts_info()

        assert held and not any(held), (
            "a slot's credential was read outside the account lock, so a "
            "swap/move could land between the record and the bytes"
        )

    def test_a_lock_held_elsewhere_sends_no_request(
        self, temp_home: Path, sample_sequence_data: dict, direct_calls,
        monkeypatch,
    ):
        """Another cswap holding the lock means the owner cannot be pinned.

        Rows are still shown (from stored data), but no request may leave:
        the route is unconfirmed, and a direct guess is what a proxied
        account forbids.
        """
        from claude_swap.json_output import USAGE_OWNER_CHANGED

        _endpoints(monkeypatch, "http://127.0.0.1:1")
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://127.0.0.1:3128")
        s._write_account_credentials("1", "test@example.com", CREDS_OK)

        fetch_calls: list[str] = []
        monkeypatch.setattr(
            oauth, "try_fetch_usage_for_account",
            lambda num, *a, **k: fetch_calls.append(num),
        )
        handle = FileLock(s.lock_file, timeout=1.0)
        assert handle.acquire()
        try:
            payload = s.list_accounts(json_output=True)
        finally:
            handle.release()

        assert fetch_calls == [] and direct_calls == []
        by_num = {a["number"]: a for a in payload["accounts"]}
        assert by_num[1]["usageStatus"] == "owner_changed"
        assert USAGE_OWNER_CHANGED == "owner changed"  # the sentinel itself

    def test_status_json_keeps_the_stored_proxy_when_the_lock_is_held(
        self, temp_home: Path, mock_claude_config: Path, sample_sequence_data: dict,
        direct_calls,
    ):
        """A skip must not be reported through `proxy`: the field is the
        stored setting, so a lock nobody can see on screen must not make an
        account with a healthy proxy read as broken."""
        s = _switcher(sample_sequence_data)
        s.set_account_proxy("1", "http://user:pw@127.0.0.1:3128")
        handle = FileLock(s.lock_file, timeout=1.0)
        assert handle.acquire()
        try:
            payload = s._build_status_payload()
        finally:
            handle.release()

        assert payload["active"]["proxy"] == "http://user:***@127.0.0.1:3128"
        assert payload["active"]["usageStatus"] == "owner_changed"
        assert direct_calls == []

    def test_a_sibling_with_the_same_email_is_not_the_account(
        self, temp_home: Path, sample_sequence_data: dict, direct_calls,
        monkeypatch,
    ):
        """Two organizations share one email; only the organization identifies.

        After a real `swap` the backup files are keyed by (slot, email), so the
        slot the snapshot named can hold the sibling's bytes. The gate must
        refuse to POST them, and nothing may be written.
        """
        _endpoints(monkeypatch, "http://127.0.0.1:1")
        s = _switcher(sample_sequence_data)
        # Same email, two organizations, as Claude Code stores them.
        data = s._get_sequence_data()
        data["accounts"]["1"].update(
            {"email": "shared@example.com", "organizationUuid": "org-a"}
        )
        data["accounts"]["2"].update(
            {"email": "shared@example.com", "organizationUuid": "org-b"}
        )
        s._write_json(s.sequence_file, data)
        s._write_account_credentials("1", "shared@example.com", CREDS_EXPIRED)
        s._write_account_credentials("2", "shared@example.com", CREDS_OK)
        before = s.sequence_file.read_bytes()

        posts: list[str] = []
        monkeypatch.setattr(
            oauth, "try_refresh_oauth_credentials",
            lambda *a, **k: posts.append("post") or oauth.RefreshOutcome(None, "t"),
        )
        s.swap_accounts("1", "2")  # slot 1 now holds org-b; its bytes are keyed
        #                                   by (slot 1, shared@example.com)
        outcome = s.consume_backup_grant(
            "1", "shared@example.com", CREDS_EXPIRED, expected_org="org-a"
        )

        assert outcome.error == "slot-moved"
        assert posts == [] and direct_calls == []
        assert s.sequence_file.read_bytes() != before  # the swap itself wrote
        assert s._read_account_credentials("1", "shared@example.com")

    def test_a_move_during_the_post_keeps_the_successor_with_its_account(
        self, temp_home: Path, sample_sequence_data: dict, monkeypatch
    ):
        """A successor belongs to the ACCOUNT, not to the number it was spent at.

        `move` takes the slot lock, so it runs exactly in the window the gate
        leaves open — the POST, which is sent outside every lock. The write
        target is resolved by identity afterwards.
        """
        s = _switcher(sample_sequence_data)
        s._write_account_credentials("1", "test@example.com", CREDS_EXPIRED)
        sibling_before = json.dumps({"claudeAiOauth": {
            "accessToken": "sk-sibling", "refreshToken": "rt-sibling",
            "expiresAt": 9999999999000,
        }})
        s._write_account_credentials("2", "account2@example.com", sibling_before)
        successor = json.dumps({"claudeAiOauth": {
            "accessToken": "sk-successor", "refreshToken": "rt-successor",
            "expiresAt": 9999999999000,
        }})

        def refresh_then_move(*args, **kwargs):
            s.move_account("1", "3")
            return oauth.RefreshOutcome(successor, None)

        monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", refresh_then_move)
        monkeypatch.setattr(s, "_live_session_pids", lambda *a, **k: [])

        outcome = s.consume_backup_grant("1", "test@example.com", CREDS_EXPIRED)

        assert outcome.error is None
        saved = json.loads(s._read_account_credentials("3", "test@example.com"))
        assert saved["claudeAiOauth"]["refreshToken"] == "rt-successor"
        # The slot the account left holds nothing of it, and the sibling's copy
        # is byte-identical to what it was.
        assert s._read_account_credentials("1", "test@example.com") == ""
        assert s._read_account_credentials("2", "account2@example.com") == sibling_before


class TestProbe:
    """The launch's pre-start check: one CONNECT, nothing else."""

    def test_a_working_proxy_opens_the_tunnel(self, proxy):
        account_proxy.probe(account_proxy.parse(proxy.url))
        row = proxy.only("CONNECT")
        assert row["path"] == "api.anthropic.com:443"
        # One request and no other: the check sends nothing to an origin.
        assert proxy.paths() == ["api.anthropic.com:443"]

    def test_the_credentials_of_the_url_travel_on_the_tunnel(self, proxy):
        account_proxy.probe(
            account_proxy.parse(f"http://user:pw@{proxy.url.split('//')[1]}")
        )
        header = proxy.only("CONNECT")["headers"]["Proxy-Authorization"]
        assert header == "Basic " + base64.b64encode(b"user:pw").decode()

    def test_a_url_without_credentials_sends_no_proxy_authorization(self, proxy):
        account_proxy.probe(account_proxy.parse(proxy.url))
        assert "Proxy-Authorization" not in proxy.only("CONNECT")["headers"]

    @pytest.mark.parametrize(
        "status,phrase,kind",
        [
            (407, "Proxy Authentication Required", account_proxy.PROXY_AUTH),
            (302, "Found", account_proxy.PROXY_REDIRECT),
            (502, "Bad Gateway", account_proxy.PROXY_UNREACHABLE),
        ],
        ids=["407", "redirect", "other-status"],
    )
    def test_a_refusal_is_classified_without_the_proxys_own_phrase(
        self, status, phrase, kind
    ):
        """The phrase is the proxy's text and may name a credential."""
        with LocalServer(connect=(status, phrase)) as server:
            with pytest.raises(account_proxy.ProxyRouteError) as err:
                account_proxy.probe(account_proxy.parse(server.url))
        assert err.value.kind == kind
        assert phrase not in str(err.value)

    def test_an_unreachable_proxy(self, dead_proxy):
        route = account_proxy.parse(f"http://127.0.0.1:{dead_proxy.port}")
        with pytest.raises(account_proxy.ProxyRouteError) as err:
            account_proxy.probe(route)
        assert err.value.kind == account_proxy.PROXY_UNREACHABLE

    def test_a_proxy_that_never_answers_the_tunnel(self):
        """A listening backlog with no accept: the connection opens and the
        reply never comes, which is a timeout, not a refusal."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        try:
            route = account_proxy.parse(
                f"http://127.0.0.1:{sock.getsockname()[1]}"
            )
            with pytest.raises(account_proxy.ProxyRouteError) as err:
                account_proxy.probe(route, timeout=0.2)
        finally:
            sock.close()
        assert err.value.kind == account_proxy.PROXY_UNREACHABLE

    def test_a_stored_value_that_does_not_parse_stops_the_probe(self):
        route = account_proxy.unusable("the stored value is not a URL")
        with pytest.raises(account_proxy.ProxyRouteError) as err:
            account_proxy.probe(route)
        assert err.value.kind == account_proxy.PROXY_INVALID

    def test_a_port_that_speaks_another_protocol(self, other_protocol_proxy):
        """An SSH or TLS service answers with a line of its own, which
        ``http.client`` raises as ``BadStatusLine`` carrying that line."""
        with pytest.raises(account_proxy.ProxyRouteError) as err:
            account_proxy.probe(account_proxy.parse(other_protocol_proxy.url))
        assert err.value.kind == account_proxy.PROXY_UNREACHABLE
        assert other_protocol_proxy.banner not in str(err.value)

    def test_a_host_with_a_space_is_refused_without_a_traceback(self):
        """``parse`` lets a space through; the connection cannot be built
        (``InvalidURL`` out of the constructor) and the text it carries is
        not what the launch prints."""
        with pytest.raises(account_proxy.ProxyRouteError) as err:
            account_proxy.probe(account_proxy.parse("http://127.0.0.1 :3128"))
        assert err.value.kind == account_proxy.PROXY_UNREACHABLE
        assert "127.0.0.1" not in str(err.value)

    def test_a_name_the_socket_cannot_encode(self, monkeypatch):
        """A host IDNA cannot encode (``a..b``) raises ``UnicodeError`` from
        inside ``http.client`` — measured on CPython 3.14 — and its text names
        the host. The suite's network guard answers before the socket sees the
        name, so the failure is injected here."""
        def unencodable(*args, **kwargs):
            raise UnicodeError("idna", "a..b", 2, 3, "label empty")

        monkeypatch.setattr(http.client, "HTTPConnection", unencodable)
        with pytest.raises(account_proxy.ProxyRouteError) as err:
            account_proxy.probe(account_proxy.parse("http://a..b:3128"))
        assert err.value.kind == account_proxy.PROXY_UNREACHABLE
        assert str(err.value) == "the proxy's address or its reply is unusable"


class TestLaunchEnv:
    """The variables a launch hands Claude Code for a proxied account."""

    def test_both_spellings_and_the_whole_no_proxy_list(self):
        route = account_proxy.parse("http://user:p%40ss@127.0.0.1:3128")
        env = account_proxy.launch_env(route, "localhost,10.0.0.0/8", {"PATH": "/bin"})
        assert env["PATH"] == "/bin"
        for name in (
            "HTTPS_PROXY", "https_proxy",
            "HTTP_PROXY", "http_proxy",
            "ALL_PROXY", "all_proxy",
        ):
            # The stored form, credentials included: that is how a client
            # presents them to a proxy.
            assert env[name] == "http://user:p%40ss@127.0.0.1:3128"
        assert env["NO_PROXY"] == "localhost,10.0.0.0/8"
        assert env["no_proxy"] == "localhost,10.0.0.0/8"

    def test_every_inherited_spelling_is_dropped_first(self):
        """A shell's ``https_proxy`` wins over ``HTTPS_PROXY`` in Claude Code,
        and ``NO_PROXY=*`` would switch the account's proxy off."""
        route = account_proxy.parse("http://127.0.0.1:3128")
        inherited = {
            "HTTPS_PROXY": "http://old.invalid:1",
            "https_proxy": "http://old.invalid:1",
            "HTTP_PROXY": "http://old.invalid:1",
            "http_proxy": "http://old.invalid:1",
            "ALL_PROXY": "http://old.invalid:1",
            "all_proxy": "http://old.invalid:1",
            "NO_PROXY": "*",
            "no_proxy": "*",
            "PATH": "/bin",
        }
        env = account_proxy.launch_env(route, "localhost", inherited)
        assert "old.invalid" not in " ".join(env.values())
        assert env["NO_PROXY"] == "localhost"
        assert env["PATH"] == "/bin"

"""The egress expectation: its storage, its validation and the exit check.

Three layers are under test:

- the stored rule — normalisation, damage, and what happens to it on
  renumber, removal, re-add, export and import;
- the check — the three-service chain, a mismatch stopping it, and the rule
  that it only ever travels the account's own proxy;
- the surfaces — `cswap proxy`, `cswap list`/`status` and their `--json`
  fields.

Everything network-shaped here runs against loopback servers. The three
services are monkeypatched to local URLs and the proxy is a local HTTP proxy,
so no test depends on a real GeoIP service, and the "direct counter" proves a
request never left the route.
"""

from __future__ import annotations

import json
import socket
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest

from claude_swap import account_proxy, cli, egress
from claude_swap.exceptions import EgressCheckError
from claude_swap.switcher import ClaudeAccountSwitcher
from tests import proxy_servers


# --- local servers -----------------------------------------------------------


class _ProxyHandler(BaseHTTPRequestHandler):
    """A loopback HTTP proxy whose answers a test sets per absolute URL."""

    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - http.server's spelling
        server = self.server
        with server.lock:
            server.requests.append(self.path)
            answer = server.answers.get(self.path)
        status, headers, body = answer or (404, {}, b"{}")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # keep the test output clean
        pass


class LocalProxy:
    """A local HTTP proxy with scripted replies, recording what it was asked."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.answers: dict[str, tuple[int, dict, bytes]] = {}
        self.lock = threading.Lock()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
        self.httpd.daemon_threads = True
        self.httpd.requests = self.requests
        self.httpd.answers = self.answers
        self.httpd.lock = self.lock
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "LocalProxy":
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

    def answer(
        self, url: str, body: object = b"{}", status: int = 200,
        headers: dict | None = None,
    ) -> None:
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        with self.lock:
            self.answers[url] = (status, headers or {}, payload)


class _CountingHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.hits.append(self.client_address)
        self.request.close()


class DirectCounter:
    """A listener that counts connections: reaching it means going direct."""

    def __init__(self) -> None:
        self.hits: list[tuple] = []
        self.server = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), _CountingHandler
        )
        self.server.daemon_threads = True
        self.server.hits = self.hits
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "DirectCounter":
        self.thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"


@pytest.fixture
def proxy():
    with LocalProxy() as server:
        yield server


@pytest.fixture
def direct_counter():
    with DirectCounter() as counter:
        yield counter


def _endpoints(proxy: LocalProxy, monkeypatch, names=("one", "two", "three")):
    endpoints = tuple(
        egress.Endpoint(f"{proxy.url}/{name}") for name in names
    )
    monkeypatch.setattr(egress, "ENDPOINTS", endpoints)
    return endpoints


def _url(proxy: LocalProxy, name: str) -> str:
    return f"{proxy.url}/{name}"


# --- normalisation and the stored value --------------------------------------


class TestNormalisation:
    @pytest.mark.parametrize("value", ["us", "Us", " uS ", "DE"])
    def test_a_country_code_is_uppercased(self, value):
        assert egress.normalize_country(value) == value.strip().upper()

    @pytest.mark.parametrize(
        "value", ["", "USA", "U", "1A", "U1", "U S", None, 12, True]
    )
    def test_a_bad_country_code_is_refused(self, value):
        with pytest.raises(egress.ExpectationError):
            egress.normalize_country(value)

    @pytest.mark.parametrize("value", ["ß", "ﬁ", "ſſ"])
    def test_a_non_ascii_letter_is_refused_before_the_case_fold(self, value):
        """``"ß".upper()`` is ``"SS"`` and ``"ﬁ".upper()`` is ``"FI"``.

        The two letters are checked before folding, so a Unicode look-alike
        cannot name a country it was never typed as.
        """
        with pytest.raises(egress.ExpectationError):
            egress.normalize_country(value)

    def test_only_codes_iso_assigns_to_a_country_are_accepted(self):
        """``ZZ`` is user-assigned, so no service could ever confirm it."""
        assert len(egress.ISO_COUNTRY_CODES) == 249
        for code in ("ZZ", "XK", "AA", "EU", "UK", "QZ"):
            with pytest.raises(egress.ExpectationError):
                egress.normalize_country(code)

    @pytest.mark.parametrize(
        "value, canonical",
        [
            ("1.2.3.4", "1.2.3.4"),
            (" 2001:0db8:0000:0000:0000:0000:0000:0001 ", "2001:db8::1"),
            ("::FFFF:1.2.3.4", "::ffff:1.2.3.4"),
            ("::ffff:102:304", "::ffff:1.2.3.4"),
        ],
    )
    def test_an_ip_is_stored_canonically(self, value, canonical):
        assert egress.normalize_ip(value) == canonical

    @pytest.mark.parametrize(
        "value", ["", "1.2.3", "999.1.1.1", "host", None, 1.2]
    )
    def test_a_bad_ip_is_refused(self, value):
        with pytest.raises(egress.ExpectationError):
            egress.normalize_ip(value)

    @pytest.mark.parametrize(
        "value",
        ["fe80::1%eth0", "fe80::1%", "::1%1", "fe80::1%\x1b[31mred"],
    )
    def test_an_ip_with_a_zone_is_refused(self, value):
        """``ipaddress`` keeps a zone's text, and only the address is echoed."""
        with pytest.raises(egress.ExpectationError):
            egress.normalize_ip(value)

    def test_the_message_never_repeats_the_value(self):
        with pytest.raises(egress.ExpectationError) as exc:
            egress.normalize_country("TOPSECRET")
        assert "TOPSECRET" not in str(exc.value)


class TestReadRecord:
    def test_no_keys_means_no_rule(self):
        assert egress.read({"email": "a@b"}) is None
        assert egress.read(None) is None

    def test_one_key_alone_is_a_rule(self):
        country = egress.read({egress.COUNTRY_FIELD: "us"})
        assert country is not None and country.country == "US" and country.ip is None
        ip = egress.read({egress.IP_FIELD: "2001:0db8::1"})
        assert ip is not None and ip.ip == "2001:db8::1" and ip.country is None

    @pytest.mark.parametrize(
        "record",
        [
            {egress.COUNTRY_FIELD: None},
            {egress.COUNTRY_FIELD: ""},
            {egress.COUNTRY_FIELD: 1},
            {egress.IP_FIELD: None},
            {egress.IP_FIELD: "not-an-ip"},
            {egress.COUNTRY_FIELD: "US", egress.IP_FIELD: []},
            {egress.COUNTRY_FIELD: "ß"},
        ],
    )
    def test_damage_reads_as_an_error_not_as_no_rule(self, record):
        expected = egress.read(record)
        assert expected is not None
        assert expected.error
        assert expected.required

    def test_describe_and_json_fields(self):
        record = {egress.COUNTRY_FIELD: "de", egress.IP_FIELD: "1.2.3.4"}
        assert egress.describe(record) == "expects country DE, IP 1.2.3.4"
        assert egress.json_fields(record) == {
            "proxyExpectedCountry": "DE",
            "proxyExpectedIp": "1.2.3.4",
        }

    def test_json_fields_of_a_damaged_rule_are_one_invalid_marker(self):
        fields = egress.json_fields({egress.COUNTRY_FIELD: None})
        assert set(fields) == {"proxyExpected"}
        assert fields["proxyExpected"].startswith("invalid (")
        assert egress.describe({egress.COUNTRY_FIELD: None}).startswith("invalid (")


# --- the check ---------------------------------------------------------------


class TestCheck:
    def test_no_rule_sends_nothing(self, proxy, monkeypatch):
        _endpoints(proxy, monkeypatch)
        egress.check(account_proxy.parse(proxy.url), None)
        assert proxy.requests == []

    def test_the_first_matching_answer_wins(self, proxy, monkeypatch):
        proxy.answer(_url(proxy, "one"), {"ip": "1.2.3.4", "country": "US"})
        _endpoints(proxy, monkeypatch)
        route = account_proxy.parse(proxy.url)

        egress.check(route, egress.read({egress.COUNTRY_FIELD: "us",
                                        egress.IP_FIELD: "1.2.3.4"}))

        assert proxy.requests == [_url(proxy, "one")]

    def test_each_failure_moves_to_the_next_service(self, proxy, monkeypatch):
        proxy.answer(_url(proxy, "one"), status=503)
        proxy.answer(_url(proxy, "two"), b"not json")
        proxy.answer(_url(proxy, "three"), {"ip": "1.2.3.4", "country": "US"})
        _endpoints(proxy, monkeypatch)

        egress.check(
            account_proxy.parse(proxy.url),
            egress.read({egress.IP_FIELD: "1.2.3.4"}),
        )

        assert proxy.requests == [
            _url(proxy, "one"), _url(proxy, "two"), _url(proxy, "three"),
        ]

    def test_a_missing_field_moves_on_but_a_mismatch_stops(self, proxy, monkeypatch):
        proxy.answer(_url(proxy, "one"), {"country": "US"})  # no IP
        proxy.answer(_url(proxy, "two"), {"ip": "5.6.7.8"})
        proxy.answer(_url(proxy, "three"), {"ip": "1.2.3.4"})
        _endpoints(proxy, monkeypatch)

        with pytest.raises(EgressCheckError) as exc:
            egress.check(
                account_proxy.parse(proxy.url),
                egress.read({egress.IP_FIELD: "1.2.3.4"}),
            )

        assert "5.6.7.8" in str(exc.value) and "1.2.3.4" in str(exc.value)
        assert proxy.requests == [_url(proxy, "one"), _url(proxy, "two")]

    def test_a_country_mismatch_is_reported_with_both_values(self, proxy, monkeypatch):
        proxy.answer(_url(proxy, "one"), {"ip": "1.2.3.4", "country": "DE"})
        _endpoints(proxy, monkeypatch)

        with pytest.raises(EgressCheckError) as exc:
            egress.check(
                account_proxy.parse(proxy.url),
                egress.read({egress.COUNTRY_FIELD: "US"}),
            )
        assert "DE" in str(exc.value) and "US" in str(exc.value)
        assert proxy.requests == [_url(proxy, "one")]

    def test_a_country_that_is_not_ascii_is_a_missing_field(
        self, proxy, monkeypatch
    ):
        """``"ß"`` folds to ``"SS"``, which is not this service's country."""
        proxy.answer(_url(proxy, "one"), {"country": "ß"})
        proxy.answer(_url(proxy, "two"), {"country": "US"})
        _endpoints(proxy, monkeypatch)

        egress.check(
            account_proxy.parse(proxy.url),
            egress.read({egress.COUNTRY_FIELD: "US"}),
        )

        assert proxy.requests == [_url(proxy, "one"), _url(proxy, "two")]

    def test_every_service_failing_is_a_refusal_with_the_reasons(
        self, proxy, monkeypatch
    ):
        proxy.answer(_url(proxy, "one"), status=500)
        proxy.answer(_url(proxy, "two"), b"[]")
        proxy.answer(_url(proxy, "three"), {})
        _endpoints(proxy, monkeypatch)

        with pytest.raises(EgressCheckError, match="no GeoIP endpoint"):
            egress.check(
                account_proxy.parse(proxy.url),
                egress.read({egress.COUNTRY_FIELD: "US"}),
            )
        assert len(proxy.requests) == 3

    def test_a_redirect_moves_on_to_the_next_service(
        self, proxy, direct_counter, monkeypatch
    ):
        """A 3xx over an HTTPS tunnel is the SERVICE's answer, not the proxy's.

        The service moved or is refusing automated clients; the next service
        may still answer, so one changed public address does not block every
        launch. The redirect itself is still never followed.
        """
        elsewhere = "http://127.0.0.1:9/redirected"
        proxy.answer(
            _url(proxy, "one"), status=302, headers={"Location": elsewhere}
        )
        proxy.answer(_url(proxy, "two"), {"ip": "1.2.3.4", "country": "US"})
        _endpoints(proxy, monkeypatch)

        egress.check(
            account_proxy.parse(proxy.url),
            egress.read({egress.COUNTRY_FIELD: "US"}),
        )

        assert proxy.requests == [_url(proxy, "one"), _url(proxy, "two")]
        assert direct_counter.hits == []

    def test_every_service_redirecting_is_a_refusal(
        self, proxy, direct_counter, monkeypatch
    ):
        for name in ("one", "two", "three"):
            proxy.answer(_url(proxy, name), status=302, headers={"Location": "/"})
        _endpoints(proxy, monkeypatch)

        with pytest.raises(EgressCheckError) as exc:
            egress.check(
                account_proxy.parse(proxy.url),
                egress.read({egress.COUNTRY_FIELD: "US"}),
            )

        assert "redirect" in str(exc.value)
        assert len(proxy.requests) == 3
        assert direct_counter.hits == []

    def test_a_user_assigned_country_in_an_answer_counts_as_missing(
        self, proxy, monkeypatch
    ):
        """``ZZ`` names no country, so this answer cannot confirm the rule."""
        proxy.answer(_url(proxy, "one"), {"ip": "1.2.3.4", "country": "ZZ"})
        proxy.answer(_url(proxy, "two"), {"ip": "1.2.3.4", "country": "US"})
        _endpoints(proxy, monkeypatch)

        egress.check(
            account_proxy.parse(proxy.url),
            egress.read({egress.COUNTRY_FIELD: "US"}),
        )

        assert proxy.requests == [_url(proxy, "one"), _url(proxy, "two")]

    def test_an_address_with_a_zone_in_an_answer_counts_as_missing(
        self, proxy, monkeypatch
    ):
        """A zone's text is never repeated, and this answer cannot confirm."""
        proxy.answer(
            _url(proxy, "one"), {"ip": "fe80::1%\x1b[31mred", "country": "US"}
        )
        proxy.answer(_url(proxy, "two"), {"ip": "1.2.3.4", "country": "US"})
        _endpoints(proxy, monkeypatch)

        egress.check(
            account_proxy.parse(proxy.url),
            egress.read({egress.IP_FIELD: "1.2.3.4"}),
        )

        assert proxy.requests == [_url(proxy, "one"), _url(proxy, "two")]

    def test_a_deeply_nested_answer_moves_on(self, proxy, monkeypatch):
        """A body no parser can walk is this service's answer, not the route's."""
        proxy.answer(_url(proxy, "one"), b"[" * 5000 + b"]" * 5000)
        proxy.answer(_url(proxy, "two"), {"ip": "1.2.3.4", "country": "US"})
        _endpoints(proxy, monkeypatch)

        egress.check(
            account_proxy.parse(proxy.url),
            egress.read({egress.COUNTRY_FIELD: "US"}),
        )

        assert proxy.requests == [_url(proxy, "one"), _url(proxy, "two")]

    def test_the_shells_proxy_variables_are_not_consulted(
        self, proxy, direct_counter, monkeypatch
    ):
        proxy.answer(_url(proxy, "one"), {"ip": "1.2.3.4", "country": "US"})
        _endpoints(proxy, monkeypatch, names=("one",))
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy"):
            monkeypatch.setenv(name, direct_counter.url)
        monkeypatch.setenv("NO_PROXY", "*")
        monkeypatch.setenv("no_proxy", "*")

        egress.check(
            account_proxy.parse(proxy.url),
            egress.read({egress.COUNTRY_FIELD: "US"}),
        )

        assert proxy.requests == [_url(proxy, "one")]
        assert direct_counter.hits == []

    def test_a_refused_proxy_reports_no_password_and_asks_once(
        self, proxy, monkeypatch
    ):
        proxy.answer(_url(proxy, "one"), status=407)
        _endpoints(proxy, monkeypatch)
        route = account_proxy.parse(
            proxy.url.replace("http://", "http://user:secret@")
        )

        with pytest.raises(EgressCheckError) as exc:
            egress.check(route, egress.read({egress.COUNTRY_FIELD: "US"}))

        assert "secret" not in str(exc.value)
        assert "407" in str(exc.value)
        # The same failure would repeat on every service, so it stops here.
        assert proxy.requests == [_url(proxy, "one")]

    def test_an_unreachable_proxy_lists_the_failures_without_credentials(
        self, monkeypatch
    ):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        try:
            port = sock.getsockname()[1]
            route = account_proxy.parse(f"http://user:secret@127.0.0.1:{port}")
            endpoints = tuple(
                egress.Endpoint(f"http://127.0.0.1:{port}/{name}")
                for name in ("one", "two", "three")
            )
            monkeypatch.setattr(egress, "ENDPOINTS", endpoints)

            with pytest.raises(EgressCheckError) as exc:
                egress.check(route, egress.read({egress.IP_FIELD: "1.2.3.4"}))
            assert "no GeoIP endpoint" in str(exc.value)
            assert "secret" not in str(exc.value)
        finally:
            sock.close()

    def test_a_rule_without_a_proxy_never_checks_directly(self, direct_counter):
        with pytest.raises(EgressCheckError, match="no proxy"):
            egress.check(None, egress.read({egress.COUNTRY_FIELD: "US"}))
        assert direct_counter.hits == []

    def test_a_damaged_rule_is_refused_without_a_request(self, proxy, monkeypatch):
        _endpoints(proxy, monkeypatch)
        with pytest.raises(EgressCheckError, match="unusable"):
            egress.check(
                account_proxy.parse(proxy.url),
                egress.read({egress.COUNTRY_FIELD: None}),
            )
        assert proxy.requests == []


# --- the setting: CLI and lifecycle ------------------------------------------


def _switcher(with_policy: bool = True) -> ClaudeAccountSwitcher:
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._init_sequence_file()
    data = switcher._get_sequence_data()
    data["accounts"] = {
        "1": {
            "email": "one@example.com", "uuid": "u1",
            "organizationUuid": "", "organizationName": "",
            "added": "2024-01-01T00:00:00Z",
        },
        "2": {
            "email": "two@example.com", "uuid": "u2",
            "organizationUuid": "", "organizationName": "",
            "added": "2024-01-02T00:00:00Z",
        },
    }
    data["sequence"] = [1, 2]
    data["activeAccountNumber"] = 1
    switcher._write_json(switcher.sequence_file, data)
    return switcher


def _records(switcher: ClaudeAccountSwitcher) -> dict:
    return switcher._get_sequence_data()["accounts"]


def _offline_usage(switcher: ClaudeAccountSwitcher, monkeypatch) -> None:
    """Serve an empty stored reading per account, so no fetch leaves."""
    from claude_swap.usage_store import UsageEntry

    monkeypatch.setattr(
        switcher,
        "_collect_usage_entries",
        lambda infos, fetch=None: {
            str(row[0]): UsageEntry() for row in infos
        },
    )


class TestProxyCommandExpectations:
    def test_setting_expectations_needs_the_proxy_first(self, temp_home, capsys):
        switcher = _switcher()
        before = switcher.sequence_file.read_bytes()
        with patch("os.geteuid", return_value=1000, create=True):
            with pytest.raises(SystemExit) as exc:
                cli._proxy_command(["1", "--expect-country", "us"])
        assert exc.value.code == 1
        assert "no usable proxy" in capsys.readouterr().err
        assert switcher.sequence_file.read_bytes() == before

    def test_a_url_and_an_expectation_can_arrive_together(self, temp_home, capsys):
        _switcher()
        with patch("os.geteuid", return_value=1000, create=True):
            cli._proxy_command([
                "1", "http://127.0.0.1:3128",
                "--expect-country", "de", "--expect-ip", "2001:0db8::1",
            ])
        record = _records(ClaudeAccountSwitcher())["1"]
        assert record["proxy"] == "http://127.0.0.1:3128"
        assert record[egress.COUNTRY_FIELD] == "DE"
        assert record[egress.IP_FIELD] == "2001:db8::1"
        out = capsys.readouterr().out
        assert "country DE" in out and "2001:db8::1" in out

    def test_expectations_can_change_without_repeating_the_url(
        self, temp_home, capsys
    ):
        switcher = _switcher()
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US"
        )
        with patch("os.geteuid", return_value=1000, create=True):
            cli._proxy_command(["1", "--expect-ip", "1.2.3.4"])
        record = _records(ClaudeAccountSwitcher())["1"]
        assert record[egress.IP_FIELD] == "1.2.3.4"
        # The part that was not named keeps its value.
        assert record[egress.COUNTRY_FIELD] == "US"
        assert record["proxy"] == "http://127.0.0.1:3128"
        assert "1.2.3.4" in capsys.readouterr().out

    def test_unset_expect_keeps_the_proxy(self, temp_home, capsys):
        switcher = _switcher()
        switcher.set_account_proxy("1", "http://127.0.0.1:3128")
        switcher.update_account_proxy("1", expect_country="US")
        with patch("os.geteuid", return_value=1000, create=True):
            cli._proxy_command(["1", "--unset-expect"])
        record = _records(ClaudeAccountSwitcher())["1"]
        assert record["proxy"] == "http://127.0.0.1:3128"
        assert egress.COUNTRY_FIELD not in record
        assert "Cleared" in capsys.readouterr().out

    def test_unset_clears_both(self, temp_home):
        switcher = _switcher()
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US"
        )
        with patch("os.geteuid", return_value=1000, create=True):
            cli._proxy_command(["1", "--unset"])
        record = _records(ClaudeAccountSwitcher())["1"]
        assert "proxy" not in record and egress.COUNTRY_FIELD not in record

    @pytest.mark.parametrize(
        "args",
        [
            ["1", "http://127.0.0.1:3128", "--expect-country", "USA"],
            ["1", "http://127.0.0.1:3128", "--expect-country", "ZZ"],
            ["1", "http://127.0.0.1:3128", "--expect-ip", "999.1.1.1"],
            ["1", "http://127.0.0.1:3128", "--expect-ip", "fe80::1%eth0"],
        ],
    )
    def test_a_bad_expectation_writes_nothing(self, temp_home, capsys, args):
        switcher = _switcher()
        before = switcher.sequence_file.read_bytes()
        with patch("os.geteuid", return_value=1000, create=True):
            with pytest.raises(SystemExit) as exc:
                cli._proxy_command(args)
        assert exc.value.code == 1
        assert "Error" in capsys.readouterr().err
        assert switcher.sequence_file.read_bytes() == before

    @pytest.mark.parametrize(
        "args",
        [
            ["--expect-country", "US"],
            ["1", "--unset", "--expect-country", "US"],
            ["1", "--unset-expect", "--expect-ip", "1.2.3.4"],
            ["1", "http://127.0.0.1:3128", "--unset-expect"],
            ["1"],
        ],
    )
    def test_contradictory_arguments_are_usage_errors(self, temp_home, args):
        _switcher()
        with patch("os.geteuid", return_value=1000, create=True):
            with pytest.raises(SystemExit) as exc:
                cli._proxy_command(args)
        assert exc.value.code == 2

    def test_the_listing_shows_the_rule_and_still_masks_the_password(
        self, temp_home, capsys
    ):
        switcher = _switcher()
        switcher.update_account_proxy(
            "2", "http://user:secret@127.0.0.1:3128",
            expect_country="us", expect_ip="1.2.3.4",
        )
        with patch("os.geteuid", return_value=1000, create=True):
            cli._proxy_command([])
        out = capsys.readouterr().out
        assert "country US" in out and "1.2.3.4" in out
        assert "secret" not in out


class TestStorageLifecycle:
    def test_swap_and_move_carry_the_rule(self, temp_home):
        switcher = _switcher()
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US", expect_ip="1.2.3.4"
        )
        switcher.swap_accounts("1", "2")
        record = _records(switcher)["2"]
        assert record[egress.COUNTRY_FIELD] == "US"
        assert record[egress.IP_FIELD] == "1.2.3.4"
        assert egress.COUNTRY_FIELD not in _records(switcher)["1"]

        switcher.move_account("2", "3")
        assert _records(switcher)["3"][egress.IP_FIELD] == "1.2.3.4"

    def test_remove_takes_the_rule_with_the_account(self, temp_home):
        switcher = _switcher()
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US"
        )
        switcher.remove_account("1", assume_yes=True)
        assert "proxy_expected" not in json.dumps(switcher._get_sequence_data())

    def test_a_damaged_rule_survives_a_move_by_key_presence(self, temp_home):
        switcher = _switcher()
        data = switcher._get_sequence_data()
        data["accounts"]["1"][egress.COUNTRY_FIELD] = None
        switcher._write_json(switcher.sequence_file, data)
        switcher.swap_accounts("1", "2")
        record = _records(switcher)["2"]
        assert egress.COUNTRY_FIELD in record and record[egress.COUNTRY_FIELD] is None
        assert egress.describe(record).startswith("invalid (")

    def test_export_omits_the_rule_and_import_keeps_the_local_one(
        self, temp_home, tmp_path
    ):
        from claude_swap import transfer

        switcher = _switcher()
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US", expect_ip="1.2.3.4"
        )
        switcher._write_account_credentials("1", "one@example.com", json.dumps({
            "claudeAiOauth": {"accessToken": "sk-1", "refreshToken": "rt-1"},
        }))
        switcher._write_account_config(
            "1", "one@example.com",
            json.dumps({"oauthAccount": {"emailAddress": "one@example.com"}}),
        )
        destination = tmp_path / "export.json"
        transfer.export_accounts(switcher, str(destination))
        exported = json.loads(destination.read_text())
        assert "proxy_expected" not in json.dumps(exported)

        transfer.import_accounts(switcher, str(destination), force=True)
        record = _records(switcher)["1"]
        assert record[egress.COUNTRY_FIELD] == "US"
        assert record[egress.IP_FIELD] == "1.2.3.4"

    def test_a_readd_into_the_same_slot_keeps_the_rule(
        self, temp_home, mock_claude_config
    ):
        switcher = _switcher()
        data = switcher._get_sequence_data()
        data["accounts"]["1"]["email"] = "test@example.com"
        switcher._write_json(switcher.sequence_file, data)
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US"
        )
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "sk-live", "refreshToken": "rt-live",
            "expiresAt": 9999999999000,
        }})
        with patch.object(
            switcher, "_read_capture_credentials", return_value=creds
        ):
            switcher.add_account(slot=1, assume_yes=True)
        record = _records(switcher)["1"]
        assert record[egress.COUNTRY_FIELD] == "US"
        assert record["proxy"] == "http://127.0.0.1:3128"


class TestJsonFields:
    def test_list_payload_carries_the_rule_and_keeps_old_fields(
        self, temp_home, monkeypatch
    ):
        switcher = _switcher()
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US", expect_ip="1.2.3.4"
        )
        _offline_usage(switcher, monkeypatch)
        payload = switcher.list_accounts(json_output=True)
        row = next(a for a in payload["accounts"] if a["number"] == 1)
        assert row["proxyExpectedCountry"] == "US"
        assert row["proxyExpectedIp"] == "1.2.3.4"
        assert row["proxy"] == "http://127.0.0.1:3128"

        untouched = next(a for a in payload["accounts"] if a["number"] == 2)
        assert "proxyExpectedCountry" not in untouched
        assert "proxyExpectedIp" not in untouched
        assert "proxyExpected" not in untouched

    def test_status_payload_carries_the_rule(
        self, temp_home, mock_claude_config, monkeypatch
    ):
        switcher = _switcher()
        data = switcher._get_sequence_data()
        data["accounts"]["1"]["email"] = "test@example.com"
        switcher._write_json(switcher.sequence_file, data)
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="us"
        )
        _offline_usage(switcher, monkeypatch)
        payload = switcher._build_status_payload()
        assert payload["active"]["proxyExpectedCountry"] == "US"

    def test_list_and_status_human_views_show_the_rule(
        self, temp_home, mock_claude_config, capsys, monkeypatch
    ):
        monkeypatch.setattr(
            "claude_swap.switcher.get_running_instances", lambda: ([], [])
        )
        switcher = _switcher()
        data = switcher._get_sequence_data()
        data["accounts"]["1"]["email"] = "test@example.com"
        switcher._write_json(switcher.sequence_file, data)
        switcher.update_account_proxy(
            "1", "http://127.0.0.1:3128", expect_country="US"
        )
        _offline_usage(switcher, monkeypatch)
        switcher.list_accounts()
        listed = capsys.readouterr().out
        switcher.status()
        stated = capsys.readouterr().out

        assert "egress" in listed and "country US" in listed
        assert "Egress:" in stated and "country US" in stated

    def test_a_damaged_rule_is_visible_in_json(self, temp_home, monkeypatch):
        switcher = _switcher()
        data = switcher._get_sequence_data()
        data["accounts"]["1"][egress.IP_FIELD] = "nonsense"
        switcher._write_json(switcher.sequence_file, data)
        _offline_usage(switcher, monkeypatch)
        payload = switcher.list_accounts(json_output=True)
        row = next(a for a in payload["accounts"] if a["number"] == 1)
        assert row["proxyExpected"].startswith("invalid (")

    def test_a_user_assigned_country_in_a_stored_rule_is_visible_damage(
        self, temp_home, monkeypatch
    ):
        """``ZZ`` names no country, so a rule for it is damage, never "no rule"."""
        switcher = _switcher()
        switcher.set_account_proxy("1", "http://127.0.0.1:3128")
        data = switcher._get_sequence_data()
        data["accounts"]["1"][egress.COUNTRY_FIELD] = "ZZ"
        switcher._write_json(switcher.sequence_file, data)
        _offline_usage(switcher, monkeypatch)
        payload = switcher.list_accounts(json_output=True)
        row = next(a for a in payload["accounts"] if a["number"] == 1)
        assert row["proxyExpected"].startswith("invalid (")


# --- what a failed request is called -----------------------------------------


class TestFailureDiagnostics:
    """Each refusal names its cause, and no more than its cause.

    A proxy's status phrase and a certificate error's text are the peer's
    words — a phrase can name a credential — so only the code travels.
    """

    def _expect(self, route, endpoint, monkeypatch, timeout=5.0):
        monkeypatch.setattr(
            egress, "ENDPOINTS", (egress.Endpoint(endpoint),)
        )
        with pytest.raises(EgressCheckError) as err:
            egress.check(
                route,
                egress.read({egress.IP_FIELD: "1.2.3.4"}),
                timeout=timeout,
            )
        return str(err.value)

    def test_a_refused_connect_keeps_only_its_code(self, monkeypatch):
        with proxy_servers.HttpProxy(refuse=403) as proxy:
            route = account_proxy.parse(proxy.url)
            dead = proxy_servers.DeadProxy()
            message = self._expect(
                route, f"https://127.0.0.1:{dead.port}/json", monkeypatch
            )
            assert proxy.url not in message

        assert "CONNECT HTTP 403" in message
        assert "Refused" not in message  # the proxy's own phrase

    def test_a_tls_failure_is_a_tls_error(self, monkeypatch):
        with proxy_servers.HttpProxy() as proxy:
            with proxy_servers.Origin(tls=False) as origin:
                route = account_proxy.parse(proxy.url)
                message = self._expect(
                    route, f"https://127.0.0.1:{origin.port}/json", monkeypatch
                )

        assert "TLS error" in message

    def test_an_unreachable_proxy_is_a_network_error(self, monkeypatch):
        dead = proxy_servers.DeadProxy()
        route = account_proxy.parse(f"http://127.0.0.1:{dead.port}")
        with proxy_servers.Origin() as origin:
            message = self._expect(
                route, f"{origin.url}/json", monkeypatch
            )

        assert "network error" in message
        assert origin.hits == 0

    @pytest.mark.parametrize("scheme", ["https", "socks5h"])
    @pytest.mark.parametrize("expected", ["network error", "timeout"])
    def test_bridged_proxy_transport_failure(self, scheme, expected, monkeypatch):
        with socket.socket() as proxy:
            proxy.bind(("127.0.0.1", 0))
            if expected == "timeout":
                # TCP connects, but nothing answers the TLS or SOCKS greeting.
                proxy.listen()
            port = proxy.getsockname()[1]
            route = account_proxy.parse(f"{scheme}://user:secret@127.0.0.1:{port}")
            timeout = 0.3 if expected == "timeout" else 5.0
            message = self._expect(
                route, "https://127.0.0.1:443/json", monkeypatch, timeout=timeout
            )

        assert expected in message
        assert "ConnectionRefusedError" not in message
        assert "secret" not in message

    def test_an_untrusted_https_proxy_certificate_is_a_tls_error(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(
            tls=True, context=proxy_servers.untrusted_context(),
        ) as proxy:
            route = account_proxy.parse(f"https://user:secret@127.0.0.1:{proxy.port}")
            with proxy_servers.Origin(tls=True) as origin:
                message = self._expect(route, f"{origin.url}/json", monkeypatch)
                assert origin.hits == 0

        assert "TLS error" in message
        assert "secret" not in message

    def test_a_service_redirect_inside_a_tls_proxy_tunnel(self, monkeypatch):
        proxy_servers.trust_fixture_ca(monkeypatch)
        with proxy_servers.HttpProxy(tls=True) as proxy:
            route = account_proxy.parse(f"https://127.0.0.1:{proxy.port}")
            with proxy_servers.Origin(tls=True, status=302) as origin:
                message = self._expect(route, f"{origin.url}/json", monkeypatch)

        assert message.endswith(": redirect")

    def test_a_service_that_never_answers_is_a_timeout(self, monkeypatch):
        """The proxy opens the tunnel and then says nothing at all."""
        with proxy_servers.SilentProxy() as proxy:
            route = account_proxy.parse(proxy.url)
            message = self._expect(
                route, "https://127.0.0.1:443/json", monkeypatch, timeout=0.3
            )

        assert "timeout" in message

    @pytest.mark.parametrize(
        ("reason", "expected"),
        [
            (TimeoutError(), "timeout"),
            (ConnectionRefusedError(), "network error"),
            (OSError("Tunnel connection failed: 407 Nope"), "CONNECT HTTP 407"),
            (ssl.SSLError("handshake"), "TLS error"),
            (
                ssl.SSLCertVerificationError("untrusted: proxy-password"),
                "TLS error",
            ),
        ],
    )
    def test_the_reason_mapping(self, reason, expected):
        assert egress._transport_failure(reason) == expected

    def test_a_tls_reason_never_repeats_its_text(self):
        reason = ssl.SSLCertVerificationError("hostname 'secret.example'")
        assert "secret.example" not in egress._transport_failure(reason)

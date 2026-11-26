"""`cswap add --login` and `--expect-country` / `--expect-ip` on `add`.

The isolated login is Claude Code's own ``claude auth login`` in a throwaway
``CLAUDE_CONFIG_DIR``. These tests drive that child through a fake
``spawn.run``: no browser, no network, no real profile. The proxy and GeoIP
checks are seams too, so a refused check is observed before the child starts.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import account_proxy, cli, egress, login
from claude_swap.exceptions import (
    ConfigError,
    EgressCheckError,
    LoginError,
    SessionError,
    ValidationError,
)
from claude_swap.models import Platform
from claude_swap.session import AUTH_OVERRIDE_ENV_VARS
from claude_swap.settings import DEFAULT_NO_PROXY, RunSettings
from claude_swap.switcher import ClaudeAccountSwitcher

NEW_TOKEN = "sk-ant-oat01-NEW-ACCOUNT-TEST-TOKEN"
NEW_REFRESH = "rt-new-account-test-refresh"
NEW_CREDS = json.dumps({
    "claudeAiOauth": {
        "accessToken": NEW_TOKEN,
        "refreshToken": NEW_REFRESH,
        "expiresAt": 99999999999000,
    }
})
NEW_CONFIG = json.dumps({
    "oauthAccount": {
        "emailAddress": "new@example.com",
        "accountUuid": "uuid-new",
        "organizationUuid": "org-new",
        "organizationName": "New Org",
    }
})
LIVE_CREDS = json.dumps({"claudeAiOauth": {"accessToken": "live-token"}})


def _switcher():
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._init_sequence_file()
    return switcher


def _seed(switcher, accounts, *, active=1):
    data = {
        "activeAccountNumber": active,
        "lastUpdated": "2024-01-01T00:00:00Z",
        "sequence": sorted(int(num) for num in accounts),
        "accounts": accounts,
    }
    switcher._write_json(switcher.sequence_file, data)
    return data


def _account(email, *, alias=None, org="", org_name="", **extra):
    record = {
        "email": email,
        "uuid": f"uuid-{email}",
        "organizationUuid": org,
        "organizationName": org_name,
        "added": "2024-01-01T00:00:00Z",
    }
    if alias is not None:
        record["alias"] = alias
    record.update(extra)
    return record


def _login_mock(
    record,
    *,
    creds=NEW_CREDS,
    config=NEW_CONFIG,
    returncode=0,
    error=None,
    write_creds=True,
    write_config=True,
):
    def fake(argv, **kwargs):
        env = kwargs["env"]
        config_dir = Path(env["CLAUDE_CONFIG_DIR"])
        record["argv"] = list(argv)
        record["env"] = env
        record["dir"] = config_dir
        if os.name != "nt":
            record["mode"] = stat.S_IMODE(os.stat(config_dir).st_mode)
        if error is not None:
            raise error
        if returncode == 0 and write_creds:
            (config_dir / ".credentials.json").write_text(creds, encoding="utf-8")
        if returncode == 0 and write_config:
            (config_dir / ".claude.json").write_text(config, encoding="utf-8")
        return subprocess.CompletedProcess(argv, returncode)
    return fake


@pytest.fixture
def claude_bin(monkeypatch):
    monkeypatch.setattr("claude_swap.session.find_claude", lambda: "/fake/bin/claude")
    return "/fake/bin/claude"


@pytest.fixture
def checks_pass(monkeypatch):
    seen = {"probe": [], "egress": []}
    monkeypatch.setattr(
        account_proxy,
        "probe",
        lambda route, timeout=account_proxy.PROBE_TIMEOUT_S: seen["probe"].append(route),
    )
    monkeypatch.setattr(
        egress,
        "check",
        lambda route, expectation, timeout=egress.TIMEOUT_S: seen["egress"].append(
            (route, expectation)
        ),
    )
    return seen


def _no_live_profile(temp_home: Path):
    creds = temp_home / ".claude" / ".credentials.json"
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text(LIVE_CREDS, encoding="utf-8")
    config = temp_home / ".claude.json"
    config.write_text(json.dumps({"oauthAccount": {
        "emailAddress": "live@example.com",
        "accountUuid": "uuid-live",
        "organizationUuid": "",
    }}), encoding="utf-8")
    return creds, config


class TestAddLogin:
    def test_imports_a_slot_and_leaves_the_live_login_alone(
        self, temp_home, claude_bin, checks_pass, monkeypatch, capsys,
    ):
        switcher = _switcher()
        live_creds, live_config = _no_live_profile(temp_home)
        before_creds = live_creds.read_bytes()
        before_config = live_config.read_bytes()
        _seed(switcher, {"1": _account("live@example.com")})

        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))

        switcher.add_account_via_login(
            proxy="http://user:secret@127.0.0.1:3128",
            expect_country="us",
            expect_ip="1.2.3.4",
            alias="New",
        )

        data = switcher._get_sequence_data()
        assert data["activeAccountNumber"] == 1
        assert data["accounts"]["1"]["email"] == "live@example.com"
        assert data["accounts"]["2"]["email"] == "new@example.com"
        assert data["accounts"]["2"]["organizationUuid"] == "org-new"
        assert data["accounts"]["2"]["alias"] == "new"
        assert data["accounts"]["2"]["proxy"] == (
            "http://user:secret@127.0.0.1:3128"
        )
        assert data["accounts"]["2"]["proxy_expected_country"] == "US"
        assert data["accounts"]["2"]["proxy_expected_ip"] == "1.2.3.4"
        assert live_creds.read_bytes() == before_creds
        assert live_config.read_bytes() == before_config
        assert not record["dir"].exists()
        if os.name != "nt":
            assert record["mode"] == 0o700
        captured = capsys.readouterr()
        assert "secret" not in captured.out + captured.err
        assert NEW_TOKEN not in captured.out + captured.err
        assert NEW_REFRESH not in captured.out + captured.err
        log_file = switcher.backup_dir / "claude-swap.log"
        if log_file.exists():
            log = log_file.read_text(encoding="utf-8")
            assert "secret" not in log
            assert NEW_TOKEN not in log
            assert NEW_REFRESH not in log

    def test_forwards_the_login_arguments_and_the_launch_environment(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        for name in AUTH_OVERRIDE_ENV_VARS:
            monkeypatch.setenv(name, "stale")
        monkeypatch.setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", "/tmp/other-store")
        monkeypatch.setenv("HTTPS_PROXY", "http://shell.invalid:1")
        monkeypatch.setenv("no_proxy", "*")

        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))

        switcher.add_account_via_login(
            slot=2,
            proxy="http://user:secret@127.0.0.1:3128",
            email="new@example.com",
        )

        assert record["argv"] == [
            "/fake/bin/claude", "auth", "login", "--claudeai",
            "--email", "new@example.com",
        ]
        env = record["env"]
        url = account_proxy.parse("http://user:secret@127.0.0.1:3128").text()
        for name in (
            "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
            "ALL_PROXY", "all_proxy",
        ):
            assert env[name] == url
        assert env["NO_PROXY"] == DEFAULT_NO_PROXY
        assert env["no_proxy"] == DEFAULT_NO_PROXY
        assert env["CLAUDE_CONFIG_DIR"] == str(record["dir"])
        assert env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
        for name in AUTH_OVERRIDE_ENV_VARS:
            assert name not in env
        assert "CLAUDE_SECURESTORAGE_CONFIG_DIR" not in env

    def test_run_settings_control_no_proxy_and_nonessential_traffic(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        monkeypatch.setattr(
            "claude_swap.login.load_run_settings",
            lambda backup_dir: RunSettings(
                no_proxy="only.example", disable_nonessential_traffic=False
            ),
        )
        monkeypatch.delenv("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", raising=False)

        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))
        switcher.add_account_via_login(proxy="http://127.0.0.1:3128")

        assert record["env"]["NO_PROXY"] == "only.example"
        assert record["env"]["no_proxy"] == "only.example"
        assert "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" not in record["env"]

    def test_a_dead_proxy_stops_the_login_before_claude(
        self, temp_home, claude_bin, monkeypatch, capsys,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        spawn_called = []

        def fake(*args, **kwargs):
            spawn_called.append(args)
            raise AssertionError("claude ran despite a dead proxy")

        monkeypatch.setattr("claude_swap.login.spawn.run", fake)

        def dead(route, timeout=account_proxy.PROBE_TIMEOUT_S):
            raise account_proxy.ProxyRouteError(
                account_proxy.PROXY_UNREACHABLE,
                "the proxy did not accept a connection",
            )

        monkeypatch.setattr(account_proxy, "probe", dead)

        with pytest.raises(SessionError, match="cannot be used"):
            switcher.add_account_via_login(
                slot=2, proxy="http://user:secret@127.0.0.1:3128"
            )

        assert spawn_called == []
        assert "2" not in switcher._get_sequence_data()["accounts"]
        captured = capsys.readouterr()
        assert "secret" not in captured.out + captured.err

    def test_a_wrong_exit_stops_the_login_before_claude(
        self, temp_home, claude_bin, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        spawn_called = []
        monkeypatch.setattr(
            "claude_swap.login.spawn.run",
            lambda *a, **k: spawn_called.append(a),
        )
        monkeypatch.setattr(
            account_proxy,
            "probe",
            lambda route, timeout=account_proxy.PROBE_TIMEOUT_S: None,
        )

        def wrong(route, expectation, timeout=egress.TIMEOUT_S):
            raise EgressCheckError("the exit country is DE, but US was expected")

        monkeypatch.setattr(egress, "check", wrong)

        with pytest.raises(EgressCheckError) as exc:
            switcher.add_account_via_login(
                slot=2,
                proxy="http://127.0.0.1:3128",
                expect_country="US",
            )

        assert "DE" in str(exc.value) and "US" in str(exc.value)
        assert spawn_called == []
        assert "2" not in switcher._get_sequence_data()["accounts"]

    def test_an_expectation_without_a_proxy_is_refused_before_any_lookup(
        self, temp_home, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})

        def forbidden():
            raise AssertionError("find_claude ran before the argument check")

        monkeypatch.setattr("claude_swap.session.find_claude", forbidden)

        with pytest.raises(ValidationError, match="require --proxy"):
            switcher.add_account_via_login(expect_country="US")

    @pytest.mark.parametrize(
        ("kwargs", "error"),
        [
            ({"slot": 0}, ConfigError),
            ({"alias": "-bad"}, ValidationError),
            ({"email": "not-an-email"}, ValidationError),
            ({"proxy": "https://127.0.0.1:3128"}, ValidationError),
            ({"proxy": "http://127.0.0.1:3128", "expect_country": "ZZ"}, ValidationError),
            ({"proxy": "http://127.0.0.1:3128", "expect_ip": "999.1.1.1"}, ValidationError),
        ],
        ids=["slot", "alias", "email", "proxy", "country", "ip"],
    )
    def test_invalid_arguments_are_refused_before_claude(
        self, temp_home, monkeypatch, kwargs, error,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})

        def forbidden():
            raise AssertionError("find_claude ran before the argument check")

        monkeypatch.setattr("claude_swap.session.find_claude", forbidden)

        with pytest.raises(error):
            switcher.add_account_via_login(**kwargs)

    def test_a_missing_claude_binary_is_reported_before_any_network(
        self, temp_home, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        monkeypatch.setattr("claude_swap.session.find_claude", lambda: None)

        def forbidden(*args, **kwargs):
            raise AssertionError("network check ran without a claude binary")

        monkeypatch.setattr(account_proxy, "probe", forbidden)

        with pytest.raises(SessionError, match="not found on PATH"):
            switcher.add_account_via_login(
                slot=2, proxy="http://127.0.0.1:3128"
            )
        assert "2" not in switcher._get_sequence_data()["accounts"]

    @pytest.mark.parametrize(
        "mode",
        ["nonzero", "interrupt", "no-credentials", "no-config"],
    )
    def test_a_failed_or_incomplete_login_adds_no_slot(
        self, temp_home, claude_bin, checks_pass, monkeypatch, capsys, mode,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        before = switcher.sequence_file.read_bytes()
        record = {}
        options = {
            "nonzero": {"returncode": 1},
            "interrupt": {"error": KeyboardInterrupt()},
            "no-credentials": {"write_creds": False},
            "no-config": {"write_config": False},
        }[mode]
        monkeypatch.setattr(
            "claude_swap.login.spawn.run", _login_mock(record, **options)
        )

        with pytest.raises((LoginError, KeyboardInterrupt)):
            switcher.add_account_via_login(slot=2)

        data = switcher._get_sequence_data()
        assert "2" not in data["accounts"]
        assert data["activeAccountNumber"] == 1
        assert switcher.sequence_file.read_bytes() == before
        assert not record["dir"].exists()
        captured = capsys.readouterr()
        assert NEW_TOKEN not in captured.out + captured.err

    def test_an_alias_conflict_is_refused_before_claude(
        self, temp_home, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account("other@example.com", alias="dev"),
        })
        spawn_called = []
        monkeypatch.setattr(
            "claude_swap.session.find_claude", lambda: "/fake/bin/claude"
        )
        monkeypatch.setattr(
            "claude_swap.login.spawn.run",
            lambda *a, **k: spawn_called.append(a),
        )

        with pytest.raises(ValidationError, match="already used"):
            switcher.add_account_via_login(alias="dev")

        assert spawn_called == []

    def test_the_overwrite_question_can_stop_the_import(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account("other@example.com"),
        })
        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))
        monkeypatch.setattr("builtins.input", lambda prompt: "n")

        switcher.add_account_via_login(slot=2)

        data = switcher._get_sequence_data()
        assert data["accounts"]["2"]["email"] == "other@example.com"
        assert "3" not in data["accounts"]
        assert data["activeAccountNumber"] == 1
        assert not record["dir"].exists()

    def test_an_accepted_overwrite_replaces_the_slot(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account("other@example.com"),
        })
        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))

        switcher.add_account_via_login(slot=2, assume_yes=True)

        data = switcher._get_sequence_data()
        assert data["accounts"]["2"]["email"] == "new@example.com"
        assert "1" in data["accounts"] and "3" not in data["accounts"]
        assert switcher._read_account_config("2", "other@example.com") == ""

    def test_a_refresh_keeps_the_carried_settings(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account(
                "new@example.com",
                alias="kept",
                org="org-new",
                org_name="New Org",
                proxy="http://127.0.0.1:3129",
                proxy_expected_country="DE",
                proxy_expected_ip="5.6.7.8",
            ),
        })
        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))

        switcher.add_account_via_login(slot=2)

        record_2 = switcher._get_sequence_data()["accounts"]["2"]
        assert record_2["alias"] == "kept"
        assert record_2["proxy"] == "http://127.0.0.1:3129"
        assert record_2["proxy_expected_country"] == "DE"
        assert record_2["proxy_expected_ip"] == "5.6.7.8"

    def test_explicit_settings_replace_the_carried_ones(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account(
                "new@example.com",
                alias="old",
                org="org-new",
                org_name="New Org",
                proxy="http://127.0.0.1:3129",
                proxy_expected_country="DE",
                proxy_expected_ip="5.6.7.8",
            ),
        })
        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))

        switcher.add_account_via_login(
            slot=2,
            alias="fresh",
            proxy="http://user:secret@127.0.0.1:3130",
            expect_country="us",
            expect_ip="9.9.9.9",
        )

        record_2 = switcher._get_sequence_data()["accounts"]["2"]
        assert record_2["alias"] == "fresh"
        assert record_2["proxy"] == "http://user:secret@127.0.0.1:3130"
        assert record_2["proxy_expected_country"] == "US"
        assert record_2["proxy_expected_ip"] == "9.9.9.9"


class TestIsolatedProfileCleanup:
    def test_the_directory_is_removed_on_success_and_on_error(self):
        captured = []
        with login.isolated_profile() as config_dir:
            captured.append(config_dir)
            (config_dir / ".credentials.json").write_text("{}", encoding="utf-8")
        assert not captured[0].exists()

        with pytest.raises(RuntimeError):
            with login.isolated_profile() as config_dir:
                captured.append(config_dir)
                raise RuntimeError("login interrupted")
        assert not captured[1].exists()

    def test_the_keychain_item_is_removed_too(
        self, block_real_keychain, monkeypatch,
    ):
        from claude_swap import session

        monkeypatch.setattr(
            Platform, "detect", classmethod(lambda cls: Platform.MACOS)
        )
        captured = {}
        with login.isolated_profile() as config_dir:
            captured["dir"] = config_dir
            service = session.keychain_service_name(str(config_dir))
            account = session._keychain_account_name()
            captured["service"] = service
            captured["account"] = account
            block_real_keychain.set_password(service, account, "secret")
            assert block_real_keychain.item_exists(service, account)

        assert not captured["dir"].exists()
        assert not block_real_keychain.item_exists(
            captured["service"], captured["account"]
        )

        interrupted = {}
        with pytest.raises(RuntimeError):
            with login.isolated_profile() as config_dir:
                service = session.keychain_service_name(str(config_dir))
                account = session._keychain_account_name()
                interrupted.update(dir=config_dir, service=service, account=account)
                block_real_keychain.set_password(service, account, "secret")
                raise RuntimeError("Ctrl+C")
        assert not interrupted["dir"].exists()
        assert not block_real_keychain.item_exists(
            interrupted["service"], interrupted["account"]
        )


class TestAddExpectations:
    def _live(self, temp_home):
        _no_live_profile(temp_home)

    def test_plain_add_stores_the_expectation_with_the_proxy(
        self, temp_home, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        self._live(temp_home)
        monkeypatch.setattr(
            "claude_swap.switcher.ClaudeAccountSwitcher._read_capture_credentials",
            lambda self: NEW_CREDS,
        )
        config_path = switcher._get_claude_config_path()
        config_path.write_text(json.dumps({"oauthAccount": {
            "emailAddress": "live@example.com",
            "accountUuid": "uuid-live",
            "organizationUuid": "",
            "organizationName": "",
        }}), encoding="utf-8")

        switcher.add_account(
            slot=2,
            proxy="http://user:secret@127.0.0.1:3128",
            expect_country="us",
            expect_ip="1.2.3.4",
            assume_yes=True,
        )

        record = switcher._get_sequence_data()["accounts"]["2"]
        assert record["proxy"] == "http://user:secret@127.0.0.1:3128"
        assert record["proxy_expected_country"] == "US"
        assert record["proxy_expected_ip"] == "1.2.3.4"

    def test_an_expectation_without_a_proxy_is_refused_before_any_write(
        self, temp_home, monkeypatch,
    ):
        switcher = _switcher()
        before = switcher.sequence_file.read_bytes()
        monkeypatch.setattr(
            "claude_swap.switcher.ClaudeAccountSwitcher._read_capture_credentials",
            lambda self: pytest.fail("credentials were read"),
        )

        with pytest.raises(ValidationError, match="require --proxy"):
            switcher.add_account(slot=1, expect_country="US")

        assert switcher.sequence_file.read_bytes() == before

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"slot": 0},
            {"proxy": "https://127.0.0.1:3128"},
            {"proxy": "http://127.0.0.1:3128", "expect_country": "ZZ"},
            {"proxy": "http://127.0.0.1:3128", "expect_ip": "999.1.1.1"},
        ],
        ids=["slot", "proxy", "country", "ip"],
    )
    def test_a_rejected_value_leaves_sequence_untouched(
        self, temp_home, monkeypatch, kwargs,
    ):
        switcher = _switcher()
        before = switcher.sequence_file.read_bytes()
        monkeypatch.setattr(
            "claude_swap.switcher.ClaudeAccountSwitcher._read_capture_credentials",
            lambda self: pytest.fail("credentials were read"),
        )

        with pytest.raises((ConfigError, ValidationError)):
            switcher.add_account(**kwargs)

        assert switcher.sequence_file.read_bytes() == before

    def test_an_explicit_expectation_replaces_the_stored_one(
        self, temp_home, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account(
                "live@example.com",
                proxy="http://127.0.0.1:3129",
                proxy_expected_country="DE",
                proxy_expected_ip="5.6.7.8",
            ),
        })
        monkeypatch.setattr(
            "claude_swap.switcher.ClaudeAccountSwitcher._read_capture_credentials",
            lambda self: NEW_CREDS,
        )
        config_path = switcher._get_claude_config_path()
        config_path.write_text(json.dumps({"oauthAccount": {
            "emailAddress": "live@example.com",
            "accountUuid": "uuid-live",
            "organizationUuid": "",
            "organizationName": "",
        }}), encoding="utf-8")

        switcher.add_account(
            slot=1,
            proxy="http://127.0.0.1:3130",
            expect_country="us",
            expect_ip="9.9.9.9",
            assume_yes=True,
        )

        record = switcher._get_sequence_data()["accounts"]["1"]
        assert record["proxy_expected_country"] == "US"
        assert record["proxy_expected_ip"] == "9.9.9.9"

    def test_a_concurrent_expectation_update_survives_a_rebuild(
        self, temp_home, monkeypatch,
    ):
        """ALX-1726: the under-lock carry covers the whole rule, not the proxy.

        A `cswap proxy --expect-*` writes its fields while this add is between
        its first snapshot and the lock that rebuilds the record. Copying only
        the proxy field would drop the rule the user just set.
        """
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com", proxy="http://127.0.0.1:3129"),
        })
        monkeypatch.setattr(
            "claude_swap.switcher.ClaudeAccountSwitcher._read_capture_credentials",
            lambda self: NEW_CREDS,
        )
        config_path = switcher._get_claude_config_path()
        config_path.write_text(json.dumps({"oauthAccount": {
            "emailAddress": "live@example.com",
            "accountUuid": "uuid-live",
            "organizationUuid": "",
            "organizationName": "",
        }}), encoding="utf-8")

        real_write = switcher._write_account_credentials

        def write_then_concurrent_proxy(num, email, creds):
            real_write(num, email, creds)
            data = switcher._get_sequence_data()
            data["accounts"]["1"]["proxy_expected_country"] = "DE"
            data["accounts"]["1"]["proxy_expected_ip"] = "5.6.7.8"
            switcher._write_json(switcher.sequence_file, data)

        monkeypatch.setattr(
            switcher, "_write_account_credentials", write_then_concurrent_proxy
        )

        switcher.add_account(slot=1, assume_yes=True)

        record = switcher._get_sequence_data()["accounts"]["1"]
        assert record["proxy"] == "http://127.0.0.1:3129"
        assert record["proxy_expected_country"] == "DE"
        assert record["proxy_expected_ip"] == "5.6.7.8"


class TestAddLoginCLI:
    def _main(self, argv, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["claude-swap", *argv])
        with patch("claude_swap.cli.ClaudeAccountSwitcher") as switcher_cls, \
             patch("os.geteuid", return_value=1000, create=True), \
             patch("claude_swap.update_check.check_for_update", return_value=None):
            cli.main()
        return switcher_cls

    def test_add_login_dispatches_to_the_isolated_login(
        self, temp_home, monkeypatch,
    ):
        switcher_cls = self._main(
            [
                "add", "--login",
                "--proxy", "http://user:secret@127.0.0.1:3128",
                "--expect-country", "us",
                "--expect-ip", "1.2.3.4",
                "--alias", "dev",
                "--slot", "3",
                "--email", "new@example.com",
            ],
            monkeypatch,
        )
        switcher_cls.return_value.add_account_via_login.assert_called_once_with(
            slot=3,
            alias="dev",
            proxy="http://user:secret@127.0.0.1:3128",
            expect_country="us",
            expect_ip="1.2.3.4",
            email="new@example.com",
        )
        switcher_cls.return_value.add_account.assert_not_called()

    def test_plain_add_forwards_the_expectation(
        self, temp_home, monkeypatch,
    ):
        switcher_cls = self._main(
            [
                "add",
                "--proxy", "http://127.0.0.1:3128",
                "--expect-country", "DE",
            ],
            monkeypatch,
        )
        switcher_cls.return_value.add_account.assert_called_once_with(
            slot=None,
            alias=None,
            proxy="http://127.0.0.1:3128",
            expect_country="DE",
            expect_ip=None,
        )

    def test_expectation_without_a_proxy_is_refused(
        self, temp_home, monkeypatch, capsys,
    ):
        monkeypatch.setattr(
            sys, "argv", ["claude-swap", "add", "--expect-country", "US"]
        )
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2
        assert "require --proxy" in capsys.readouterr().err

    def test_expectation_on_another_command_is_refused(
        self, temp_home, monkeypatch, capsys,
    ):
        monkeypatch.setattr(
            sys,
            "argv",
            ["claude-swap", "list", "--proxy", "http://127.0.0.1:3128",
             "--expect-country", "US"],
        )
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2
        assert "can only be used with 'add'" in capsys.readouterr().err

    def test_login_outside_add_is_refused(
        self, temp_home, monkeypatch, capsys,
    ):
        monkeypatch.setattr(sys, "argv", ["claude-swap", "list", "--login"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2
        assert "--login can only be used with 'add'" in capsys.readouterr().err

    def test_email_without_login_is_refused(
        self, temp_home, monkeypatch, capsys,
    ):
        monkeypatch.setattr(
            sys, "argv",
            ["claude-swap", "add", "--email", "new@example.com"],
        )
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2
        assert "add --login" in capsys.readouterr().err

    def test_a_parse_error_on_add_login_does_not_echo_the_proxy_password(
        self, temp_home, monkeypatch, capsys,
    ):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "claude-swap", "add", "--login",
                "--proxy", "http://user:secret@127.0.0.1:3128",
                "--slot=http://user:other-secret@127.0.0.1:3129",
            ],
        )
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "secret" not in err
        assert "<URL>" in err

"""`cswap add --login` and `--expect-country` / `--expect-ip` on `add`.

The isolated login is Claude Code's own ``claude auth login`` in a throwaway
``CLAUDE_CONFIG_DIR``. These tests drive that child through a fake
``spawn.run``: no browser, no network, no real profile. The proxy and GeoIP
checks are seams too, so a refused check is observed before the child starts.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
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

    def test_a_dead_saved_proxy_stops_the_relogin_before_claude(
        self, temp_home, claude_bin, monkeypatch, capsys,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account(
                "new@example.com",
                org="org-new",
                org_name="New Org",
                proxy="http://user:secret@127.0.0.1:3129",
            ),
        })
        spawn_called = []
        monkeypatch.setattr(
            "claude_swap.login.spawn.run",
            lambda *a, **k: spawn_called.append(a),
        )

        def dead(route, timeout=account_proxy.PROBE_TIMEOUT_S):
            raise account_proxy.ProxyRouteError(
                account_proxy.PROXY_UNREACHABLE,
                "the proxy did not accept a connection",
            )

        monkeypatch.setattr(account_proxy, "probe", dead)

        with pytest.raises(SessionError, match="cannot be used"):
            switcher.add_account_via_login(slot=2)

        assert spawn_called == []
        assert switcher._get_sequence_data()["accounts"]["2"]["email"] == (
            "new@example.com"
        )
        captured = capsys.readouterr()
        assert "secret" not in captured.out + captured.err

    def test_a_corrupt_saved_proxy_stops_the_relogin_before_claude(
        self, temp_home, claude_bin, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account(
                "new@example.com",
                org="org-new",
                org_name="New Org",
                proxy="not a proxy URL",
            ),
        })
        spawn_called = []
        monkeypatch.setattr(
            "claude_swap.login.spawn.run",
            lambda *a, **k: spawn_called.append(a),
        )

        # The real probe refuses an unusable stored value before any socket.
        with pytest.raises(SessionError, match="cannot be used"):
            switcher.add_account_via_login(slot=2)

        assert spawn_called == []
        assert switcher._get_sequence_data()["accounts"]["2"]["proxy"] == (
            "not a proxy URL"
        )

    def test_a_login_without_a_slot_warns_that_a_saved_proxy_was_not_used(
        self, temp_home, claude_bin, checks_pass, monkeypatch, capsys,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account(
                "new@example.com",
                org="org-new",
                org_name="New Org",
                proxy="http://user:secret@127.0.0.1:3129",
            ),
        })
        record = {}
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock(record))

        switcher.add_account_via_login()

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "already has a saved proxy" in output
        assert "http://user:***@127.0.0.1:3129" in output
        assert "cswap add --login --slot 2" in output
        assert "secret" not in output
        # The login itself went direct; the stored route is only reported.
        assert checks_pass["probe"] == []
        assert checks_pass["egress"] == []
        assert "127.0.0.1:3129" not in record["env"].get("HTTPS_PROXY", "")

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

    def test_an_invalid_email_value_is_not_echoed(
        self, temp_home, monkeypatch, capsys,
    ):
        switcher = _switcher()
        _seed(switcher, {"1": _account("live@example.com")})
        pasted_proxy = "http://user:s3cret-word@127.0.0.1:3128"

        def forbidden():
            raise AssertionError("find_claude ran before the argument check")

        monkeypatch.setattr("claude_swap.session.find_claude", forbidden)

        with pytest.raises(ValidationError) as exc:
            switcher.add_account_via_login(email=pasted_proxy)

        message = str(exc.value)
        assert "Invalid email format" in message
        assert "s3cret-word" not in message
        assert pasted_proxy not in message
        captured = capsys.readouterr()
        assert "s3cret-word" not in captured.out + captured.err

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

        saved_route = account_proxy.parse("http://127.0.0.1:3129")
        assert [route.text() for route in checks_pass["probe"]] == [
            saved_route.text()
        ]
        assert len(checks_pass["egress"]) == 1
        checked_route, checked_rule = checks_pass["egress"][0]
        assert checked_route.text() == saved_route.text()
        assert checked_rule == egress.Expectation(
            country="DE", ip="5.6.7.8"
        )
        assert record["env"]["HTTPS_PROXY"] == saved_route.text()
        assert record["env"]["https_proxy"] == saved_route.text()

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


class TestLoginCommitSafety:
    OLD_CREDS = json.dumps({
        "claudeAiOauth": {
            "accessToken": "old-access",
            "refreshToken": "old-refresh",
            "expiresAt": 99999999999000,
        }
    })
    OLD_CONFIG = json.dumps({"oauthAccount": {"emailAddress": "old@example.com"}})

    def _seed_files(self, switcher, num, email):
        switcher._write_account_credentials(num, email, self.OLD_CREDS)
        switcher._write_account_config(num, email, self.OLD_CONFIG)

    def test_a_config_write_failure_leaves_the_displaced_slot_intact(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account("other@example.com", org="org-other"),
        })
        self._seed_files(switcher, "2", "other@example.com")
        before = switcher.sequence_file.read_bytes()
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock({}))

        def no_space(num, email, config):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(switcher, "_write_account_config", no_space)

        with pytest.raises(OSError) as exc:
            switcher.add_account_via_login(slot=2, assume_yes=True)
        assert exc.value.errno == errno.ENOSPC

        assert switcher.sequence_file.read_bytes() == before
        data = switcher._get_sequence_data()
        assert data["accounts"]["2"]["email"] == "other@example.com"
        assert switcher._read_account_credentials(
            "2", "other@example.com"
        ) == self.OLD_CREDS
        assert switcher._read_account_config(
            "2", "other@example.com"
        ) == self.OLD_CONFIG
        assert switcher._read_account_credentials("2", "new@example.com") == ""
        assert switcher._read_account_config("2", "new@example.com") == ""

    def test_a_same_email_write_failure_restores_the_old_material(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account(
                "new@example.com",
                org="org-old",
                org_name="Old Org",
            ),
        })
        self._seed_files(switcher, "2", "new@example.com")
        before = switcher.sequence_file.read_bytes()
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock({}))

        real_write_json = switcher._write_json

        def fail_sequence(path, data):
            if path == switcher.sequence_file:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write_json(path, data)

        monkeypatch.setattr(switcher, "_write_json", fail_sequence)

        with pytest.raises(OSError) as exc:
            switcher.add_account_via_login(slot=2, assume_yes=True)
        assert exc.value.errno == errno.ENOSPC

        assert switcher.sequence_file.read_bytes() == before
        data = switcher._get_sequence_data()
        assert data["accounts"]["2"]["organizationUuid"] == "org-old"
        assert switcher._read_account_credentials(
            "2", "new@example.com"
        ) == self.OLD_CREDS
        assert switcher._read_account_config(
            "2", "new@example.com"
        ) == self.OLD_CONFIG

    def test_a_refresh_failure_keeps_the_slots_old_files(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account(
                "new@example.com",
                org="org-new",
                org_name="New Org",
                proxy="http://127.0.0.1:3129",
            ),
        })
        self._seed_files(switcher, "2", "new@example.com")
        before = switcher.sequence_file.read_bytes()
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock({}))

        real_write_json = switcher._write_json

        def fail_sequence(path, data):
            if path == switcher.sequence_file:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write_json(path, data)

        monkeypatch.setattr(switcher, "_write_json", fail_sequence)

        with pytest.raises(OSError):
            switcher.add_account_via_login(slot=2)

        assert switcher.sequence_file.read_bytes() == before
        assert switcher._read_account_credentials(
            "2", "new@example.com"
        ) == self.OLD_CREDS
        assert switcher._read_account_config(
            "2", "new@example.com"
        ) == self.OLD_CONFIG
        assert switcher._get_sequence_data()["accounts"]["2"]["proxy"] == (
            "http://127.0.0.1:3129"
        )

    def test_a_live_session_on_the_migration_source_keeps_both_slots(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("new@example.com", org="org-new", org_name="New Org"),
            "2": _account("other@example.com", org="org-other"),
        })
        self._seed_files(switcher, "1", "new@example.com")
        self._seed_files(switcher, "2", "other@example.com")
        before = switcher.sequence_file.read_bytes()
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock({}))
        monkeypatch.setattr(
            switcher,
            "_live_session_pids",
            lambda num, email: [4242] if num == "1" else [],
        )

        with pytest.raises(SessionError, match="live session-mode"):
            switcher.add_account_via_login(slot=2, assume_yes=True)

        assert switcher.sequence_file.read_bytes() == before
        data = switcher._get_sequence_data()
        assert data["accounts"]["1"]["email"] == "new@example.com"
        assert data["accounts"]["2"]["email"] == "other@example.com"
        assert switcher._read_account_config(
            "2", "other@example.com"
        ) == self.OLD_CONFIG

    def test_overwriting_the_active_slot_is_refused_before_any_write(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com"),
            "2": _account("other@example.com", org="org-other"),
        }, active=2)
        self._seed_files(switcher, "2", "other@example.com")
        before = switcher.sequence_file.read_bytes()
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock({}))

        with pytest.raises(ConfigError, match="active login"):
            switcher.add_account_via_login(slot=2, assume_yes=True)

        assert switcher.sequence_file.read_bytes() == before
        data = switcher._get_sequence_data()
        assert data["accounts"]["2"]["email"] == "other@example.com"
        assert data["activeAccountNumber"] == 2
        assert switcher._read_account_config(
            "2", "other@example.com"
        ) == self.OLD_CONFIG

    def test_moving_the_active_account_updates_the_pointer(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("new@example.com", org="org-new", org_name="New Org"),
        }, active=1)
        self._seed_files(switcher, "1", "new@example.com")
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock({}))

        switcher.add_account_via_login(slot=2)

        data = switcher._get_sequence_data()
        assert data["activeAccountNumber"] == 2
        assert "1" not in data["accounts"]
        assert data["accounts"]["2"]["email"] == "new@example.com"
        assert data["sequence"] == [2]

    def test_initialization_runs_under_the_account_lock_and_keeps_a_slot(
        self, temp_home, claude_bin, checks_pass, monkeypatch,
    ):
        from claude_swap import switcher as switcher_module

        switcher = ClaudeAccountSwitcher()
        switcher._setup_directories()
        switcher.sequence_file.unlink(missing_ok=True)

        depths = {"now": 0, "init": None}
        real_lock = switcher_module.FileLock

        class RecordingLock(real_lock):
            def __enter__(self):
                depths["now"] += 1
                return super().__enter__()

            def __exit__(self, *args):
                try:
                    return super().__exit__(*args)
                finally:
                    depths["now"] -= 1

        monkeypatch.setattr(switcher_module, "FileLock", RecordingLock)
        real_init = switcher._init_sequence_file

        def init_recording():
            depths["init"] = depths["now"]
            real_init()

        monkeypatch.setattr(switcher, "_init_sequence_file", init_recording)
        real_setup = switcher._setup_directories

        def setup_then_race():
            real_setup()
            if not switcher.sequence_file.exists():
                switcher._write_json(switcher.sequence_file, {
                    "activeAccountNumber": 1,
                    "lastUpdated": "2024-01-01T00:00:00Z",
                    "sequence": [1],
                    "accounts": {"1": _account("live@example.com")},
                })

        monkeypatch.setattr(switcher, "_setup_directories", setup_then_race)
        monkeypatch.setattr("claude_swap.login.spawn.run", _login_mock({}))

        switcher.add_account_via_login(slot=2)

        assert depths["init"] is not None and depths["init"] >= 1
        data = switcher._get_sequence_data()
        assert data["accounts"]["1"]["email"] == "live@example.com"
        assert data["accounts"]["2"]["email"] == "new@example.com"

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


    def test_a_keychain_delete_failure_is_a_warning(
        self, block_real_keychain, monkeypatch, capsys,
    ):
        from claude_swap import macos_keychain

        monkeypatch.setattr(
            Platform, "detect", classmethod(lambda cls: Platform.MACOS)
        )

        def denied(service, account):
            raise macos_keychain.KeychainError("the Keychain denied the request")

        monkeypatch.setattr(macos_keychain, "delete_password", denied)
        captured = {}
        with login.isolated_profile() as config_dir:
            captured["dir"] = config_dir

        assert not captured["dir"].exists()
        err = capsys.readouterr().err
        assert "could not delete the temporary login Keychain entry" in err
        assert "denied" not in err

    def test_a_directory_removal_failure_is_a_warning(
        self, monkeypatch, capsys,
    ):
        real_rmtree = shutil.rmtree

        def busy(path, *args, **kwargs):
            raise OSError("directory is busy")

        monkeypatch.setattr(login.shutil, "rmtree", busy)
        captured = {}
        try:
            with login.isolated_profile() as config_dir:
                captured["dir"] = config_dir
        finally:
            real_rmtree(captured["dir"], ignore_errors=True)

        err = capsys.readouterr().err
        assert "could not remove the temporary login profile" in err
        assert str(captured["dir"]) in err


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

        real_guard = switcher._reject_foreign_credential_capture

        def guard_then_concurrent_proxy(*args, **kwargs):
            result = real_guard(*args, **kwargs)
            data = switcher._get_sequence_data()
            data["accounts"]["1"]["proxy_expected_country"] = "DE"
            data["accounts"]["1"]["proxy_expected_ip"] = "5.6.7.8"
            switcher._write_json(switcher.sequence_file, data)
            return result

        monkeypatch.setattr(
            switcher,
            "_reject_foreign_credential_capture",
            guard_then_concurrent_proxy,
        )

        switcher.add_account(slot=1, assume_yes=True)

        record = switcher._get_sequence_data()["accounts"]["1"]
        assert record["proxy"] == "http://127.0.0.1:3129"
        assert record["proxy_expected_country"] == "DE"
        assert record["proxy_expected_ip"] == "5.6.7.8"


    def _live_add_setup(self, temp_home, switcher, monkeypatch):
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

    def test_a_concurrent_expectation_update_survives_a_slot_migration(
        self, temp_home, monkeypatch,
    ):
        switcher = _switcher()
        _seed(switcher, {
            "1": _account("live@example.com", proxy="http://127.0.0.1:3129"),
        })
        self._live_add_setup(temp_home, switcher, monkeypatch)
        real_guard = switcher._reject_foreign_credential_capture

        def guard_then_concurrent_proxy(*args, **kwargs):
            result = real_guard(*args, **kwargs)
            data = switcher._get_sequence_data()
            data["accounts"]["1"]["proxy_expected_country"] = "DE"
            data["accounts"]["1"]["proxy_expected_ip"] = "5.6.7.8"
            switcher._write_json(switcher.sequence_file, data)
            return result

        monkeypatch.setattr(
            switcher,
            "_reject_foreign_credential_capture",
            guard_then_concurrent_proxy,
        )

        switcher.add_account(slot=2, assume_yes=True)

        data = switcher._get_sequence_data()
        assert "1" not in data["accounts"]
        record = data["accounts"]["2"]
        assert record["proxy"] == "http://127.0.0.1:3129"
        assert record["proxy_expected_country"] == "DE"
        assert record["proxy_expected_ip"] == "5.6.7.8"

    def test_a_concurrent_unset_expectation_is_not_resurrected(
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
        self._live_add_setup(temp_home, switcher, monkeypatch)
        real_guard = switcher._reject_foreign_credential_capture

        def guard_then_unset(*args, **kwargs):
            result = real_guard(*args, **kwargs)
            data = switcher._get_sequence_data()
            data["accounts"]["1"].pop("proxy_expected_country", None)
            data["accounts"]["1"].pop("proxy_expected_ip", None)
            switcher._write_json(switcher.sequence_file, data)
            return result

        monkeypatch.setattr(
            switcher, "_reject_foreign_credential_capture", guard_then_unset
        )

        switcher.add_account(slot=1, assume_yes=True)

        record = switcher._get_sequence_data()["accounts"]["1"]
        assert record["proxy"] == "http://127.0.0.1:3129"
        assert "proxy_expected_country" not in record
        assert "proxy_expected_ip" not in record

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

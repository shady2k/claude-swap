"""The fork's isolated paradigm: the active slot in ``sequence.json`` is the
account, and the global ``~/.claude`` login is never written or used.

What users see is in ``docs/auto-launch.md``; the rules are in the module
docstring of ``claude_swap/isolated_mode.py``.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from claude_swap import isolated_mode, oauth
from claude_swap.credentials import CredentialStore
from claude_swap.exceptions import ConfigError, SessionError, SwitchError
from claude_swap.models import Platform
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.usage_store import UsageEntry

CREDS_1 = json.dumps({
    "claudeAiOauth": {"accessToken": "sk-1", "refreshToken": "rt-1",
                      "expiresAt": 9999999999000},
})
CREDS_2 = json.dumps({
    "claudeAiOauth": {"accessToken": "sk-2", "refreshToken": "rt-2",
                      "expiresAt": 9999999999000},
})


def _config(email: str, uuid: str) -> str:
    return json.dumps({
        "oauthAccount": {"emailAddress": email, "accountUuid": uuid,
                         "organizationUuid": ""},
    })


def _switcher() -> ClaudeAccountSwitcher:
    s = ClaudeAccountSwitcher()
    s.platform = Platform.LINUX
    s._setup_directories()
    s._init_sequence_file()
    return s


def _seed(s: ClaudeAccountSwitcher, num: int, email: str, creds: str = CREDS_1) -> None:
    s._write_account_credentials(str(num), email, creds)
    s._write_account_config(str(num), email, _config(email, f"uuid-{num}"))
    data = s._get_sequence_data()
    data["accounts"][str(num)] = {
        "email": email,
        "uuid": f"uuid-{num}",
        "organizationUuid": "",
        "organizationName": "",
        "added": "2024-01-01T00:00:00Z",
    }
    if num not in data["sequence"]:
        data["sequence"].append(num)
        data["sequence"].sort()
    if data["activeAccountNumber"] is None:
        data["activeAccountNumber"] = num
    s._write_json(s.sequence_file, data)


def _tree(root: Path) -> dict[str, bytes]:
    """Every file under ``root`` with its bytes — a whole-store fingerprint."""
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# ---------------------------------------------------------------------------
# A switch writes sequence.json and nothing else
# ---------------------------------------------------------------------------


class TestASwitchWritesOnlyTheRecord:
    def test_switch_to_changes_only_the_two_fields(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)

        roots = [temp_home / ".claude", s.credentials_dir, s.configs_dir]
        before = {root: _tree(root) for root in roots if root.exists()}
        with patch.object(s, "_write_credentials") as write_live, \
             patch.object(s, "list_accounts"):
            s.switch_to("2", json_output=True)
        write_live.assert_not_called()

        after = {root: _tree(root) for root in roots if root.exists()}
        assert after == before, "a switch wrote into the account store"
        data = s._get_sequence_data()
        assert data["activeAccountNumber"] == 2

    def test_active_slot_credentials_are_never_rewritten(self, temp_home: Path):
        """A switch leaves every slot's stored credential as it was."""
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        before = {
            "1": s._read_account_credentials("1", "a@example.com"),
            "2": s._read_account_credentials("2", "b@example.com"),
        }

        with patch.object(s, "list_accounts"):
            s.switch_to("2")

        assert s._read_account_credentials("1", "a@example.com") == before["1"]
        assert s._read_account_credentials("2", "b@example.com") == before["2"]

    def test_a_running_session_is_untouched(self, temp_home: Path):
        """The active slot's live session profile is not opened at all."""
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        session_dir = s.backup_dir / "sessions" / "1-a-example.com"
        session_dir.mkdir(parents=True)
        (session_dir / ".credentials.json").write_text(CREDS_1)
        before = _tree(session_dir)

        with patch.object(s, "list_accounts"):
            s.switch_to("2")

        assert _tree(session_dir) == before

    def test_next_and_prev_walk_the_sequence(self, temp_home: Path):
        s = _switcher()
        for num, email in ((1, "a@example.com"), (2, "b@example.com"),
                           (3, "c@example.com")):
            _seed(s, num, email)
        data = s._get_sequence_data()
        data["activeAccountNumber"] = 2
        s._write_json(s.sequence_file, data)

        s.switch(json_output=True)
        assert s._get_sequence_data()["activeAccountNumber"] == 3
        s.switch(json_output=True, previous=True)
        assert s._get_sequence_data()["activeAccountNumber"] == 2

    def test_switch_to_an_unlaunchable_slot_names_the_remedy(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        data = s._get_sequence_data()
        data["accounts"]["2"] = {
            "email": "b@example.com", "uuid": "uuid-2",
            "organizationUuid": "", "organizationName": "",
            "added": "2024-01-01T00:00:00Z",
        }
        data["sequence"].append(2)
        s._write_json(s.sequence_file, data)

        with pytest.raises(SwitchError, match="cswap --add-account --slot 2"):
            s.switch_to("2")
        assert s._get_sequence_data()["activeAccountNumber"] == 1


# ---------------------------------------------------------------------------
# The active slot is the record, never the global login
# ---------------------------------------------------------------------------


class TestTheRecordIsTheActiveAccount:
    def test_current_account_number_reads_the_record(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        data = s._get_sequence_data()
        data["activeAccountNumber"] = 2
        s._write_json(s.sequence_file, data)

        assert s.current_account_number() == "2"

    def test_a_global_login_does_not_become_the_active_slot(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        data = s._get_sequence_data()
        data["activeAccountNumber"] = None
        s._write_json(s.sequence_file, data)
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "a@example.com",
                             "accountUuid": "uuid-1"},
        }))
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_1)

        assert s.current_account_number() is None
        assert s.has_live_login() is True

    def test_require_active_slot_refuses_with_nothing_recorded(self, temp_home: Path):
        s = _switcher()
        with pytest.raises(ConfigError, match="cswap switch"):
            isolated_mode.require_active_slot(s)

    def test_require_active_slot_refuses_a_slot_without_credentials(
        self, temp_home: Path
    ):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        s._delete_account_credentials("1", "a@example.com")

        with pytest.raises(ConfigError, match="cswap add --slot 1"):
            isolated_mode.require_active_slot(s)

    def test_the_active_slot_is_not_marked_switchable_by_the_global_login(
        self, temp_home: Path
    ):
        """The list marks the recorded slot; a global login alone marks none."""
        s = _switcher()
        _seed(s, 1, "a@example.com", CREDS_1)
        data = s._get_sequence_data()
        data["activeAccountNumber"] = None
        s._write_json(s.sequence_file, data)
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_2)
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "a@example.com",
                             "accountUuid": "uuid-1"},
        }))

        with patch("claude_swap.oauth.try_fetch_usage_for_account",
                   return_value=oauth.UsageOutcome(None)):
            payload = s.list_accounts(json_output=True)

        assert payload["activeAccountNumber"] is None
        assert [a["active"] for a in payload["accounts"]] == [False]


# ---------------------------------------------------------------------------
# The leftover global login is reported, never used
# ---------------------------------------------------------------------------


class TestTheLeftoverGlobalLogin:
    def _global_login(self, temp_home: Path, email: str = "stray@example.com") -> None:
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": email, "accountUuid": "uuid-stray"},
            "mcpServers": {"keep": {"command": "x"}},
        }))
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_2)

    def test_detector_reads_the_default_profile(self, temp_home: Path, monkeypatch):
        s = _switcher()
        self._global_login(temp_home)
        assert isolated_mode.global_login(s) == {"email": "stray@example.com"}

        # Inside a session profile's shell the DEFAULT profile still answers.
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(s.backup_dir / "sessions" / "x"))
        assert isolated_mode.global_login(s) == {"email": "stray@example.com"}

    def test_no_login_no_notice(self, temp_home: Path):
        s = _switcher()
        assert isolated_mode.global_login(s) is None
        assert isolated_mode.global_login_notice(s) is None

    def test_list_and_status_carry_it_additively(self, temp_home: Path, capsys):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        self._global_login(temp_home)
        before = (temp_home / ".claude.json").read_text()

        with patch("claude_swap.oauth.try_fetch_usage_for_account",
                   return_value=oauth.UsageOutcome(None)):
            listed = s.list_accounts(json_output=True)
            status = s.status(json_output=True)

        assert listed["globalLogin"] == {"email": "stray@example.com"}
        assert status["globalLogin"] == {"email": "stray@example.com"}
        assert (temp_home / ".claude.json").read_text() == before, (
            "reporting must never write the global login"
        )

    def test_the_human_list_says_what_to_do(self, temp_home: Path, capsys):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        self._global_login(temp_home)

        with patch("claude_swap.oauth.try_fetch_usage_for_account",
                   return_value=oauth.UsageOutcome(None)):
            s.list_accounts()

        out = capsys.readouterr().out
        assert "stray@example.com" in out
        assert "cswap add" in out

    def test_absent_field_when_clean(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        with patch("claude_swap.oauth.try_fetch_usage_for_account",
                   return_value=oauth.UsageOutcome(None)):
            payload = s.list_accounts(json_output=True)
        assert "globalLogin" not in payload


# ---------------------------------------------------------------------------
# `cswap add` takes the global login over
# ---------------------------------------------------------------------------


class TestAddTakesTheGlobalLoginOver:
    def _login(self, temp_home: Path, email: str = "a@example.com") -> None:
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": email, "accountUuid": "uuid-a",
                             "organizationUuid": ""},
            "mcpServers": {"keep": {"command": "x"}},
            "projects": {"/work": {"allowedTools": []}},
            "userID": "uid-1",
        }))
        (temp_home / ".claude").mkdir(exist_ok=True)
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_1)
        (temp_home / ".claude" / "settings.json").write_text('{"theme": "dark"}')
        (temp_home / ".claude" / "CLAUDE.md").write_text("# notes")
        (temp_home / ".claude" / "skills").mkdir(exist_ok=True)

    def test_a_saved_slot_removes_the_auth_and_keeps_the_shared_files(
        self, temp_home: Path
    ):
        s = _switcher()
        self._login(temp_home)

        with patch.object(s, "_read_capture_credentials", return_value=CREDS_1), \
             patch("claude_swap.oauth.fetch_oauth_profile",
                   return_value={"uuid": "uuid-a", "email": "a@example.com",
                                 "organizationUuid": ""}):
            s.add_account()

        assert not (temp_home / ".claude" / ".credentials.json").exists()
        config = json.loads((temp_home / ".claude.json").read_text())
        assert "oauthAccount" not in config
        # Everything shared survives untouched.
        assert config["mcpServers"] == {"keep": {"command": "x"}}
        assert config["projects"] == {"/work": {"allowedTools": []}}
        assert config["userID"] == "uid-1"
        assert (temp_home / ".claude" / "settings.json").exists()
        assert (temp_home / ".claude" / "CLAUDE.md").read_text() == "# notes"
        assert (temp_home / ".claude" / "skills").is_dir()

    def test_a_failed_save_keeps_the_global_login(self, temp_home: Path):
        """The login is only removed once the slot is committed."""
        s = _switcher()
        self._login(temp_home)

        with patch.object(s, "_read_capture_credentials", return_value=CREDS_1), \
             patch("claude_swap.oauth.fetch_oauth_profile",
                   return_value={"uuid": "uuid-a", "email": "a@example.com",
                                 "organizationUuid": ""}), \
             patch.object(s, "_write_slot_atomically",
                          side_effect=ConfigError("slot save failed")):
            with pytest.raises(ConfigError):
                s.add_account()

        assert (temp_home / ".claude" / ".credentials.json").read_text() == CREDS_1
        config = json.loads((temp_home / ".claude.json").read_text())
        assert config["oauthAccount"]["emailAddress"] == "a@example.com"

    def test_clear_global_login_is_atomic_about_the_config(self, temp_home: Path):
        """An unreadable ``~/.claude.json`` is reported, not overwritten."""
        s = _switcher()
        self._login(temp_home)
        (temp_home / ".claude.json").write_text('{"oauthAccount": ')

        assert isolated_mode.clear_global_login(s, CREDS_1) is False
        # The credential still went; the file is left for the user to repair.
        assert not (temp_home / ".claude" / ".credentials.json").exists()
        assert (temp_home / ".claude.json").read_text() == '{"oauthAccount": '


# ---------------------------------------------------------------------------
# Launching the active slot: fail closed, and never on the global login
# ---------------------------------------------------------------------------


class TestTheLaunchOnTheActiveSlot:
    def _namespace(self, **overrides) -> MagicMock:
        args = MagicMock()
        args.account = None
        args.auto = False
        args.active = True
        args.no_share = False
        args.share_history = None
        args.require_session = False
        args.debug = False
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def test_active_launches_the_recorded_slot_with_its_identity(
        self, temp_home: Path
    ):
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        data = s._get_sequence_data()
        data["activeAccountNumber"] = 2
        s._write_json(s.sequence_file, data)

        calls = []
        manager = MagicMock()
        manager.run.side_effect = lambda *a, **k: calls.append((a, k))
        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager), \
             patch("claude_swap.cli._guard_root"):
            cli._run_launch(self._namespace(), ["--resume"])

        (args, kwargs), = calls
        assert args[0] == "2"
        claude_args = args[1]
        # `--active` carries the StopFailure hook the recorded account was
        # resolved with: `--settings` first, the user's words after it.
        assert claude_args[0] == "--settings"
        hook = json.loads(claude_args[1])["hooks"]["StopFailure"][0]
        assert hook["matcher"] == "rate_limit"
        assert "rate-limited b@example.com" in hook["hooks"][0]["command"]
        assert claude_args[2:] == ["--resume"]
        # The triple pins the launch to the account that was resolved.
        assert kwargs["account"] == ("2", "b@example.com", "")

    def test_active_with_nothing_recorded_is_a_refusal(self, temp_home: Path, capsys):
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        data = s._get_sequence_data()
        data["activeAccountNumber"] = None
        s._write_json(s.sequence_file, data)

        manager = MagicMock()
        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(SystemExit) as excinfo:
                cli._run_launch(self._namespace(), [])

        assert excinfo.value.code == 1
        manager.run.assert_not_called()
        manager.exec_default.assert_not_called()
        assert "No active account is recorded" in capsys.readouterr().err

    def test_active_refuses_without_falling_back_to_plain_claude(
        self, temp_home: Path
    ):
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        s._config_backup_path("1", "a@example.com").unlink()

        manager = MagicMock()
        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(SystemExit):
                cli._run_launch(self._namespace(), [])

        manager.run.assert_not_called()
        manager.exec_default.assert_not_called()


# ---------------------------------------------------------------------------
# The wrapper and find_claude
# ---------------------------------------------------------------------------


class TestFindClaude:
    def _executable(self, path: Path, body: str) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return str(path)

    def test_cswap_claude_bin_wins(self, temp_home: Path, monkeypatch):
        from claude_swap.session import find_claude

        real = self._executable(temp_home / "opt" / "claude", "#!/bin/sh\nexit 0\n")
        monkeypatch.setenv("CSWAP_CLAUDE_BIN", real)
        assert find_claude() == real

    def test_cswap_claude_bin_is_used_without_a_path_claude(
        self, temp_home: Path, monkeypatch
    ):
        from claude_swap.session import find_claude

        real = self._executable(temp_home / "bin" / "claude", "#!/bin/sh\nexit 0\n")
        monkeypatch.setenv("CSWAP_CLAUDE_BIN", real)
        monkeypatch.setenv("PATH", str(temp_home / "empty"))
        assert find_claude() == real

    def test_a_wrapper_behind_cswap_claude_bin_is_refused(
        self, temp_home: Path, monkeypatch
    ):
        """The variable may name a launcher, but never our own wrapper."""
        from claude_swap import wrapper
        from claude_swap.session import find_claude

        copy = temp_home / "bin" / "claude"
        copy.parent.mkdir(parents=True)
        copy.write_bytes(wrapper.WRAPPER_PATH.read_bytes())
        copy.chmod(0o755)
        monkeypatch.setenv("CSWAP_CLAUDE_BIN", str(copy))
        assert find_claude() is None

    def test_a_missing_cswap_claude_bin_is_not_a_reason_to_search_path(
        self, temp_home: Path, monkeypatch
    ):
        """An explicit answer is honoured exactly: no silent fallback."""
        from claude_swap.session import find_claude

        self._executable(temp_home / "bin" / "claude", "#!/bin/sh\nexit 0\n")
        monkeypatch.setenv("CSWAP_CLAUDE_BIN", str(temp_home / "nope" / "claude"))
        monkeypatch.setenv("PATH", str(temp_home / "bin"))
        assert find_claude() is None


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the wrapper is a POSIX shell script; Windows is not a target",
)
class TestTheShippedWrapper:
    def _layout(self, tmp_path: Path) -> dict[str, Path]:
        from claude_swap import wrapper

        wrapper_dir = tmp_path / "wrapper"
        cswap_dir = tmp_path / "cswap"
        real_dir = tmp_path / "real"
        for directory in (wrapper_dir, cswap_dir, real_dir):
            directory.mkdir()
        link = wrapper_dir / "claude"
        link.symlink_to(wrapper.WRAPPER_PATH)
        recorded = tmp_path / "cswap.json"

        shim = cswap_dir / "cswap"
        shim.write_text(
            "#!{}\nimport json, os, sys\n"
            "json.dump({{'argv': sys.argv[1:], 'env': dict(os.environ)}}, "
            "open({!r}, 'w'))\n".format(sys.executable, str(recorded)),
            encoding="utf-8",
        )
        shim.chmod(0o755)
        real = real_dir / "claude"
        real.write_text(
            "#!{}\nimport json, sys\nprint(json.dumps({{'real': sys.argv[1:]}}))\n".format(
                sys.executable
            ),
            encoding="utf-8",
        )
        real.chmod(0o755)
        return {
            "wrapper_dir": wrapper_dir,
            "cswap_dir": cswap_dir,
            "real_dir": real_dir,
            "link": link,
            "recorded": recorded,
        }

    def _env(self, layout: dict[str, Path], **extra: str) -> dict[str, str]:
        env = {
            # The user's usual directories come after the three this test
            # builds, so head/grep exist as they would on a real box.
            "PATH": os.pathsep.join(
                [
                    str(layout[name])
                    for name in ("wrapper_dir", "cswap_dir", "real_dir")
                ]
                + [os.environ.get("PATH", "")]
            ),
            "HOME": str(layout["wrapper_dir"].parent),
            "LC_ALL": "C",
        }
        env.update(extra)
        return env

    def _run(self, argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv, env=env, capture_output=True, text=True, timeout=60
        )

    def test_a_launch_hands_over_to_the_active_slot(self, tmp_path: Path):
        layout = self._layout(tmp_path)
        result = self._run([str(layout["link"]), "--resume"], self._env(layout))

        assert result.returncode == 0, result.stderr
        recorded = json.loads(layout["recorded"].read_text())
        assert recorded["argv"] == ["run", "--active", "--", "--resume"]
        # Claude Code's own updater would install a second, unwrapped launcher.
        assert recorded["env"]["DISABLE_AUTOUPDATER"] == "1"

    @pytest.mark.parametrize("flag", ["--version", "-v", "--help", "-h"])
    def test_a_version_or_help_flag_goes_straight_to_the_real_binary(
        self, tmp_path: Path, flag: str
    ):
        """An SDK asking for the version gets an answer without an account."""
        layout = self._layout(tmp_path)
        result = self._run([str(layout["link"]), flag], self._env(layout))

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"real": [flag]}
        assert not layout["recorded"].exists(), "cswap must not be called"

    def test_the_version_lookup_honours_cswap_claude_bin(self, tmp_path: Path):
        layout = self._layout(tmp_path)
        # No real claude on PATH at all: only the variable names one.
        env = self._env(layout)
        env["PATH"] = os.pathsep.join(
            str(layout[name]) for name in ("wrapper_dir", "cswap_dir")
        )
        env["CSWAP_CLAUDE_BIN"] = str(layout["real_dir"] / "claude")

        result = self._run([str(layout["link"]), "--version"], env)

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"real": ["--version"]}

    def test_the_wrapper_never_execs_itself_on_a_bare_path(self, tmp_path: Path):
        """Without head/grep the marker cannot be read, so identity decides.

        A wrapper that walked PATH by marker alone would find only itself,
        and exec itself: the launch would recurse instead of answering.
        """
        layout = self._layout(tmp_path)
        env = self._env(layout)
        env["PATH"] = os.pathsep.join(
            [str(layout["wrapper_dir"]), str(layout["real_dir"])]
        )

        result = self._run([str(layout["link"]), "--version"], env)

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"real": ["--version"]}


# ---------------------------------------------------------------------------
# A disabled slot is refused by every launch and switch, not skipped silently
# ---------------------------------------------------------------------------


def _active_args(**overrides) -> MagicMock:
    args = MagicMock()
    args.account = None
    args.auto = False
    args.active = True
    args.no_share = False
    args.share_history = None
    args.require_session = False
    args.debug = False
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def _disable(s: ClaudeAccountSwitcher, num: int) -> None:
    s.set_account_disabled(str(num), True)


class TestADisabledSlotIsRefused:
    def test_require_active_slot_refuses_a_disabled_slot(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _disable(s, 1)

        with pytest.raises(ConfigError, match="cswap enable 1"):
            isolated_mode.require_active_slot(s)

    def test_switch_to_a_disabled_slot_refuses(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _disable(s, 2)

        with pytest.raises(SwitchError, match="cswap enable 2"):
            s.switch_to("2", json_output=True)
        assert s._get_sequence_data()["activeAccountNumber"] == 1

    def test_activate_refuses_a_disabled_slot(self, temp_home: Path):
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _disable(s, 2)

        with pytest.raises(SwitchError, match="disabled"):
            isolated_mode.activate(s, "2", emit_output=False)

    def test_run_active_on_a_disabled_slot_launches_nothing(
        self, temp_home: Path, capsys
    ):
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _disable(s, 1)
        manager = MagicMock()

        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(SystemExit) as excinfo:
                cli._run_launch(_active_args(), [])

        assert excinfo.value.code == 1
        manager.run.assert_not_called()
        manager.exec_default.assert_not_called()
        assert "cswap enable 1" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Upgrading from the release that kept the login in ~/.claude
# ---------------------------------------------------------------------------


class TestTheUpgradeFromTheGlobalLogin:
    def _managed_with_its_global_login(self, temp_home: Path) -> ClaudeAccountSwitcher:
        s = _switcher()
        _seed(s, 1, "a@example.com", CREDS_1)
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "a@example.com",
                             "accountUuid": "uuid-1",
                             "organizationUuid": ""},
        }))
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_1)
        return s

    def test_a_launch_refuses_until_cswap_add_takes_the_login_over(
        self, temp_home: Path, capsys
    ):
        from claude_swap import cli

        s = self._managed_with_its_global_login(temp_home)

        manager = MagicMock()
        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(SystemExit) as excinfo:
                cli._run_launch(_active_args(), ["--resume"])

        assert excinfo.value.code == 1
        manager.run.assert_not_called()
        err = capsys.readouterr().err
        assert "Account-1 (a@example.com)" in err
        assert "cswap add" in err

        # The remedy the refusal names: `cswap add` on the managed account
        # takes the update branch and clears the global copy.
        with patch.object(s, "_read_capture_credentials", return_value=CREDS_1), \
             patch("claude_swap.oauth.fetch_oauth_profile",
                   return_value={"uuid": "uuid-1", "email": "a@example.com",
                                 "organizationUuid": ""}):
            s.add_account()

        assert not (temp_home / ".claude" / ".credentials.json").exists()
        config = json.loads((temp_home / ".claude.json").read_text())
        assert "oauthAccount" not in config
        assert isolated_mode.require_active_slot(s) == "1"

    def test_the_update_branch_keeps_the_slot_settings(self, temp_home: Path):
        """`cswap add` refreshes in place: alias, threshold, proxy survive."""
        s = self._managed_with_its_global_login(temp_home)
        s.set_alias("1", "work")
        s.set_account_threshold("1", 70)

        with patch.object(s, "_read_capture_credentials", return_value=CREDS_1), \
             patch("claude_swap.oauth.fetch_oauth_profile",
                   return_value={"uuid": "uuid-1", "email": "a@example.com",
                                 "organizationUuid": ""}):
            s.add_account()

        record = s._get_sequence_data()["accounts"]["1"]
        assert record["alias"] == "work"
        assert record["threshold"] == 70

    def test_another_accounts_global_login_does_not_block_the_launch(
        self, temp_home: Path
    ):
        """Only the active slot's own login is the upgrade case."""
        s = _switcher()
        _seed(s, 1, "a@example.com", CREDS_1)
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "stray@example.com",
                             "accountUuid": "uuid-x",
                             "organizationUuid": ""},
        }))

        assert isolated_mode.require_active_slot(s) == "1"


# ---------------------------------------------------------------------------
# The global cleanup: default profile, matching fingerprint, verified
# ---------------------------------------------------------------------------


class TestTheGlobalCleanupKeepsTheLiveToken:
    def _login(self, temp_home: Path, creds: str = CREDS_1) -> None:
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "a@example.com",
                             "accountUuid": "uuid-1",
                             "organizationUuid": ""},
            "mcpServers": {"keep": {"command": "x"}},
        }))
        (temp_home / ".claude" / ".credentials.json").write_text(creds)

    def test_a_refreshed_global_token_is_left_in_place(self, temp_home: Path, capsys):
        """Claude Code may have spent the generation the add read."""
        s = _switcher()
        self._login(temp_home, CREDS_2)  # a different refresh token

        assert isolated_mode.clear_global_login(s, CREDS_1) is False
        assert (temp_home / ".claude" / ".credentials.json").read_text() == CREDS_2
        config = json.loads((temp_home / ".claude.json").read_text())
        assert config["oauthAccount"]["emailAddress"] == "a@example.com"
        assert "only live copy" in capsys.readouterr().out

    def test_the_matching_token_goes_and_the_shared_files_stay(
        self, temp_home: Path
    ):
        s = _switcher()
        self._login(temp_home, CREDS_1)

        assert isolated_mode.clear_global_login(s, CREDS_1) is True
        assert not (temp_home / ".claude" / ".credentials.json").exists()
        config = json.loads((temp_home / ".claude.json").read_text())
        assert "oauthAccount" not in config
        assert config["mcpServers"] == {"keep": {"command": "x"}}

    def test_a_macos_keychain_item_is_removed(self, temp_home: Path):
        """The default Keychain item is the credential on macOS."""
        s = _switcher()
        s.platform = Platform.MACOS
        self._login(temp_home, CREDS_1)
        reads = [(CREDS_1, False), (None, False)]
        removed: list[bool] = []

        with patch.object(s._store, "_read_one_oauth_keychain",
                          side_effect=lambda service: reads.pop(0)), \
             patch.object(s._store, "_delete_active_keychain_entry",
                          side_effect=lambda: removed.append(True) or True):
            assert isolated_mode.clear_global_login(s, CREDS_1) is True

        assert removed == [True], "the default Keychain item was never deleted"
        assert not (temp_home / ".claude" / ".credentials.json").exists()

    def test_a_still_present_file_is_reported(self, temp_home: Path, capsys):
        """Removal is verified, not assumed: a survivor is a warning."""
        s = _switcher()
        self._login(temp_home, CREDS_1)

        with patch.object(s._store, "_clear_oauth_credential"):  # unlinks nothing
            assert isolated_mode.clear_global_login(s, CREDS_1) is False

        assert (temp_home / ".claude" / ".credentials.json").exists()
        assert "could not be removed" in capsys.readouterr().out

    def test_an_unreadable_keychain_is_not_an_absent_login(
        self, temp_home: Path, capsys
    ):
        """The item it could not read may be the only live generation."""
        s = _switcher()
        s.platform = Platform.MACOS
        self._login(temp_home, CREDS_1)

        with patch.object(s._store, "_read_one_oauth_keychain",
                          return_value=(None, True)), \
             patch.object(s._store, "_clear_oauth_credential") as cleared:
            assert isolated_mode.clear_global_login(s, CREDS_1) is False

        cleared.assert_not_called()
        assert (temp_home / ".claude" / ".credentials.json").exists()
        config = json.loads((temp_home / ".claude.json").read_text())
        assert config["oauthAccount"]["emailAddress"] == "a@example.com"
        assert "Could not read the macOS Keychain" in capsys.readouterr().out

    def test_a_keychain_that_fails_after_the_removal_is_no_verdict(
        self, temp_home: Path, capsys
    ):
        """The re-read is the check: a failure there verifies nothing."""
        s = _switcher()
        s.platform = Platform.MACOS
        self._login(temp_home, CREDS_1)
        reads = [(None, False), (None, True)]

        with patch.object(s._store, "_read_one_oauth_keychain",
                          side_effect=lambda service: reads.pop(0)):
            assert isolated_mode.clear_global_login(s, CREDS_1) is False

        config = json.loads((temp_home / ".claude.json").read_text())
        assert config["oauthAccount"]["emailAddress"] == "a@example.com"
        assert "Could not read the macOS Keychain" in capsys.readouterr().out

    def test_a_config_that_refuses_the_write_names_the_manual_step(
        self, temp_home: Path, capsys
    ):
        """The slot is saved either way; the leftover key is the user's to
        remove, so the console says which one and where."""
        s = _switcher()
        self._login(temp_home, CREDS_1)

        with patch.object(s._store, "_update_global_config",
                          side_effect=PermissionError("read-only file system")):
            assert isolated_mode.clear_global_login(s, CREDS_1) is False

        out = capsys.readouterr().out
        assert "oauthAccount" in out
        assert ".claude.json" in out
        assert "by hand" in out

    def test_another_profile_skips_the_default_cleanup(
        self, temp_home: Path, monkeypatch, capsys
    ):
        """`CLAUDE_CONFIG_DIR` means the add imported from that profile."""
        s = _switcher()
        self._login(temp_home, CREDS_1)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(temp_home / "other"))

        assert isolated_mode.clear_global_login(s, CREDS_1) is False
        assert (temp_home / ".claude" / ".credentials.json").exists()
        assert "another profile" in capsys.readouterr().out

    def test_an_orphaned_credentials_file_is_a_login(self, temp_home: Path):
        """A failed cleanup leaves the file without the key beside it."""
        s = _switcher()
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_1)

        assert isolated_mode.global_login(s) == {"email": ""}
        notice = isolated_mode.global_login_notice(s)
        assert notice is not None and ".claude/.credentials.json" in notice

    def test_cswap_add_cannot_import_an_orphan(self, temp_home: Path):
        """`cswap add` reads the identity from `~/.claude.json`, so the file
        it cannot see is the one the notice has to tell the user to remove."""
        s = _switcher()
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_1)

        with pytest.raises(ConfigError, match="No active Claude account"):
            s.add_account()

        assert (temp_home / ".claude" / ".credentials.json").exists()
        notice = isolated_mode.global_login_notice(s)
        assert notice is not None
        assert "remove" in notice and "by hand" in notice
        assert "log in again" in notice

    def test_the_orphan_goes_once_add_can_reach_the_cleanup(self, temp_home: Path):
        """Logging in again puts the account beside the file, which is the
        other route the notice names."""
        s = _switcher()
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_1)

        assert isolated_mode.clear_global_login(s, CREDS_1) is True
        assert isolated_mode.global_login(s) is None


# ---------------------------------------------------------------------------
# CSWAP_CLAUDE_BIN: one answer, whitespace included
# ---------------------------------------------------------------------------


class TestTheClaudeBinaryOverride:
    def test_a_whitespace_only_value_refuses_instead_of_searching_path(
        self, temp_home: Path, monkeypatch
    ):
        from claude_swap.session import find_claude

        real = temp_home / "bin" / "claude"
        real.parent.mkdir(parents=True)
        real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        real.chmod(0o755)
        monkeypatch.setenv("CSWAP_CLAUDE_BIN", "   ")
        monkeypatch.setenv("PATH", str(real.parent))

        assert find_claude() is None

    def test_the_refusal_names_the_variable(self, temp_home: Path, monkeypatch):
        from claude_swap.session import SessionManager

        monkeypatch.setenv("CSWAP_CLAUDE_BIN", str(temp_home / "nope" / "claude"))
        manager = SessionManager(_switcher())

        with pytest.raises(SessionError, match="CSWAP_CLAUDE_BIN"):
            manager.run("1", [])


# ---------------------------------------------------------------------------
# The key invariant: nothing outside the record is ever written
# ---------------------------------------------------------------------------


class TestTheInvariantAcrossEverySurface:
    """No launch or switch writes a login — only the record changes.

    Every path that could reach Claude Code's active store is driven at once,
    with those store writes replaced by a raise: a re-base onto upstream that
    restores ``_perform_switch`` or a same-account fast path fails here instead
    of spending a user's refresh token.
    """

    @staticmethod
    def _readonly(name: str):
        def boom(*args, **kwargs):
            raise AssertionError(
                f"{name} was called: a switch or launch wrote a login"
            )

        return patch.object(CredentialStore, name, boom)

    def test_switch_list_status_auto_and_run_write_no_login(self, temp_home: Path):
        from claude_swap import cli
        from claude_swap.autoswitch import AutoSwitchEngine
        from claude_swap.settings import AutoSwitchSettings

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        # A global login is present, so a path that still looked for one would
        # find something to rewrite.
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "a@example.com",
                             "accountUuid": "uuid-1",
                             "organizationUuid": ""},
        }))
        (temp_home / ".claude" / ".credentials.json").write_text(CREDS_1)
        config_path = temp_home / ".claude.json"
        cred_path = temp_home / ".claude" / ".credentials.json"
        before = (config_path.read_bytes(), cred_path.read_bytes())

        manager = MagicMock()
        with patch("claude_swap.oauth.try_fetch_usage_for_account",
                   return_value=oauth.UsageOutcome(None)), \
             self._readonly("_write_credentials"), \
             self._readonly("_write_oauth_credentials"), \
             self._readonly("_write_active_credentials_file"), \
             self._readonly("_update_global_config"), \
             patch("claude_swap.cli._guard_root"), \
             patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager):
            s.switch(json_output=True)                    # `cswap next`
            s.switch(previous=True, json_output=True)     # `cswap prev`
            s.switch_to("2", json_output=True)
            s.list_accounts(json_output=True)
            s.status(json_output=True)
            AutoSwitchEngine(
                s, AutoSwitchSettings(), lambda event: None
            ).tick()                                      # `cswap auto`
            cli._run_launch(_active_args(), [])           # `cswap run --active`

        manager.run.assert_called_once()
        manager.exec_default.assert_not_called()
        assert (config_path.read_bytes(), cred_path.read_bytes()) == before


# ---------------------------------------------------------------------------
# `--active` is wired to the slot's own route, fail-closed
# ---------------------------------------------------------------------------


class _HandedOver(Exception):
    def __init__(self, binary, argv, env):
        self.binary, self.argv, self.env = binary, argv, env


def _manager_with_a_fake_handover(
    monkeypatch, seen: dict, profile: Path
) -> None:
    from claude_swap import session as session_mod

    monkeypatch.setattr(
        session_mod.SessionManager,
        "_check_proxy",
        lambda self, route, who, expectation=None: seen.update(route=route),
    )
    monkeypatch.setattr(session_mod.SessionManager, "_check_egress",
                        lambda *args, **kwargs: None)
    monkeypatch.setattr(
        session_mod.SessionManager,
        "setup_session",
        lambda self, *args, **kwargs: (profile, "1", "a@example.com"),
    )

    def fake_exec(self, binary, args, env):
        raise _HandedOver(binary, [binary, *args], env)

    monkeypatch.setattr(session_mod.SessionManager, "_exec", fake_exec)
    monkeypatch.setattr(
        session_mod.shutil, "which", lambda name: "/fake/bin/claude"
    )


class TestTheActiveLaunchUsesItsOwnRoute:
    def test_the_slots_proxy_is_checked_and_handed_to_claude(
        self, temp_home: Path, monkeypatch
    ):
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        s.set_account_proxy("1", "http://127.0.0.1:3128")
        seen: dict = {}
        _manager_with_a_fake_handover(monkeypatch, seen, temp_home / "profile")

        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(_HandedOver) as excinfo:
                cli._run_launch(_active_args(), ["-p", "hi"])

        assert seen["route"] is not None
        assert excinfo.value.env["HTTPS_PROXY"] == seen["route"].text()
        assert excinfo.value.env["HTTPS_PROXY"].startswith("http://127.0.0.1:")
        # `--active` carries the StopFailure hook for the recorded account.
        assert excinfo.value.argv[1] == "--settings"
        hook = json.loads(excinfo.value.argv[2])["hooks"]["StopFailure"][0]
        assert hook["matcher"] == "rate_limit"
        assert "rate-limited a@example.com" in hook["hooks"][0]["command"]
        assert excinfo.value.argv[3:] == ["-p", "hi"]

    def test_an_account_without_a_proxy_keeps_what_it_inherited(
        self, temp_home: Path, monkeypatch
    ):
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        monkeypatch.setenv("HTTPS_PROXY", "http://inherited:8443")
        seen: dict = {}
        _manager_with_a_fake_handover(monkeypatch, seen, temp_home / "profile")

        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(_HandedOver) as excinfo:
                cli._run_launch(_active_args(), [])

        assert seen["route"] is None
        assert excinfo.value.env["HTTPS_PROXY"] == "http://inherited:8443"

    def test_a_dead_proxy_stops_the_launch_before_claude_starts(
        self, temp_home: Path, monkeypatch, capsys
    ):
        import socket

        from claude_swap import cli
        from claude_swap import session as session_mod

        s = _switcher()
        _seed(s, 1, "a@example.com")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        s.set_account_proxy("1", f"http://127.0.0.1:{port}")

        launched: list = []
        monkeypatch.setattr(
            session_mod.SessionManager, "_exec",
            lambda self, *a, **k: launched.append(a),
        )
        monkeypatch.setattr(
            session_mod.shutil, "which", lambda name: "/fake/bin/claude"
        )

        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(SystemExit) as excinfo:
                cli._run_launch(_active_args(), [])

        assert excinfo.value.code == 1
        assert launched == []
        assert "proxy" in capsys.readouterr().err.lower()

    def test_a_failed_egress_check_stops_the_launch_before_claude_starts(
        self, temp_home: Path, monkeypatch, capsys
    ):
        from claude_swap import cli
        from claude_swap import session as session_mod
        from claude_swap.exceptions import EgressCheckError

        s = _switcher()
        _seed(s, 1, "a@example.com")
        s.set_account_proxy("1", "http://127.0.0.1:3128")

        launched: list = []
        monkeypatch.setattr(
            session_mod.SessionManager,
            "_check_proxy",
            lambda self, route, who, expectation=None: None,
        )
        monkeypatch.setattr(
            session_mod.SessionManager,
            "_check_egress",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                EgressCheckError("the exit country is DE, but US was expected")
            ),
        )
        monkeypatch.setattr(
            session_mod.SessionManager, "_exec",
            lambda self, *a, **k: launched.append(a),
        )
        monkeypatch.setattr(
            session_mod.shutil, "which", lambda name: "/fake/bin/claude"
        )

        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(SystemExit) as excinfo:
                cli._run_launch(_active_args(), [])

        assert excinfo.value.code == 1
        assert launched == []
        assert "exit country" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Claude Code's own commands through the active launch
# ---------------------------------------------------------------------------


class TestClaudeCommandsOnTheActiveLaunch:
    def test_mcp_goes_to_the_shared_profile(self, temp_home: Path):
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        manager = MagicMock()
        tail = ["mcp", "add", "-s", "user", "x", "cmd"]

        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager), \
             patch("claude_swap.cli._guard_root"):
            cli._run_launch(_active_args(), tail)

        manager.exec_default.assert_called_once_with(tail, primary_profile=True)
        manager.run.assert_not_called()

    def test_a_command_that_needs_a_login_runs_on_the_active_slot(
        self, temp_home: Path
    ):
        """`claude auth status` must answer about the active account."""
        from claude_swap import cli

        s = _switcher()
        _seed(s, 1, "a@example.com")
        manager = MagicMock()
        manager.run.side_effect = AssertionError("launch recorded")
        tail = ["auth", "status", "--json"]

        with patch("claude_swap.cli.ClaudeAccountSwitcher", return_value=s), \
             patch("claude_swap.session.SessionManager", return_value=manager), \
             patch("claude_swap.cli._guard_root"):
            with pytest.raises(AssertionError, match="launch recorded"):
                cli._run_launch(_active_args(), tail)

        args, kwargs = manager.run.call_args
        assert args[0] == "1"
        assert args[1] == tail
        assert kwargs["account"] == ("1", "a@example.com", "")
        manager.exec_default.assert_not_called()


# ---------------------------------------------------------------------------
# StopFailure during a launch on the recorded active slot
# ---------------------------------------------------------------------------


class _FakeUsageStore:
    """Cache-only usage store: ``entries`` returns the injected readings."""

    def __init__(self, by_num, now=1000.0):
        self.by_num = by_num
        self._now = now

    def clock(self):
        return self._now

    def entries(self, identities, models=()):
        return {num: self.by_num.get(num, UsageEntry()) for num in identities}


def _headroom_entry(pct, fetched_at=None):
    """A reading with headroom 100-pct (None when pct is None)."""
    if pct is None:
        return UsageEntry()
    return UsageEntry(
        last_good={"five_hour": {"pct": pct}, "seven_day": {"pct": pct}},
        fetched_at=fetched_at,
        age_s=0.0,
    )


def _set_active(s, num):
    data = s._get_sequence_data()
    data["activeAccountNumber"] = num
    s._write_json(s.sequence_file, data)


class TestStopFailureMovesTheActiveSlot:
    def test_moves_to_best_unmarked_headroom(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        _seed(s, 3, "c@example.com")
        _set_active(s, 1)
        # Slot 3 has the most headroom (20% used); 2 is nearly spent.
        s._usage_store = _FakeUsageStore({"2": _headroom_entry(90), "3": _headroom_entry(20)})
        s._stop_failure_marks = lambda: {("a@example.com", ""): 5000.0}

        changed = isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        data = s._get_sequence_data()
        assert changed is True
        assert data["activeAccountNumber"] == 3

    def test_marked_slot_with_stale_high_headroom_is_skipped(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        _seed(s, 3, "c@example.com")
        _set_active(s, 1)
        # 2 looks best (10% used) but its StopFailure mark is newer than its
        # reading; 3 is honest at 40% used.
        marks = {("a@example.com", ""): 5000.0, ("b@example.com", ""): 5000.0}
        s._usage_store = _FakeUsageStore(
            {"2": _headroom_entry(10, fetched_at=1000.0), "3": _headroom_entry(40)}
        )
        s._stop_failure_marks = lambda: marks

        isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert s._get_sequence_data()["activeAccountNumber"] == 3

    def test_reading_newer_than_the_mark_clears_it(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        _seed(s, 3, "c@example.com")
        _set_active(s, 1)
        marks = {("b@example.com", ""): 2000.0}
        s._usage_store = _FakeUsageStore(
            {"2": _headroom_entry(5, fetched_at=3000.0), "3": _headroom_entry(60)}
        )
        s._stop_failure_marks = lambda: marks

        # A reading from after the mark is fresh evidence: 2 wins outright.
        isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert s._get_sequence_data()["activeAccountNumber"] == 2

    def test_empty_usage_cache_rotates_to_next_suitable_slot(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        _seed(s, 3, "c@example.com")
        _set_active(s, 1)
        s._usage_store = _FakeUsageStore({})
        s._stop_failure_marks = lambda: {}

        isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert s._get_sequence_data()["activeAccountNumber"] == 2

    def test_skips_disabled_api_key_and_unprepared_slots(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        _seed(s, 3, "c@example.com")
        _seed(s, 4, "d@example.com")
        _set_active(s, 1)
        data = s._get_sequence_data()
        data["accounts"]["2"]["disabled"] = True
        data["accounts"]["3"]["kind"] = "api_key"
        s._write_json(s.sequence_file, data)
        # slot 4 has no stored config backup → not switchable
        s._config_backup_path("4", "d@example.com").unlink()
        s._usage_store = _FakeUsageStore({})
        s._stop_failure_marks = lambda: {}

        isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert s._get_sequence_data()["activeAccountNumber"] == 1  # nothing usable

    def test_headroom_at_or_below_zero_is_never_picked(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        _seed(s, 3, "c@example.com")
        _set_active(s, 1)
        # 2 is spent (100% used → headroom 0); 3 has no reading at all → the
        # rotation fallback takes 3.
        s._usage_store = _FakeUsageStore({"2": _headroom_entry(100), "3": UsageEntry()})
        s._stop_failure_marks = lambda: {}

        isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert s._get_sequence_data()["activeAccountNumber"] == 3

    def test_no_switch_when_active_already_moved_away(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com")
        _set_active(s, 2)
        s._usage_store = _FakeUsageStore({"1": _headroom_entry(5)})
        s._stop_failure_marks = lambda: {}

        changed = isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert changed is False
        assert s._get_sequence_data()["activeAccountNumber"] == 2

    def test_no_switch_with_a_single_account(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _set_active(s, 1)
        s._usage_store = _FakeUsageStore({})
        s._stop_failure_marks = lambda: {}

        changed = isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert changed is False

    def test_writes_only_sequence_fields_and_prints_nothing(
        self, temp_home: Path, capsys
    ):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _set_active(s, 1)
        before_sequence = json.loads(s.sequence_file.read_text())
        roots = [temp_home / ".claude", s.credentials_dir, s.configs_dir]
        before = {root: _tree(root) for root in roots if root.exists()}
        s._usage_store = _FakeUsageStore({"2": _headroom_entry(30)})
        s._stop_failure_marks = lambda: {}

        changed = isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""
        after = {root: _tree(root) for root in roots if root.exists()}
        assert after == before, "a hook move wrote outside sequence.json"
        after_sequence = json.loads(s.sequence_file.read_text())
        assert after_sequence["activeAccountNumber"] == 2
        diff = {
            k for k in set(before_sequence) | set(after_sequence)
            if before_sequence.get(k) != after_sequence.get(k)
        }
        assert diff <= {"activeAccountNumber", "lastUpdated"}

    def test_record_stop_failure_moves_active_and_marks_the_account(
        self, temp_home: Path, capsys
    ):
        """The hook target writes the mark and moves the recorded active slot.

        Integration through ``record_stop_failure`` itself: the mark lands in
        ``cache/stop-failure.json`` keyed by account, the active slot moves by
        rotation (empty usage cache), and nothing is printed.
        """
        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _set_active(s, 1)
        s._usage_store = _FakeUsageStore({})
        marks_before = s._stop_failure_marks()
        claude_tree_before = _tree(temp_home / ".claude")

        s.record_stop_failure("a@example.com", "")

        data = s._get_sequence_data()
        assert data["activeAccountNumber"] == 2
        assert s._stop_failure_marks() == {("a@example.com", ""): s._usage_store.clock()}
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""
        # The mark file is inside the backup dir — ~/.claude is byte-for-byte untouched.
        assert _tree(temp_home / ".claude") == claude_tree_before


class TestStopFailurePickRules:
    def test_marked_slot_with_oldest_mark_wins_when_all_marked(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _seed(s, 3, "c@example.com")
        _set_active(s, 2)
        # No usage cache: the rotation fallback would apply, but both other
        # slots are marked — slot 1's report is older than slot 3's, so the
        # active slot moves back to slot 1 (its reading, if any, predates the
        # report and is stale evidence either way).
        s._usage_store = _FakeUsageStore({})
        s._stop_failure_marks = lambda: {
            ("a@example.com", ""): 1000.0,
            ("c@example.com", ""): 5000.0,
        }

        changed = isolated_mode.switch_active_after_rate_limit(s, "b@example.com", "")

        assert changed is True
        assert s._get_sequence_data()["activeAccountNumber"] == 1

    def test_unmarked_headroom_tie_breaks_in_rotation_order(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _seed(s, 3, "c@example.com")
        _set_active(s, 3)
        # Slots 1 and 2 have the same cached headroom; 1 comes first in the
        # rotation, so it wins — not 2.
        s._usage_store = _FakeUsageStore(
            {"1": _headroom_entry(30), "2": _headroom_entry(30)}
        )
        s._stop_failure_marks = lambda: {}

        changed = isolated_mode.switch_active_after_rate_limit(s, "c@example.com", "")

        assert changed is True
        assert s._get_sequence_data()["activeAccountNumber"] == 1

    def test_rotation_walk_starts_after_the_active_slot(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _seed(s, 3, "c@example.com")
        _set_active(s, 2)
        # No cached readings anywhere: the fallback walks rotation order
        # starting after the active slot — 3, then 1 — and takes 3.
        s._usage_store = _FakeUsageStore({})
        s._stop_failure_marks = lambda: {}

        changed = isolated_mode.switch_active_after_rate_limit(s, "b@example.com", "")

        assert changed is True
        assert s._get_sequence_data()["activeAccountNumber"] == 3

    def test_credential_less_slot_is_skipped_not_only_config_less(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _seed(s, 3, "c@example.com")
        _seed(s, 4, "d@example.com", CREDS_2)
        _set_active(s, 1)
        # Slot 4 has its config backup but no stored credential → not suitable.
        s._store._backup_enc_path("4", "d@example.com").unlink()
        s._usage_store = _FakeUsageStore({})
        s._stop_failure_marks = lambda: {}

        changed = isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert changed is True
        assert s._get_sequence_data()["activeAccountNumber"] == 2

    def test_exhausted_unmarked_slots_fall_back_to_oldest_marked(self, temp_home: Path):
        from claude_swap import isolated_mode

        s = _switcher()
        _seed(s, 1, "a@example.com")
        _seed(s, 2, "b@example.com", CREDS_2)
        _seed(s, 3, "c@example.com")
        _set_active(s, 1)
        # Slot 2 is unmarked but spent (headroom 0); slot 3 is marked. The
        # marked slot with the oldest report takes over — never the spent one.
        s._usage_store = _FakeUsageStore(
            {"2": _headroom_entry(100), "3": _headroom_entry(5)}
        )
        s._stop_failure_marks = lambda: {("c@example.com", ""): 1000.0}

        changed = isolated_mode.switch_active_after_rate_limit(s, "a@example.com", "")

        assert changed is True
        assert s._get_sequence_data()["activeAccountNumber"] == 3

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
from claude_swap.exceptions import ConfigError, SwitchError
from claude_swap.models import Platform
from claude_swap.switcher import ClaudeAccountSwitcher

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

        assert isolated_mode.clear_global_login(s) is False
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
        assert args[1] == ["--resume"]
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

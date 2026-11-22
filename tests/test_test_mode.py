"""F8 for the cswap entry point and its session auth probe."""

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import cli, paths, session, test_mode


def test_default_mode_reaches_subprocess_without_stand_configuration():
    assert test_mode.active()
    assert test_mode.ENDPOINT not in os.environ
    parent_home = Path.home()
    script = """
from pathlib import Path
import os
from claude_swap import test_mode
assert test_mode.active()
assert test_mode.ENDPOINT not in os.environ
assert Path.home() == Path(os.environ['HOME'])
print(Path.home())
"""
    child = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30,
    )
    assert child.returncode == 0, child.stderr
    assert Path(child.stdout.strip()) == parent_home


@pytest.fixture
def route(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for key in tuple(os.environ):
        if key.upper().endswith("_PROXY") or key.startswith("CLAUDE_SWAP_TEST_"):
            monkeypatch.delenv(key)
    monkeypatch.delenv("CLAUDE_SWAP_BYPASS", raising=False)
    fake = tmp_path / ("claude.exe" if sys.platform == "win32" else "claude")
    fake.touch()
    managed = tmp_path / "managed-settings.json"
    monkeypatch.setattr(test_mode, "_managed_settings", lambda: managed)
    monkeypatch.setattr(test_mode.shutil, "which", lambda name: str(fake))
    values = {
        test_mode.MODE: "1",
        test_mode.ENDPOINT: "https://api.mock.example",
        test_mode.CLAUDE_BASE: "https://api.mock.example",
        test_mode.PROXY: "http://127.0.0.1:18080",
        test_mode.ALLOW: str(fake),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return fake, managed, values


@pytest.fixture
def no_attempts(monkeypatch):
    attempts = []

    def reject(*args, **kwargs):
        attempts.append(None)
        pytest.fail("configuration refusal attempted network or process creation")

    for name in ("socket", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, reject)
    monkeypatch.setattr(subprocess, "Popen", reject)
    monkeypatch.setattr(os, "execvpe", reject)
    monkeypatch.setattr(os, "posix_spawn", reject, raising=False)
    yield
    assert not attempts


def _check_cli(monkeypatch, capsys, args, clue):
    monkeypatch.setattr(sys, "argv", ["cswap", *args])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 4
    stderr = capsys.readouterr().err
    assert "TestModeConfigError" in stderr
    assert clue in stderr
    return stderr


@pytest.mark.parametrize("key,value", [
    (test_mode.ENDPOINT, None),
    (test_mode.ENDPOINT, "https://127.0.0.1"),
    (test_mode.ENDPOINT, "https://service.example.org"),
    (test_mode.CLAUDE_BASE, None),
    (test_mode.CLAUDE_BASE, "https://[::1]"),
    (test_mode.CLAUDE_BASE, "https://example.org"),
    (test_mode.PROXY, "http://proxy.example:18080"),
    ("ALL_PROXY", "http://192.0.2.1:18080"),
    (test_mode.ALLOW, ""),
    (test_mode.CA, "not-a-test-ca.pem"),
    ("CLAUDE_SWAP_BYPASS", "1"),
])
def test_f8_rejects_configuration(route, no_attempts, monkeypatch, capsys, key, value):
    if value is None:
        monkeypatch.delenv(key)
    else:
        monkeypatch.setenv(key, value)
    _check_cli(monkeypatch, capsys, ["run", "1"], key)


@pytest.mark.parametrize("source", ["user", "project", "local", "managed"])
def test_f8_rejects_lower_layer(route, no_attempts, monkeypatch, capsys, source):
    _, managed, _ = route
    file = {
        "user": paths.get_claude_config_home() / "settings.json",
        "project": Path.cwd() / ".claude" / "settings.json",
        "local": Path.cwd() / ".claude" / "settings.local.json",
        "managed": managed,
    }[source]
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps({"env": {"HTTPS_PROXY": "never-log-this"}}))
    stderr = _check_cli(monkeypatch, capsys, ["run", "1"], f"{file}: env.HTTPS_PROXY")
    assert "never-log-this" not in stderr


@pytest.mark.parametrize("args,clue", [
    (["run"], "explicit account"),
    (["run", "1", "--", "--settings", "{}"], "--settings"),
    (["run", "1", "--", "--settings={}"], "--settings"),
    (["run", "1", "--", "auth", "status"], "auth"),
    (["run", "1", "--", "update"], "update"),
    (["run", "1", "--", "-p", "update"], "update"),
    (["run", "1", "--", "--print", "mcp"], "mcp"),
    (["run", "1", "--", "-p", "auth"], "auth"),
    (["run", "1", "--", "-p", "install"], "install"),
    (["run", "1", "--", "-p", "other-command"], "unknown"),
    (["run", "1", "--", "--print", "--output-format", "json", "update"], "update"),
    (["run", "1", "--", "-p", "synthetic prompt", "update"], "update"),
    (["run", "1", "--", "update", "-p", "synthetic prompt"], "update"),
    (["run", "1", "--", "other-command"], "unknown"),
    (["update"], "update"),
])
def test_f8_rejects_invocation_forms(route, no_attempts, monkeypatch, capsys, args, clue):
    _check_cli(monkeypatch, capsys, args, clue)


@pytest.mark.parametrize("args", [
    ["--resume"],
    ["--resume", "synthetic-session"],
    ["--print", "--output-format", "json", "synthetic prompt"],
])
def test_f8_accepts_stand_client_forms(route, no_attempts, args):
    assert test_mode.check_launch(args) == str(route[0])


def test_f8_cold_profile_pins_auth_probe_and_launch(route, monkeypatch):
    fake, _, values = route
    backup = paths.get_backup_root()
    profile = session.session_dir_for(backup, "1", "synthetic@example.test")
    switcher = SimpleNamespace(
        backup_dir=backup, _logger=None, lock_file=backup / ".lock",
        resolve_account=lambda _: ("1", "synthetic@example.test", ""),
        _account_kind=lambda _: "oauth",
        _get_current_account=lambda: None,
        read_account_credentials=lambda *_: None,
    )
    backup.mkdir(parents=True)
    manager = session.SessionManager(switcher)
    monkeypatch.setattr(manager, "_bootstrap", lambda d, *_: d.mkdir(parents=True))
    monkeypatch.setattr(manager, "_sync_sharing", lambda *_: None)
    calls = []

    def record(binary, args, env):
        assert binary == str(fake)
        assert args[0] == "--settings"
        pinned = {key: values[key] for key in (test_mode.CLAUDE_BASE, test_mode.PROXY)}
        assert json.loads(args[1]) == {"env": pinned}
        assert Path(env["CLAUDE_CONFIG_DIR"]) == profile
        assert "NO_PROXY" not in env
        assert "ANTHROPIC_API_KEY" not in env
        calls.append(args[2:])

    def probe(argv, *, env, **kwargs):
        record(argv[0], argv[1:], env)
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "loggedIn": True, "authMethod": "claude.ai", "email": "synthetic@example.test",
        }))

    class Finished(Exception):
        pass

    def launch(binary, argv, env):
        record(binary, argv[1:], env)
        raise Finished

    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic")
    monkeypatch.setattr(session.spawn, "run", probe)
    if sys.platform == "win32":
        monkeypatch.setattr(session.subprocess, "run", lambda argv, env: launch(argv[0], argv, env))
    else:
        monkeypatch.setattr(os, "execvpe", launch)
    assert not profile.exists()
    with pytest.raises(Finished):
        manager.run("1", ["-p", "synthetic prompt"])
    assert calls == [["auth", "status", "--json"], ["-p", "synthetic prompt"]]


def test_f8_transport_refuses_missing_test_ca_before_dial(route, no_attempts):
    from urllib.request import Request

    endpoint = route[2][test_mode.ENDPOINT]
    with pytest.raises(test_mode.TestModeConfigError, match=test_mode.CA):
        test_mode.open_service(Request(endpoint + "/probe"), timeout=1)


def test_f8_transport_refuses_wrong_origin_before_dial(route, no_attempts):
    from urllib.request import Request

    with pytest.raises(test_mode.TestModeConfigError, match=test_mode.ENDPOINT):
        test_mode.open_service(Request("https://not-the-configured-origin.invalid"), timeout=1)


def test_f8_probe_refuses_profile_with_route_override(route, no_attempts, monkeypatch, capsys):
    profile = Path.cwd() / "cold"
    profile.mkdir()
    settings = profile / "settings.json"
    settings.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "invalid"}}))
    manager = session.SessionManager(SimpleNamespace(backup_dir=Path.cwd(), _logger=None))
    monkeypatch.setattr(cli, "ClaudeAccountSwitcher", lambda **_: object())
    monkeypatch.setattr(cli, "_guard_root", lambda _: None)
    monkeypatch.setattr(session, "SessionManager", lambda _: SimpleNamespace(
        run=lambda *args, **kwargs: manager._session_validity(profile, "synthetic@example.test", ""),
    ))
    _check_cli(monkeypatch, capsys, ["run", "1"], f"{settings}: env.ANTHROPIC_BASE_URL")

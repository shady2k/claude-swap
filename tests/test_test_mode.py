"""F8 for the cswap entry point and its session auth probe."""

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import cli, launch_policy, paths, real_claude, session, test_mode


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
    monkeypatch.setattr(real_claude, "resolve", lambda **_: SimpleNamespace(path=fake))
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
    monkeypatch.setattr(os, "execve", reject)
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
@pytest.mark.parametrize("key", ["HTTPS_PROXY", "CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR"])
def test_f8_rejects_lower_layer(route, no_attempts, monkeypatch, capsys, source, key):
    _, managed, _ = route
    file = {
        "user": paths.get_claude_config_home() / "settings.json",
        "project": Path.cwd() / ".claude" / "settings.json",
        "local": Path.cwd() / ".claude" / "settings.local.json",
        "managed": managed,
    }[source]
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps({"env": {key: "never-log-this"}}))
    stderr = _check_cli(monkeypatch, capsys, ["run", "1"], f"{file}: env.{key}")
    assert "never-log-this" not in stderr


@pytest.mark.parametrize("args,clue", [
    (["run"], "explicit account"),
    (["run", "1", "--", "--settings", "{}"], "--settings"),
    (["run", "1", "--", "--settings={}"], "--settings"),
    (["run", "1", "--", "--setting-sources=user"], "--setting-sources"),
    (["run", "1", "--", "--not-supported=value"], "--not-supported"),
    (["run", "1", "--", "auth", "status"], "auth"),
    (["run", "1", "--", "update"], "update"),
    (["run", "1", "--", "-p", "update"], "update"),
    (["run", "1", "--", "--print", "mcp"], "mcp"),
    (["run", "1", "--", "-p", "auth"], "auth"),
    (["run", "1", "--", "-p", "install"], "install"),
    (["run", "1", "--", "--print", "--output-format", "json", "update"], "update"),
    (["run", "1", "--", "-p", "synthetic prompt", "update"], "update"),
    (["run", "1", "--", "update", "-p", "synthetic prompt"], "update"),
    (["run", "1", "--", "other-command"], "other-command"),
    (["update"], "update"),
])
def test_f8_rejects_invocation_forms(route, no_attempts, monkeypatch, capsys, args, clue):
    _check_cli(monkeypatch, capsys, args, clue)


@pytest.mark.parametrize("args", [
    ["--resume"],
    ["--resume", "synthetic-session"],
    ["--print", "--output-format", "json", "synthetic prompt"],
    ["--model", "auth", "synthetic prompt"],
    ["-p", "oneword"],
    ["--print", "--", "oneword"],
    ["synthetic prompt"],
])
def test_f8_accepts_stand_client_forms(route, no_attempts, args):
    assert test_mode.check_launch(args).path == route[0]


def test_preflight_binary_can_be_reused_for_checked_launch(route, no_attempts, monkeypatch):
    binary = SimpleNamespace(path=route[0])
    calls = []

    def resolve(**kwargs):
        calls.append(kwargs)
        return binary

    monkeypatch.setattr(real_claude, "resolve", resolve)
    tail = ["-p", "hello"]
    checked = test_mode.preflight(["run", "1", "--", *tail])
    assert checked is binary
    assert test_mode.check_launch(tail, binary=checked) is binary
    assert len(calls) == 1


@pytest.mark.parametrize("verb", ["enable", "status", "disable", "pool", "revoke-shared-history"])
def test_transparent_admin_checks_route_without_resolving_claude(route, no_attempts, monkeypatch, verb):
    def cannot_resolve(**kwargs):
        pytest.fail("admin preflight should not resolve claude")

    monkeypatch.setattr(real_claude, "resolve", cannot_resolve)
    test_mode.preflight(["transparent", verb])
    monkeypatch.delenv(test_mode.ENDPOINT)
    with pytest.raises(test_mode.TestModeConfigError, match=test_mode.ENDPOINT):
        test_mode.preflight(["transparent", verb])


def test_transparent_pool_and_revoke_cli_do_not_use_network(
    route, no_attempts, monkeypatch, capsys, private_backup_root,
):
    root = private_backup_root
    members = {slot: [f"account{slot}@example.test", "", slot, "oauth"] for slot in ("1", "2")}

    def seed(policy):
        policy.update(enabled=True, pool=["1", "2"], historyZone={
            "scope": launch_policy.HISTORY_SCOPE, "members": members,
        })
        return True

    launch_policy.update(root, seed)
    monkeypatch.setattr(sys, "argv", ["cswap", "transparent", "pool", "--account", "2"])
    cli.main()
    assert "pool updated" in capsys.readouterr().out
    policy = launch_policy.read(root)
    assert policy["pool"] == ["2"]
    assert policy["historyZone"]["members"] == {"2": members["2"]}
    monkeypatch.setattr(sys, "argv", ["cswap", "transparent", "revoke-shared-history"])
    cli.main()
    assert "consent revoked" in capsys.readouterr().out
    policy = launch_policy.read(root)
    assert policy["pool"] == ["2"]
    assert "historyZone" not in policy


def test_f8_cold_profile_pins_auth_probe_and_launch(route, monkeypatch):
    from claude_swap import profile_ownership as ownership

    # This test owns argument pinning at a synthetic handoff boundary.
    monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
        "present", ownership._PosixStart(f"synthetic-{pid}"), "synthetic",
    ))
    fake, _, values = route
    backup = paths.get_backup_root()
    profile = session.session_dir_for(backup, "1", "synthetic@example.test")
    switcher = SimpleNamespace(
        backup_dir=backup, _logger=None, lock_file=backup / ".lock",
        resolve_account=lambda _: ("1", "synthetic@example.test", ""),
        _account_kind=lambda _: "oauth",
        _get_current_account=lambda: None,
        read_account_credentials=lambda *_: None,
        _get_sequence_data=lambda: {"accounts": {"1": {
            "email": "synthetic@example.test", "uuid": "synthetic-uuid",
        }}},
    )
    backup.mkdir(parents=True)
    manager = session.SessionManager(switcher)
    monkeypatch.setattr(manager, "_bootstrap", lambda d, *_: d.mkdir(parents=True))
    monkeypatch.setattr(manager, "_sync_sharing", lambda *_: None)
    calls = []

    def record(args, env):
        assert args[0] == "--settings"
        pinned = {key: values[key] for key in (test_mode.CLAUDE_BASE, test_mode.PROXY)}
        assert json.loads(args[1]) == {"env": pinned}
        assert Path(env["CLAUDE_CONFIG_DIR"]) == profile
        assert "NO_PROXY" not in env
        assert "ANTHROPIC_API_KEY" not in env
        calls.append(args[2:])

    def probe(args, *, env, **kwargs):
        record(args, env)
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "loggedIn": True, "authMethod": "claude.ai", "email": "synthetic@example.test",
        }))

    class Finished(Exception):
        pass

    def launch(args, env, **kwargs):
        record(args, env)
        raise Finished

    binary = SimpleNamespace(path=fake, run=probe, handoff=launch)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic")
    monkeypatch.setattr(real_claude, "resolve", lambda **_: binary)
    monkeypatch.setattr(session.spawn, "require_supervision", lambda: None)
    def owned_launch(callback, *, publish, release, abort):
        publish()
        result = callback()
        release()
        return result
    monkeypatch.setattr(session.spawn, "owned_launch", owned_launch)
    assert not profile.exists()
    with pytest.raises(Finished):
        manager.run("1", ["-p", "synthetic prompt"])
    assert calls == [["auth", "status", "--json"], ["-p", "synthetic prompt"]]


def test_proxy_userinfo_is_only_in_child_environment(route, monkeypatch):
    proxy = "http://stand-user:stand%2Dpassword@127.0.0.1:18080"
    monkeypatch.setenv(test_mode.PROXY, proxy)
    args, env = test_mode.pinned_launch(["--print", "synthetic prompt"], {})
    assert env[test_mode.PROXY] == proxy
    assert json.loads(args[1]) == {"env": {test_mode.CLAUDE_BASE: route[2][test_mode.CLAUDE_BASE]}}
    assert "stand-user" not in " ".join(args)
    assert "stand%2Dpassword" not in " ".join(args)
    if sys.platform == "linux":
        # Split the marker so the assertion itself does not put it in argv.
        script = (
            "from pathlib import Path; argv = Path('/proc/self/cmdline').read_bytes(); "
            "assert b'stand-' b'user' not in argv and b'stand%2D' b'password' not in argv"
        )
        proc = subprocess.run([sys.executable, "-c", script, *args], env=env, capture_output=True)
        assert proc.returncode == 0, proc.stderr


@pytest.fixture
def direct_route(route, monkeypatch, tmp_path):
    endpoint = "https://api.mock.example:19443"
    ca = tmp_path / "stand-ca.pem"
    ca.touch()
    for key, value in {
        test_mode.ENDPOINT: endpoint, test_mode.CLAUDE_BASE: endpoint,
        test_mode.DIRECT: "127.0.0.1:19443", test_mode.CA: str(ca),
    }.items():
        monkeypatch.setenv(key, value)
    return endpoint


@pytest.mark.parametrize("address", ["127.0.0.1:19444", "192.0.2.1:19443"])
def test_f34_direct_rejects_off_route_address_before_dial(direct_route, no_attempts, monkeypatch, address):
    from urllib.request import Request

    monkeypatch.setenv(test_mode.DIRECT, address)
    with pytest.raises(test_mode.TestModeConfigError, match=test_mode.DIRECT):
        test_mode.open_service(Request(direct_route + "/probe"), timeout=1)


@pytest.mark.skipif(sys.platform != "linux", reason="direct test routing is Linux-only")
def test_f34_direct_discards_inherited_proxies(direct_route, no_attempts, monkeypatch):
    proxy = "http://unusable.invalid:18080"
    monkeypatch.setenv(test_mode.PROXY, proxy)
    assert test_mode.check_launch(["-p", "synthetic prompt"])
    args, env = test_mode.pinned_launch([], {
        "HTTPS_PROXY": proxy, "http_proxy": proxy, "ALL_proxy": proxy, "No_Proxy": "*",
    })
    assert env == {
        test_mode.CLAUDE_BASE: direct_route,
        test_mode.DIRECT: "127.0.0.1:19443",
        "NODE_EXTRA_CA_CERTS": os.environ[test_mode.CA],
    }
    assert json.loads(args[1])["env"] == env


def test_f34_direct_refuses_other_platforms(direct_route, no_attempts, monkeypatch):
    monkeypatch.setattr(test_mode, "sys", SimpleNamespace(**(vars(sys) | {"platform": "darwin"})))
    with pytest.raises(test_mode.TestModeConfigError, match="Linux stand"):
        test_mode.preflight(["--version"])


@pytest.mark.skipif(sys.platform != "linux", reason="direct test routing is Linux-only")
def test_f34_direct_refuses_managed_proxy_override(direct_route, no_attempts, route):
    managed = route[1]
    managed.write_text(json.dumps({"env": {"https_proxy": "http://127.0.0.1:18080"}}))
    with pytest.raises(test_mode.TestModeConfigError, match=r"env\.https_proxy"):
        test_mode.check_launch(["-p", "synthetic prompt"])


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

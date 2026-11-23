"""Exercise the installed shim with a synthetic Claude and no network."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from claude_swap import paths, test_mode, transparent
from claude_swap.settings import set_setting

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="requires the POSIX PATH shim")


@pytest.fixture
def installed(tmp_path, monkeypatch):
    root = paths.get_backup_root()
    programs = tmp_path / "bin"
    programs.mkdir()
    fake = programs / "claude"
    fake.write_text(
        f"#!{sys.executable} -I\n"
        "import json, os, signal, sys\n"
        "if sys.argv[-1] == 'wait for signal':\n"
        "    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})\n"
        "    os.write(1, b'ready\\n')\n"
        "    signal.sigwait({signal.SIGTERM})\n"
        "    os.write(1, b'term')\n"
        "    raise SystemExit(42)\n"
        "sys.stdout.buffer.write(json.dumps(sys.argv[1:]).encode() + b'\\n')\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n"
        "sys.stderr.buffer.write(b'\\xd1\\x00diagnostic')\n"
        "raise SystemExit(27)\n"
    )
    fake.chmod(0o700)
    monkeypatch.setenv(test_mode.MODE, "1")
    monkeypatch.setenv(test_mode.ENDPOINT, "https://usage.test")
    monkeypatch.setenv(test_mode.CLAUDE_BASE, "https://claude.test")
    monkeypatch.setenv(test_mode.PROXY, "http://127.0.0.1:21980")
    monkeypatch.setenv(test_mode.ALLOW, str(fake))
    for key in ("ALL_PROXY", "HTTP_PROXY", "all_proxy", "http_proxy", "https_proxy"):
        monkeypatch.delenv(key, raising=False)
    from claude_swap.session import session_dir_for

    email, uuid = "profile@example.test", "fake-profile"
    profile = session_dir_for(root, "1", email)
    profile.mkdir(parents=True, mode=0o700)
    (root / "sequence.json").write_text(json.dumps({"accounts": {"1": {"email": email, "uuid": uuid}}}))
    (profile / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": email, "accountUuid": uuid}}))
    shim = paths.get_shim_dir(root)
    monkeypatch.setenv("PATH", f"{shim}{os.pathsep}{programs}")
    return root, shim, fake


def invoke(*args, **kwargs):
    return subprocess.run(["claude", *args], capture_output=True, input=b"\x00\xff\r\n", **kwargs)


def test_f9_lifecycle_argv_streams_exit_and_launch_count(installed):
    root, shim, fake = installed
    expected_hash = hashlib.sha256(fake.read_bytes()).digest()
    args = ["--model", "auth", "-p", "--", 'quoted \"text\"', "", "--settings=prompt text"]
    baseline = invoke(*args)
    assert baseline.returncode == 27
    assert transparent.enable(root, accept_shared_history=True, pool=["1"]) == shim
    assert any("first on PATH" in line for line in transparent.status(root))
    result = invoke(*args)
    assert result.returncode == baseline.returncode
    first, body = result.stdout.split(b"\n", 1)
    original, original_body = baseline.stdout.split(b"\n", 1)
    flag, layer, *forwarded = json.loads(first)
    assert flag == "--settings"
    assert json.loads(Path(layer).read_text())["env"][test_mode.CLAUDE_BASE] == "https://claude.test"
    assert forwarded == json.loads(original) == args
    assert body == original_body == b"\x00\xff\r\n"
    assert result.stderr == baseline.stderr == b"\xd1\x00diagnostic"
    assert "Shim launches (last 24 hours): 1" in transparent.status(root)
    transparent.disable(root)
    transparent.disable(root)
    assert not (shim / "claude").exists()
    assert invoke(*args).stdout == baseline.stdout
    assert hashlib.sha256(fake.read_bytes()).digest() == expected_hash


def test_enable_refuses_group_writable_shim_directory(installed):
    root, shim, _ = installed
    shim.mkdir(parents=True)
    shim.chmod(0o770)
    with pytest.raises(transparent.fsguard.GuardError, match="Writable"):
        transparent.enable(root, accept_shared_history=True, pool=["1"])
    assert not (shim / "claude").exists()


def test_f9_sigterm_reaches_same_pid(installed):
    root, _, _ = installed
    transparent.enable(root, accept_shared_history=True, pool=["1"])
    with subprocess.Popen(["claude", "-p", "wait for signal"], stdout=subprocess.PIPE) as child:
        try:
            import select

            assert select.select([child.stdout], [], [], 10)[0]
            assert child.stdout.readline() == b"ready\n"
            child.send_signal(signal.SIGTERM)
            assert child.communicate(timeout=10)[0] == b"term"
            assert child.returncode == 42
        finally:
            if child.poll() is None:
                child.kill()


def test_f4_only_shim_and_explicit_shim_refuse_without_recursion(installed, monkeypatch):
    root, shim, _ = installed
    transparent.enable(root, accept_shared_history=True, pool=["1"])
    monkeypatch.setenv("PATH", os.pathsep.join((str(shim), str(shim))))
    # Measure separately from the parallel suite so scheduler delays from
    # other tests do not count against the launch budget.
    check_latency = os.environ.get("CSWAP_TEST_SHIM_LATENCY") == "1"
    for case, override in (("repeated PATH shim only", None), ("explicit shim path", shim / "claude")):
        if override is not None:
            set_setting(root, "transparent.claudePath", str(override))
        start = time.monotonic()
        result = invoke("-p", "test recursion", timeout=10)
        elapsed = time.monotonic() - start
        assert result.returncode == 4
        if check_latency:
            print(f"F4 {case}: exit {result.returncode} in {elapsed:.3f} s")
            assert elapsed < 1
        assert b"claude" in result.stderr.lower()
        assert not result.stdout


def test_f28_cwd_pythonpath_and_loader_controls(installed, monkeypatch, tmp_path):
    root, _, _ = installed
    transparent.enable(root, accept_shared_history=True, pool=["1"])
    for name in ("json.py", "claude_swap.py"):
        (tmp_path / name).write_text("raise RuntimeError('client code imported')\n")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    assert invoke("-p", "test this", cwd=tmp_path).returncode == 27
    set_setting(root, "transparent.requireProxy", "true")
    assert invoke("-p", "test this").returncode == 4
    transparent.refresh_install(root)
    monkeypatch.setenv("LD_PRELOAD", "")
    monkeypatch.delenv(test_mode.ENDPOINT)
    refusal = invoke("-p", "test this")
    assert refusal.returncode == 4
    assert b"loader environment" in refusal.stderr
    assert test_mode.ENDPOINT.encode() not in refusal.stderr


@pytest.mark.parametrize("args", [("auth", "status"), ("future-subcommand",)])
def test_f22_optional_bypass_and_strict_refusal(installed, monkeypatch, args):
    root, _, fake = installed
    # Keep the suite-wide test route intact for normal subprocesses. Only this
    # synthetic no-socket fake exercises the production policy branches.
    monkeypatch.delenv(test_mode.MODE)
    set_setting(root, "transparent.claudePath", str(fake))
    baseline = subprocess.run([str(fake), *args], capture_output=True, input=b"\x00\xff\r\n")
    transparent.enable(root, accept_shared_history=True, pool=["1"])
    result = invoke(*args)
    assert result.returncode == baseline.returncode == 27
    assert result.stdout == baseline.stdout
    notice, _, stderr = result.stderr.partition(b"\n")
    assert b"outside the profile route" in notice
    assert stderr == baseline.stderr
    set_setting(root, "transparent.requireProxy", "true")
    transparent.refresh_install(root)
    refusal = invoke(*args)
    assert refusal.returncode == 4
    assert not refusal.stdout
    assert args[0].encode() in refusal.stderr


@pytest.mark.parametrize("args", [
    ("--settings", "a", "--settings", "b"),
    ("--verbose", "--settings", "a"),
])
def test_f22_explicit_bypass_precedes_form_validation(installed, monkeypatch, args):
    root, _, fake = installed
    monkeypatch.delenv(test_mode.MODE)
    set_setting(root, "transparent.claudePath", str(fake))
    transparent.enable(root, accept_shared_history=True, pool=["1"])

    refusal = invoke(*args)
    assert refusal.returncode == 4
    assert b"--settings" in refusal.stderr

    monkeypatch.setenv("CLAUDE_SWAP_BYPASS", "1")
    result = invoke(*args)
    assert result.returncode == 27
    argv, body = result.stdout.split(b"\n", 1)
    assert json.loads(argv) == list(args)
    assert body == b"\x00\xff\r\n"
    assert b"outside the profile route: CLAUDE_SWAP_BYPASS" in result.stderr


def test_disable_does_not_delete_replaced_launcher(installed):
    root, shim, _ = installed
    transparent.enable(root, accept_shared_history=True, pool=["1"])
    launcher = shim / "claude"
    launcher.write_bytes(b"someone else's file")
    with pytest.raises(transparent.ConfigError, match="installed shim"):
        transparent.disable(root)
    assert launcher.read_bytes() == b"someone else's file"

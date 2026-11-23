"""Controls for the portable stand; none requires a network namespace."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

from tests.stand_audit import StandAudit


def _script(tmp_path, name, source):
    path = tmp_path / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


@pytest.mark.parametrize("reason", ["flags", "interpreter", "script", "environment", "environment-with-venv-launcher"])
def test_startup_refusal_reports_only_a_fixed_reason(tmp_path, reason):
    stand = StandAudit(tmp_path)
    canary = "private-startup-canary"
    script = _script(tmp_path, f"{canary}.py", "print('script ran')")
    stand.allow(script)
    flags = ["-I"]
    env = stand.env
    if reason == "flags":
        flags = ["-E", "-s"]
    elif reason == "interpreter":
        policy = json.loads(stand._policy.read_text(encoding="utf-8"))
        policy["python"] = str(tmp_path / canary)
        stand._policy.write_text(json.dumps(policy), encoding="utf-8")
    elif reason == "script":
        script.write_text("print('changed script ran')", encoding="utf-8")
    elif reason == "environment":
        env["EXTRA_TEST_VARIABLE"] = canary
    else:
        # CPython consumes __PYVENV_LAUNCHER__ before sitecustomize. Simulate
        # it being visible at the environment check without affecting getpath.
        stand._policy.with_name("synthetic_launcher.pth").write_text(
            f"import os; os.environ['__PYVENV_LAUNCHER__'] = {canary!r}\n", encoding="utf-8",
        )
    result = subprocess.run(
        [str(stand.python), *flags, str(script), canary], cwd=stand.cwd, env=env,
        close_fds=True, stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 125
    assert not result.stdout
    assert result.stderr.strip() == f"no-network stand could not establish audited startup: {reason}"
    with pytest.raises(AssertionError, match=f"^stand blocked startup: {reason}$"):
        stand.assert_clean()
    blocked, = stand.records()
    assert isinstance(blocked.pop("pid"), int)
    assert blocked == {"kind": "blocked", "event": "startup", "reason": reason}
    assert canary not in stand.journal.read_text(encoding="utf-8")


def test_f20_audited_python_process_tree_uses_only_temporary_state(tmp_path, monkeypatch):
    secret = "synthetic-not-in-inherited-environment"
    for var in ("ANTHROPIC_API_KEY", "HTTPS_PROXY", "PYTHONPATH", "PYTHONHOME",
                "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "CLAUDE_SECURESTORAGE_CONFIG_DIR"):
        monkeypatch.setenv(var, secret)
    stand = StandAudit(tmp_path)
    grandchild = stand.allow(_script(tmp_path, "grandchild.py", """
        import os
        import sys
        from pathlib import Path
        from claude_swap import paths

        assert sys.flags.isolated
        assert sys.flags.no_user_site
        assert sys.flags.ignore_environment
        assert not any(name in os.environ for name in (
            "ANTHROPIC_API_KEY", "HTTPS_PROXY", "PYTHONPATH", "PYTHONHOME",
            "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "CLAUDE_SECURESTORAGE_CONFIG_DIR",
        ))
        home = Path(os.environ["HOME"])
        assert Path.home() == home
        assert paths.get_claude_config_home().is_relative_to(home.parent)
        assert paths.get_backup_root().is_relative_to(home.parent)
        if os.name == "nt":
            try:
                os_handle = int(sys.argv[1])
                os.get_handle_inheritable(os_handle)
            except OSError:
                pass
            else:
                raise AssertionError("inheritable Windows handle was passed")
        else:
            fd = int(sys.argv[1])
            try:
                fd_stat = os.fstat(fd)
            except OSError:
                pass
            else:
                assert not os.path.samestat(fd_stat, Path(sys.argv[2]).stat())
        print("grandchild reached")
    """))
    child = _script(tmp_path, "child.py", """
        import subprocess
        import sys

        subprocess.run([sys.executable, "-I", *sys.argv[1:]], check=True)
    """)
    probe_path = tmp_path / "fd-probe"
    with probe_path.open("wb") as probe:
        os.set_inheritable(probe.fileno(), True)
        fd = probe.fileno()
        if os.name == "nt":
            import msvcrt

            fd = msvcrt.get_osfhandle(fd)
            assert os.get_handle_inheritable(fd)
        result = stand.run(child, str(grandchild), str(fd), str(probe_path))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "grandchild reached"
    started = [r for r in stand.records() if r["kind"] == "startup"]
    assert len(started) == 2 and len({r["pid"] for r in started}) == 2
    assert all(r["isolated"] for r in started)


@pytest.mark.parametrize(("call", "event", "target"), [
    ("socket.getaddrinfo(sys.argv[1], 443)", "socket.getaddrinfo", "audit-escape.invalid"),
    ("socket.socket().connect((sys.argv[1], 443))", "socket.connect", "192.0.2.1"),
])
def test_f17v_blocked_escape_in_grandchild_is_a_detected_attempt(tmp_path, call, event, target):
    stand = StandAudit(tmp_path, probe_socket_operations=True)
    grandchild = stand.allow(_script(tmp_path, "escape.py", f"""
        import socket
        import sys

        try:
            {call}
        except BaseException:
            # Report the attempt even when a caller suppresses the refusal and
            # the root process otherwise exits successfully.
            pass
    """))
    child = _script(tmp_path, "child.py", """
        import subprocess
        import sys

        subprocess.run([sys.executable, "-I", *sys.argv[1:]], check=True)
    """)
    result = stand.run(child, str(grandchild), target, check_audit=False)
    assert result.returncode == 0, result.stderr
    records = stand.records()
    assert [r["kind"] for r in records] == ["startup", "spawn", "startup", "blocked"]
    assert records[-1]["event"] == event
    assert records[-1]["pid"] == records[-2]["pid"] != records[0]["pid"]
    assert target not in stand.journal.read_text(encoding="utf-8")
    with pytest.raises(AssertionError, match="stand blocked"):
        stand.assert_clean()


@pytest.mark.skipif(os.name == "nt", reason="Windows shim not admitted before launcher verification")
@pytest.mark.parametrize(("call", "event"), [
    ("print('synthetic Claude')", None),
    ("socket.socket(socket.AF_INET, socket.SOCK_DGRAM).bind(('127.0.0.1', 0))", "socket.bind"),
    ("socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'data', ('127.0.0.1', 9))", "socket.sendto"),
    ("socket.socket().connect(('192.0.2.1', 443))", "socket.connect"),
    ("socket.getaddrinfo('audit-escape.invalid', 443)", "socket.getaddrinfo"),
    ("subprocess.Popen(['/not-allowlisted', 'probe'])", "subprocess.Popen"),
])
def test_f20_audits_plain_claude_through_the_installed_shim(tmp_path, call, event):
    stand = StandAudit(tmp_path, probe_socket_operations=True)
    installer = _script(tmp_path, "installer.py", """
        import runpy
        import sys

        sys.argv[:] = ["cswap", "transparent", "enable", "--accept-shared-history", "--account", "1"]
        runpy.run_module("claude_swap", run_name="__main__", alter_sys=True)
    """)
    result = stand.run_shim(installer, "import socket, subprocess\n" + call, "--", "prompt")
    records = stand.records()
    assert [r["kind"] for r in records[:4]] == ["startup", "startup", "exec", "startup"], result.stderr
    assert records[1]["pid"] == records[2]["pid"] == records[3]["pid"]
    if event is None:
        stand.assert_clean()
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "synthetic Claude" and not result.stderr
    else:
        assert result.returncode != 0 and not result.stdout
        assert records[-1]["event"] == event
        with pytest.raises(AssertionError, match="stand blocked"):
            stand.assert_clean()


@pytest.mark.parametrize(("call", "event"), [
    ("socket.socket()", "socket.__new__"),
    ("socket.socket(socket.AF_INET, socket.SOCK_DGRAM).bind(('127.0.0.1', 0))", "socket.bind"),
    ("socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'data', ('127.0.0.1', 9))", "socket.sendto"),
    ("subprocess.Popen([sys.executable, '-I', '-c', 'raise SystemExit(99)'])", "subprocess.Popen"),
    ("subprocess.Popen([sys.executable, '-I', '-S', sys.argv[0]])", "subprocess.Popen"),
    ("subprocess.Popen([sys.executable, '-I', sys.argv[2]])", "subprocess.Popen"),
    ("subprocess.Popen([sys.executable, '-I', sys.argv[0]], close_fds=False)", "subprocess.Popen"),
    ("subprocess.Popen([sys.executable, '-I', sys.argv[0]], env={'FOO': 'arg-canary'})", "subprocess.Popen"),
    ("subprocess.Popen([sys.argv[1], 'arg-canary'])", "subprocess.Popen"),
])
def test_f20_blocks_network_use_and_unapproved_process_launch(tmp_path, call, event):
    stand = StandAudit(tmp_path, probe_socket_operations=event in {"socket.bind", "socket.sendto"})
    child = _script(tmp_path, "child.py", "import socket, subprocess, sys\n" + call + "\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    same_basename = _script(elsewhere, child.name, "print('unexpected executable code')")
    result = stand.run(child, sys.executable, str(same_basename), check_audit=False)
    assert result.returncode != 0
    assert not result.stdout
    blocked = stand.records()[-1]
    assert blocked["event"] == event, blocked
    assert "arg-canary" not in stand.journal.read_text(encoding="utf-8")
    with pytest.raises(AssertionError, match="stand blocked"):
        stand.assert_clean()

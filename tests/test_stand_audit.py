"""Controls for the portable stand; none requires a network namespace."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import stand_startup_diagnostic
from tests.stand_audit import StandAudit




@pytest.mark.skipif(sys.platform != "linux", reason="Linux syscall trace")
@pytest.mark.parametrize("control", ["supervised", "no-subreaper", "extra-fork", "parent-exec", "parent-network"])
def test_supervised_shim_trace_requires_one_pinned_child(tmp_path, control):
    from tests import stand_linux, stand_shim

    role = ("stand_shim", "escape")
    def exec_line(path, argv):
        return f'execve({json.dumps(path)}, {json.dumps(argv)}, 0x1 /* env */) = 0'

    shim = str(stand_shim.shim_path(tmp_path))
    fake = str(stand_shim.fake_path(tmp_path))
    command = stand_shim.command("escape")
    layer = str(tmp_path / "data" / "claude-swap" / "layer.json")
    lines = [exec_line(sys.executable, stand_linux.worker_argv(*role)),
             exec_line(shim, command),
             exec_line(sys.executable, [sys.executable, "-I", "-m", "claude_swap.transparent",
                       f"--cswap-shim=0:{Path(shim).parent}", *command[1:]])]
    if control != "no-subreaper":
        lines.append("prctl(PR_SET_CHILD_SUBREAPER, 1) = 0")
    lines.append("clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1) = 102")
    child = [exec_line(fake, [fake, "--settings", layer, *command[1:]]), "+++ exited with 0 +++"]
    if control == "extra-fork":
        lines.append("clone(child_stack=NULL, flags=SIGCHLD) = 103")
        (tmp_path / "trace.103").write_text("+++ exited with 0 +++\n")
    if control == "parent-exec":
        lines.append(exec_line(fake, [fake, "--settings", layer, *command[1:]]))
    if control == "parent-network":
        lines.append('connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH (Network is unreachable)')
    lines.append("+++ exited with 0 +++")
    (tmp_path / "trace.101").write_text("\n".join(lines) + "\n")
    (tmp_path / "trace.102").write_text("\n".join(child) + "\n")
    _, violations, execs = stand_linux._audit(tmp_path, role, {}, {})
    if control == "supervised":
        assert not violations
        assert execs == ("path-shim", "shim-python", "shim-claude")
    else:
        assert violations


def _script(tmp_path, name, source):
    path = tmp_path / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


@pytest.mark.parametrize("reason", ["flags", "interpreter", "script", "environment", "venv-launcher"])
def test_startup_refusal_reports_only_fixed_categories(tmp_path, reason):
    stand = StandAudit(tmp_path)
    canary = "private-startup-canary"
    variable = "EXTRA_TEST_VARIABLE"
    script = _script(tmp_path, f"{canary}.py", "print('script ran')")
    stand.allow(script)
    flags = ["-I"]
    env = stand.env
    details = {"stage": "root"}
    if reason == "flags":
        flags = ["-E", "-s"]
    elif reason == "interpreter":
        policy = json.loads(stand._policy.read_text(encoding="utf-8"))
        policy["python"] = str(tmp_path / canary)
        stand._policy.write_text(json.dumps(policy), encoding="utf-8")
    elif reason == "script":
        script.write_text("print('changed script ran')", encoding="utf-8")
    elif reason == "environment":
        env[variable] = canary
        del env["NO_PROXY"]
        env["LC_ALL"] = canary
        details["environment"] = {
            "added": {"count": 1, "known": []},
            "missing": {"count": 1, "known": []},
            "changed": {"count": 1, "known": ["locale-all"]},
        }
    else:
        # CPython consumes __PYVENV_LAUNCHER__ before sitecustomize. Simulate
        # it being visible at the environment check without affecting getpath.
        stand._policy.with_name("synthetic_launcher.pth").write_text(
            f"import os; os.environ['__PYVENV_LAUNCHER__'] = {canary!r}\n", encoding="utf-8",
        )
        reason = "environment"
        details["environment"] = {
            "added": {"count": 1, "known": ["venv-launcher"]},
            "missing": {"count": 0, "known": []},
            "changed": {"count": 0, "known": []},
        }
    result = subprocess.run(
        [str(stand.python), *flags, str(script), canary], cwd=stand.cwd, env=env,
        close_fds=True, stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 125
    assert not result.stdout
    prefix = f"no-network stand could not establish audited startup: {reason} "
    assert result.stderr.startswith(prefix)
    assert json.loads(result.stderr[len(prefix):]) == details
    with pytest.raises(AssertionError, match=f"^stand blocked startup: {reason} ") as error:
        stand.assert_clean()
    blocked, = stand.records()
    assert isinstance(blocked.pop("pid"), int)
    assert blocked == {"kind": "blocked", "event": "startup", "reason": reason, **details}
    observations = result.stderr + str(error.value) + stand.journal.read_text(encoding="utf-8")
    assert canary not in observations and variable not in observations


@pytest.mark.parametrize("contaminate_descendant", [False, True], ids=["clean", "contaminated-descendant"])
def test_startup_probe_tracks_reached_bodies(tmp_path, monkeypatch, capsys, contaminate_descendant):
    key = "__CF_USER_TEXT_ENCODING"
    canary = "private-darwin-canary"
    monkeypatch.setenv(key, canary)
    darwin = sys.platform == "darwin"

    def make_stand(path):
        stand = StandAudit(path)
        if darwin:
            assert stand.env[key] == f"0x{os.getuid():X}:0:0"
        else:
            assert key not in stand.env
        if contaminate_descendant:
            # Modify the environment after the parent approves the launch.
            stand._policy.with_name("synthetic_darwin.pth").write_text(
                "import os, sys; "
                "sys.argv[0].endswith('descendant.py') and "
                f"os.environ.update({key}={canary!r})\n",
                encoding="utf-8",
            )
        return stand

    monkeypatch.setattr(stand_startup_diagnostic, "StandAudit", make_stand)
    if contaminate_descendant:
        drift = {category: {"count": 0, "known": []} for category in ("added", "missing", "changed")}
        drift["changed" if darwin else "added"] = {
            "count": 1, "known": ["darwin-user-text-encoding"],
        }
        expected = {
            "started": ["root"],
            "exit": 125,
            "refusal": {
                "stage": "descendant",
                "reason": "environment",
                "environment": drift,
            },
        }
    else:
        expected = {"started": ["root", "descendant"], "exit": 0}
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    assert stand_startup_diagnostic.main() == expected["exit"]
    assert json.loads(capsys.readouterr().out) == expected


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
    assert [r["stage"] for r in started] == ["root", "descendant"]


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


@pytest.mark.skipif(sys.platform != "linux", reason="Installed shim requires admitted Linux tree supervision")
@pytest.mark.parametrize(("call", "event"), [
    ("print('synthetic Claude')", None),
    ("socket.socket(socket.AF_INET, socket.SOCK_DGRAM).bind(('127.0.0.1', 0))", "socket.bind"),
    ("socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'data', ('127.0.0.1', 9))", "socket.sendto"),
    ("socket.socket().connect(('192.0.2.1', 443))", "socket.connect"),
    ("socket.getaddrinfo('audit-escape.invalid', 443)", "socket.getaddrinfo"),
    ("subprocess.Popen(['/not-allowlisted', 'probe'])", "subprocess.Popen"),
    pytest.param("os.fork()", "os.fork", marks=pytest.mark.skipif(sys.platform != "linux", reason="Linux fork control")),
    pytest.param("from claude_swap.spawn import supervise; supervise(lambda: None)", "os.fork", marks=pytest.mark.skipif(sys.platform != "linux", reason="Linux supervisor control")),
])
def test_f20_audits_plain_claude_through_the_installed_shim(tmp_path, call, event):
    stand = StandAudit(tmp_path, probe_socket_operations=True)
    installer = _script(tmp_path, "installer.py", """
        import runpy
        import sys

        sys.argv[:] = ["cswap", "transparent", "enable", "--accept-shared-history", "--account", "1"]
        runpy.run_module("claude_swap", run_name="__main__", alter_sys=True)
    """)
    result = stand.run_shim(installer, "import os, socket, subprocess\n" + call, "--", "prompt")
    records = stand.records()
    launch = records[:5]
    assert [r["kind"] for r in launch] == ["startup", "startup", "supervise", "exec", "startup"], result.stderr
    assert launch[-2]["pid"] == launch[-1]["pid"]
    assert launch[1]["pid"] == launch[2]["pid"] != launch[-1]["pid"]
    assert [r["stage"] for r in launch if r["kind"] == "startup"] == ["root", "root", "descendant"]
    if event is None:
        stand.assert_clean()
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "synthetic Claude" and not result.stderr
    else:
        assert result.returncode != 0 and not result.stdout
        assert records[-1]["event"] == event
        with pytest.raises(AssertionError, match="stand blocked"):
            stand.assert_clean()


@pytest.mark.skipif(sys.platform != "darwin", reason="Native Darwin fail-closed launch policy")
def test_installed_shim_refuses_unsupported_tree_supervision(tmp_path):
    stand = StandAudit(tmp_path)
    installer = _script(tmp_path, "installer.py", """
        import runpy
        import sys

        sys.argv[:] = ["cswap", "transparent", "enable", "--accept-shared-history", "--account", "1"]
        runpy.run_module("claude_swap", run_name="__main__", alter_sys=True)
    """)
    result = stand.run_shim(installer, "raise AssertionError('synthetic body must not run')", "--", "prompt")
    assert result.returncode != 0
    assert not result.stdout
    assert "Profile launch refused before fork" in result.stderr
    assert "Profile tree supervision is unsupported on this platform" in result.stderr
    assert [(record["kind"], record["stage"]) for record in stand.records()] == [
        ("startup", "root"), ("startup", "root"),
    ]
    from claude_swap import paths
    from claude_swap.session import session_dir_for

    backup = Path(stand.env["HOME"]) / paths.LEGACY_BACKUP_DIRNAME
    profile = session_dir_for(backup, "1", "audit@example.test")
    assert json.loads((profile / ".claude.json").read_text()) == {
        "oauthAccount": {"emailAddress": "audit@example.test", "accountUuid": "audit-profile"},
    }
    assert not list((backup / "profile-ownership" / "launches").glob("*.json"))
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

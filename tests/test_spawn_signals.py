"""Linux signal forwarding after the supervised leader exits."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from claude_swap import spawn
from tests.profile_admission_stand import AdmissionStand

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux pidfd supervision")


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_signal_reaches_detached_descendants_after_leader_reaped(tmp_path, signum):
    code = r"""
import os, signal, sys, time
from pathlib import Path
from claude_swap import spawn, profile_ownership as ownership
root = Path(sys.argv[1])
sig = int(sys.argv[2])
backup, profile = Path(sys.argv[3]), Path(sys.argv[4])
with ownership.ownership_lock(backup):
    record = ownership.reserve_locked(backup, "2", profile)
    ownership.mark_running_locked(backup, record["launchId"], os.getpid())
def launch():
    if os.fork() == 0:
        os.setsid()
        signal.pthread_sigmask(signal.SIG_BLOCK, {sig})
        if os.fork() == 0:
            (root / "grandchild").write_text(str(os.getpid()))
            signal.sigwait({sig})
            (root / "received-grandchild").write_text("yes")
            while not (root / "release").exists():
                time.sleep(.01)
            os._exit(0)
        (root / "child").write_text(str(os.getpid()))
        signal.sigwait({sig})
        (root / "received-child").write_text("yes")
        os._exit(0)
    os._exit(19)
real_wait = os.waitpid
def wait(*args):
    pid, status = real_wait(*args)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 19:
        (root / "leader-reaped").write_text("yes")
    return pid, status
spawn.os.waitpid = wait
assert spawn.supervise(launch) == 19
ownership.release_completed(backup, record["launchId"])
(root / "complete").write_text("yes")
"""
    stand = AdmissionStand(tmp_path, "session")
    proc = subprocess.Popen([sys.executable, "-c", code, str(tmp_path), str(signum),
                             str(stand.backup), str(stand.profile)], env=stand.env)
    def wait_for(name):
        deadline = time.monotonic() + 5
        while not (tmp_path / name).exists():
            assert proc.poll() is None, f"supervisor exited waiting for {name}"
            assert time.monotonic() < deadline, f"timed out waiting for {name}"
            time.sleep(.01)
    descendant_fds = []
    try:
        for name in ("child", "grandchild", "leader-reaped"):
            wait_for(name)
            if name != "leader-reaped":
                descendant_fds.append(os.pidfd_open(int((tmp_path / name).read_text())))
        assert stand.switch() == 4
        proc.send_signal(signum)
        wait_for("received-child")
        wait_for("received-grandchild")
        assert proc.poll() is None
        assert not (tmp_path / "complete").exists()
        assert stand.switch() == 4
        (tmp_path / "release").touch()
        assert proc.wait(timeout=5) == 0
        assert (tmp_path / "complete").exists()
        assert stand.switch() == 0
    finally:
        (tmp_path / "release").touch()
        for fd in descendant_fds:
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        stand.__exit__(None, None, None)


def test_descendant_discovery_includes_nonleader_threads(monkeypatch):
    root = os.getpid()
    files = {
        f"/proc/{root}/task/{root}/children": "", 
        f"/proc/{root}/task/{root + 1}/children": "2345",
        "/proc/2345/stat": f"2345 (synthetic (name)) S {root} 0 0",
        "/proc/2345/task/2345/children": "",
    }
    monkeypatch.setattr(Path, "read_text", lambda self: files[str(self)])
    monkeypatch.setattr(Path, "iterdir", lambda self: iter(
        [Path(f"/proc/{root}/task/{root}"), Path(f"/proc/{root}/task/{root + 1}")]
        if str(self) == f"/proc/{root}/task" else [Path("/proc/2345/task/2345")]))
    monkeypatch.setattr(os, "pidfd_open", lambda pid: pid + 10000)
    monkeypatch.setattr(os, "close", lambda fd: None)
    delivered = []
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda fd, sig: delivered.append((fd, sig)))
    spawn._signal_descendants(signal.SIGTERM)
    assert (12345, signal.SIGTERM) in delivered


@pytest.mark.parametrize("reused", ["child", "parent", "foreign"])
def test_unproven_or_reused_pids_are_never_signalled(monkeypatch, reused):
    root = os.getpid()
    files = {
        f"/proc/{root}/task/{root}/children": "2345",
        "/proc/2345/stat": f"2345 (synthetic) S {root if reused != 'foreign' else 999} 0 0",
    }
    monkeypatch.setattr(Path, "read_text", lambda self: files[str(self)])
    monkeypatch.setattr(Path, "iterdir", lambda self: iter([Path(f"/proc/{root}/task/{root}")]))
    monkeypatch.setattr(os, "pidfd_open", lambda pid: pid + 10000)
    closed = []
    monkeypatch.setattr(os, "close", closed.append)
    delivered = []
    def send(fd, sig):
        if sig == 0 and fd == (12345 if reused == "child" else root + 10000) and reused != "foreign":
            raise ProcessLookupError()
        if sig:
            delivered.append((fd, sig))
    monkeypatch.setattr(signal, "pidfd_send_signal", send)
    spawn._signal_descendants(signal.SIGTERM)
    assert delivered == []
    assert set(closed) == {root + 10000, 12345}


def test_subreaper_setup_failure_proves_no_child(tmp_path):
    code = r"""
import ctypes
from claude_swap import spawn
class Prctl:
    def __call__(self, *args):
        ctypes.set_errno(1)
        return -1
class Libc:
    prctl = Prctl()
ctypes.CDLL = lambda *args, **kwargs: Libc()
assert spawn.supervise(lambda: (_ for _ in ()).throw(AssertionError("launched"))) == 127
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                            text=True, timeout=10, env={**os.environ, "HOME": str(tmp_path)})
    assert result.returncode == 0, result.stderr

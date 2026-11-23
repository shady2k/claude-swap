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
            if signal.sigtimedwait({sig}, 5) is None:
                os._exit(91)
            (root / "received-grandchild").write_text("yes")
            deadline = time.monotonic() + 5
            while not (root / "release").exists():
                if time.monotonic() >= deadline:
                    os._exit(92)
                time.sleep(.01)
            os._exit(0)
        (root / "child").write_text(str(os.getpid()))
        if signal.sigtimedwait({sig}, 5) is None:
            os._exit(93)
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
        marker = tmp_path / name
        while not marker.exists() or not marker.read_text().strip():
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
try:
    spawn.require_supervision()
except OSError as exc:
    assert "subreaper" in str(exc).lower(), str(exc)
else:
    raise AssertionError("subreaper setup failure was accepted")
assert spawn.supervise(lambda: (_ for _ in ()).throw(AssertionError("launched"))) == 127
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                            text=True, timeout=10, env={**os.environ, "HOME": str(tmp_path)})
    assert result.returncode == 0, result.stderr
    assert "subreaper" in result.stderr.lower()


def _run_supervisor(code, tmp_path):
    return subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)], capture_output=True,
        text=True, timeout=10, env={**os.environ, "HOME": str(tmp_path)},
    )


@pytest.mark.parametrize("probe", ["open", "signal"])
def test_pidfd_probe_failure_precedes_publication(tmp_path, probe):
    code = r"""
import errno, os, signal, sys
from claude_swap import spawn
probe = sys.argv[2]
events = []
def fail(*args, **kwargs):
    raise OSError(errno.EMFILE, "pidfd probe unavailable")
if probe == "open":
    os.pidfd_open = fail
else:
    signal.pidfd_send_signal = fail
try:
    spawn.owned_launch(lambda: events.append("handoff"),
        publish=lambda: events.append("publish"),
        release=lambda: events.append("release"),
        abort=lambda: events.append("abort"))
except OSError as exc:
    assert exc.errno == errno.EMFILE, str(exc)
else:
    raise AssertionError("pidfd failure was accepted")
assert "publish" not in events and "handoff" not in events, events
assert "release" not in events, events
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path), probe], capture_output=True,
        text=True, timeout=10, env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr


def test_child_handoff_restores_original_mask_and_handlers(tmp_path):
    code = r"""
import os, signal, sys
from pathlib import Path
from claude_swap import spawn
root = Path(sys.argv[1])
def original(sig, frame):
    pass
signal.signal(signal.SIGINT, original)
signal.signal(signal.SIGQUIT, original)
old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGHUP, signal.SIGUSR1})
expected_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
child_mask = expected_mask - {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT}
def handoff():
    assert signal.getsignal(signal.SIGINT) is original
    assert signal.getsignal(signal.SIGQUIT) is original
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == child_mask
    (root / "restored").touch()
    os._exit(23)
assert spawn.owned_launch(handoff, publish=lambda: None,
    release=lambda: None, abort=lambda: None) == 23
assert (root / "restored").exists()
# After proven completion this dedicated launcher consumes termination
# until process exit so the external leader status cannot be replaced.
assert signal.getsignal(signal.SIGINT).__self__.completed
assert signal.getsignal(signal.SIGQUIT).__self__.completed
assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == expected_mask
signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
"""
    result = _run_supervisor(code, tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("phase", ["publish", "release"])
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_owned_launch_handles_signals_at_ownership_boundaries(tmp_path, phase, signum):
    code = r"""
import os, signal, sys
from pathlib import Path
from claude_swap import spawn
root = Path(sys.argv[1])
phase, sig = sys.argv[2], int(sys.argv[3])
events = []
def publish():
    events.append("publish")
    if phase == "publish":
        os.kill(os.getpid(), sig)
def release():
    events.append("release")
    if phase == "release":
        os.kill(os.getpid(), sig)
def handoff():
    os._exit(0)
spawn.owned_launch(handoff, publish=publish, release=release,
    abort=lambda: events.append("abort"))
assert events == ["publish", "release"], events
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path), phase, str(signum)],
        capture_output=True, text=True, timeout=10,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", ["send", "open-root", "open-child", "proc"])
@pytest.mark.parametrize("reentrant", [False, True])
@pytest.mark.parametrize("unknown_wait", [False, True])
def test_delivery_failure_does_not_unwind_wait(tmp_path, reentrant, unknown_wait, failure):
    code = r"""
import errno, os, signal, sys
from pathlib import Path
from claude_swap import spawn
reentrant, unknown_wait = map(int, sys.argv[2:4])
failure = sys.argv[4]
root = os.getpid()
events, opened, closed = [], [], []
def fail():
    events.append("delivery")
    if reentrant and events.count("delivery") == 1:
        os.kill(root, signal.SIGTERM)
    raise OSError(errno.EMFILE, "delivery exhausted descriptors")
def open_pidfd(pid):
    if (failure == "open-root" and pid == root
            or failure == "open-child" and pid != root):
        fail()
    fd = 10000 + len(opened)
    opened.append(fd)
    return fd
files = {
    f"/proc/{root}/task/{root}/children": "2345",
    "/proc/2345/stat": f"2345 (synthetic) S {root} 0 0",
    "/proc/2345/task/2345/children": "",
}
def publish():
    events.append("publish")
    Path.read_text = lambda self: fail() if failure == "proc" else files[str(self)]
    Path.iterdir = lambda self: iter([Path(f"/proc/{root}/task/{root}")]
        if str(self) == f"/proc/{root}/task" else [Path("/proc/2345/task/2345")])
    os.pidfd_open = open_pidfd
    os.close = closed.append
    signal.pidfd_send_signal = send
    os.fork = lambda: 2345
def send(fd, sig):
    if sig:
        fail()
def wait(*args):
    if "wait-returned" not in events:
        os.kill(root, signal.SIGTERM)
        events.append("wait-returned")
        return 2345, 17 << 8
    events.append("wait-finished")
    if unknown_wait:
        raise OSError(errno.EIO, "unknown wait failure")
    raise ChildProcessError()
os.waitpid = wait
try:
    rc = spawn.owned_launch(lambda: None, publish=publish,
        release=lambda: events.append("release"),
        abort=lambda: events.append("abort"))
except OSError as exc:
    assert unknown_wait, str(exc)
    assert "unknown wait failure" in str(exc), str(exc)
else:
    assert not unknown_wait, "unknown wait failure was discarded"
    assert rc == 17
assert "wait-returned" in events and "wait-finished" in events, events
assert ("release" in events) == (not unknown_wait), events
assert "abort" not in events, events
assert "delivery" in events, events
assert len(opened) >= (2 if failure == "send" else 0 if failure == "open-root" else 1), opened
assert sorted(closed) == sorted(opened), (opened, closed)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path), str(int(reentrant)), str(int(unknown_wait)), failure],
        capture_output=True, text=True, timeout=10,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr.strip(), "delivery failure needs a diagnostic"


def test_int_is_forwarded_only_after_leader_reap(tmp_path):
    code = r"""
import os, signal
from claude_swap import spawn
events = []
spawn._signal_descendants = lambda sig: events.append(sig)
def publish():
    os.fork = lambda: 2345
calls = 0
def wait(*args):
    global calls
    calls += 1
    os.kill(os.getpid(), signal.SIGINT)
    if calls == 1:
        assert events == [], events
        return 2345, 19 << 8
    assert events == [signal.SIGINT], events
    raise ChildProcessError()
os.waitpid = wait
assert spawn.owned_launch(lambda: None, publish=publish,
    release=lambda: events.append("released"), abort=lambda: None) == 19
assert events == [signal.SIGINT, "released"], events
"""
    result = _run_supervisor(code, tmp_path)
    assert result.returncode == 0, result.stderr

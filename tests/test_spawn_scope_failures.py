"""Failure paths for the protected launch scope."""
import os
import subprocess
import sys

import pytest


def _run(code, tmp_path):
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=10, env={**os.environ, "HOME": str(tmp_path)})


def test_unsupported_platform_aborts_without_posix_signal_api(tmp_path):
    result = _run(r"""
import signal
from claude_swap import spawn
spawn.sys.platform = "win32"
if hasattr(signal, "pthread_sigmask"):
    del signal.pthread_sigmask
events = []
try:
    spawn.owned_launch(lambda: events.append("handoff"),
        publish=lambda: events.append("publish"), release=lambda: events.append("release"),
        abort=lambda: events.append("abort"))
except OSError as exc:
    assert "unsupported" in str(exc)
else:
    raise AssertionError("unsupported launch accepted")
assert events == ["abort"], events
""", tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision")
def test_broken_diagnostic_cannot_interrupt_descendant_wait(tmp_path):
    result = _run(r"""
import errno, os, signal, sys
from claude_swap import spawn
class BrokenStderr:
    def write(self, text):
        raise OSError(errno.EIO, "broken diagnostic sink")
    def flush(self):
        pass
sys.stderr = BrokenStderr()
events = []
def fail(sig):
    raise OSError(errno.EMFILE, "delivery failed")
spawn._signal_descendants = fail
def publish():
    os.fork = lambda: 2345
def wait(*args):
    events.append("wait")
    if len(events) == 1:
        os.kill(os.getpid(), signal.SIGTERM)
        return 2345, 17 << 8
    raise ChildProcessError()
os.waitpid = wait
assert spawn.owned_launch(lambda: None, publish=publish,
    release=lambda: events.append("release"), abort=lambda: events.append("abort")) == 17
assert events == ["wait", "wait", "release"], events
""", tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision")
def test_restore_boundary_consumes_signal_before_original_mask(tmp_path):
    result = _run(r"""
import os, signal
from claude_swap import spawn
original = signal.signal
restoring = False
def install(sig, handler):
    result = original(sig, handler)
    if restoring and sig == signal.SIGTERM:
        os.kill(os.getpid(), signal.SIGTERM)
    return result
signal.signal = install
def release():
    global restoring
    restoring = True
assert spawn.owned_launch(lambda: os._exit(23), publish=lambda: None,
    release=release, abort=lambda: None) == 23
""", tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision")
def test_term_after_final_drain_preserves_external_leader_status(tmp_path):
    result = _run(r"""
import os, signal, sys
from claude_swap import spawn
restoring = False
original_mask = signal.pthread_sigmask
original_wait = signal.sigtimedwait
empty_read = False
def drain(*args):
    global empty_read
    result = original_wait(*args)
    if result is None:
        empty_read = True
    return result
def mask(how, signals):
    if restoring and how == signal.SIG_SETMASK:
        assert empty_read, "injection must follow the final empty drain"
        # The terminal race: no further drain can see this pending TERM.
        os.kill(os.getpid(), signal.SIGTERM)
    return original_mask(how, signals)
signal.sigtimedwait = drain
signal.pthread_sigmask = mask
def release():
    global restoring
    restoring = True
rc = spawn.owned_launch(lambda: os._exit(23), publish=lambda: None,
    release=release, abort=lambda: None)
assert empty_read
# Code delivery remains protected after returning from the storage scope.
os.kill(os.getpid(), signal.SIGTERM)
sys.exit(rc)
""", tmp_path)
    assert result.returncode == 23, result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision")
@pytest.mark.parametrize("signum", [1, 2, 15])
def test_publication_refusal_delivers_pending_termination(tmp_path, signum):
    code = r"""
import os, signal
from pathlib import Path
from claude_swap import spawn
class PolicyChanged(Exception):
    pass
def publish():
    os.kill(os.getpid(), SIGNUM)
    raise PolicyChanged()
def abort():
    Path(os.environ["HOME"], "aborted").touch()
try:
    spawn.owned_launch(lambda: os._exit(99), publish=publish,
        release=lambda: None, abort=abort)
except PolicyChanged:
    pass
raise SystemExit(42)
""".replace("SIGNUM", str(signum))
    result = _run(code, tmp_path)
    assert (tmp_path / "aborted").exists()
    if signum == 2:
        assert result.returncode in (-signum, 130), result.stderr
        assert "KeyboardInterrupt" in result.stderr
    else:
        assert result.returncode == -signum, result.stderr

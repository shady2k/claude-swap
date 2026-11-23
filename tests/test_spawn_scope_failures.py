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

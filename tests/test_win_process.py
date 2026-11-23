"""Win32 process identity: portable classification and native reads."""

import ctypes as c
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from claude_swap import _win_process


def _fake_kernel(monkeypatch, *, handle=11, error=0, wait=_win_process.WAIT_TIMEOUT,
                 creation=(7, 9), times=True):
    """A kernel32 whose four process calls are recorded instead of executed."""
    calls = {"open": [], "wait": [], "times": [], "close": []}

    def open_process(access, inherit, pid):
        calls["open"].append((access, inherit, pid))
        return handle

    def wait_for_single_object(process, milliseconds):
        calls["wait"].append((process, milliseconds))
        return wait

    def get_process_times(process, created, exited, kernel_time, user_time):
        calls["times"].append(process)
        if not times:
            return 0
        created._obj.dwHighDateTime, created._obj.dwLowDateTime = creation
        return 1

    def close_handle(process):
        calls["close"].append(process)
        return 1

    kernel = SimpleNamespace(
        OpenProcess=Mock(side_effect=open_process),
        WaitForSingleObject=Mock(side_effect=wait_for_single_object),
        GetProcessTimes=Mock(side_effect=get_process_times),
        CloseHandle=Mock(side_effect=close_handle),
    )
    monkeypatch.setattr(_win_process, "_kernel32", lambda: kernel)
    monkeypatch.setattr(c, "get_last_error", lambda: error, raising=False)
    return calls


@pytest.mark.parametrize("pid", [0, -1, 0x100000000, True, "4242", None])
def test_invalid_pid_is_unknown_without_opening_a_handle(monkeypatch, pid):
    calls = _fake_kernel(monkeypatch)
    assert _win_process.process_identity(pid) == _win_process.ProcessIdentity("unknown", None)
    assert calls["open"] == []


def test_present_identity_reads_creation_time_from_the_opened_handle(monkeypatch):
    calls = _fake_kernel(monkeypatch, creation=(7, 9))
    identity = _win_process.process_identity(4242)
    assert identity == _win_process.ProcessIdentity("present", (7 << 32) | 9)
    assert calls["open"] == [
        (_win_process.PROCESS_QUERY_LIMITED_INFORMATION | _win_process.SYNCHRONIZE, False, 4242)
    ]
    assert calls["wait"] == [(11, 0)]
    assert calls["times"] == [11]
    assert calls["close"] == [11]


def test_missing_pid_is_absence(monkeypatch):
    calls = _fake_kernel(monkeypatch, handle=0, error=_win_process.ERROR_INVALID_PARAMETER)
    assert _win_process.process_identity(4242) == _win_process.ProcessIdentity("absent", None)
    assert calls["close"] == []


def test_access_denied_is_not_absence(monkeypatch):
    _fake_kernel(monkeypatch, handle=0, error=_win_process.ERROR_ACCESS_DENIED)
    assert _win_process.classify_open_error(_win_process.ERROR_ACCESS_DENIED) == "denied"
    assert _win_process.process_identity(4242).state == "denied"


def test_other_open_failure_is_unknown(monkeypatch):
    _fake_kernel(monkeypatch, handle=0, error=8)
    assert _win_process.process_identity(4242).state == "unknown"


def test_signaled_handle_is_absence(monkeypatch):
    calls = _fake_kernel(monkeypatch, wait=_win_process.WAIT_OBJECT_0)
    assert _win_process.process_identity(4242) == _win_process.ProcessIdentity("absent", None)
    assert calls["times"] == []
    assert calls["close"] == [11]


def test_unexpected_wait_result_is_unknown(monkeypatch):
    calls = _fake_kernel(monkeypatch, wait=0xFFFFFFFF)
    assert _win_process.process_identity(4242).state == "unknown"
    assert calls["close"] == [11]


def test_unreadable_creation_time_is_unknown(monkeypatch):
    calls = _fake_kernel(monkeypatch, times=False)
    assert _win_process.process_identity(4242) == _win_process.ProcessIdentity("unknown", None)
    assert calls["close"] == [11]


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows process API")
def test_native_identity_is_stable_and_a_child_differs(tmp_path):
    from claude_swap.locking import FileLock

    own = _win_process.process_identity(os.getpid())
    assert own.state == "present"
    assert own.creation_time
    assert _win_process.process_identity(os.getpid()) == own
    lock_path = tmp_path / "child.lock"
    child_code = (
        "import sys; from pathlib import Path; "
        "from claude_swap.locking import FileLock; "
        "lock = FileLock(Path(sys.argv[1])); "
        "assert lock.acquire(); "
        "print('ready', flush=True); "
        "sys.stdin.readline(); lock.release()"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, str(lock_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    contender = FileLock(lock_path, timeout=0)
    try:
        assert child.stdout.readline().strip() == "ready"
        child_identity = _win_process.process_identity(child.pid)
        assert child_identity.state == "present"
        assert child_identity.creation_time
        assert child_identity.creation_time != own.creation_time
        assert _win_process.process_identity(child.pid) == child_identity
        assert contender.acquire() is False
        child.stdin.write("done\n")
        child.stdin.flush()
        assert child.wait(timeout=10) == 0
        assert _win_process.process_identity(child.pid).state == "absent"
        assert contender.acquire() is True
    finally:
        contender.release()
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdin.close()
        child.stdout.close()


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows process API")
def test_native_pid_zero_is_unknown():
    assert _win_process.process_identity(0).state == "unknown"

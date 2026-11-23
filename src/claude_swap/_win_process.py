"""Windows process identity and liveness, read through one process handle.

``OpenProcess`` is asked for ``PROCESS_QUERY_LIMITED_INFORMATION |
SYNCHRONIZE`` only. ``WaitForSingleObject(handle, 0)`` tells a live process
from one that has exited, and ``GetProcessTimes`` returns the creation time,
which a later process at the same PID does not share in practice. Both calls
act on the handle taken at the start, so a PID recycled in between cannot be
mistaken for the process that was asked about.

A failed open is classified by ``GetLastError``: ``ERROR_INVALID_PARAMETER``
is what ``OpenProcess`` returns for a PID that does not exist, and
``ERROR_ACCESS_DENIED`` means the process exists but this user may not inspect
it, such as a protected process or another user's. Only the first proves
absence; denial must never be read as "no process".

Evidence: ``OpenProcess`` (returns ``ERROR_INVALID_PARAMETER`` for a
nonexistent process and ``ERROR_ACCESS_DENIED`` for restricted processes),
``WaitForSingleObject`` (``WAIT_OBJECT_0`` for an exited process,
``WAIT_TIMEOUT`` for a live one), ``GetProcessTimes`` and ``GetLastError`` are
the documented Win32 process API, read from Microsoft Learn in November 2026.
"""

from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from functools import lru_cache
from typing import Literal, NamedTuple

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258

State = Literal["present", "absent", "denied", "unknown"]


class ProcessIdentity(NamedTuple):
    """What one read proved about a PID.

    ``creation_time`` is the 100 ns FILETIME of process creation and is set
    only when ``state`` is ``present``.
    """

    state: State
    creation_time: int | None = None


@lru_cache(maxsize=1)
def _kernel32():
    return c.WinDLL("kernel32", use_last_error=True)


def _function(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype = result
    fn.argtypes = args
    return fn


def classify_open_error(error: int) -> State:
    """What an ``OpenProcess`` failure proves: absence, denial, or nothing."""
    if error == ERROR_INVALID_PARAMETER:
        return "absent"
    if error == ERROR_ACCESS_DENIED:
        return "denied"
    return "unknown"


def process_identity(pid: int) -> ProcessIdentity:
    """Liveness and creation time for ``pid``, from a single process handle.

    Invalid inputs, including PID 0 (the System Idle Process), are unknown
    without opening a handle; they do not prove that a process is absent.
    """
    if type(pid) is not int or pid <= 0 or pid > 0xFFFFFFFF:
        return ProcessIdentity("unknown", None)
    kernel = _kernel32()
    open_process = _function(kernel, "OpenProcess", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
    handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not handle:
        return ProcessIdentity(classify_open_error(c.get_last_error()), None)
    try:
        wait = _function(kernel, "WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)(handle, 0)
        if wait == WAIT_OBJECT_0:
            return ProcessIdentity("absent", None)
        if wait != WAIT_TIMEOUT:
            return ProcessIdentity("unknown", None)
        creation, exited, kernel_time, user_time = (w.FILETIME() for _ in range(4))
        get_times = _function(
            kernel, "GetProcessTimes", w.BOOL, w.HANDLE,
            c.POINTER(w.FILETIME), c.POINTER(w.FILETIME),
            c.POINTER(w.FILETIME), c.POINTER(w.FILETIME),
        )
        if not get_times(
            handle, c.byref(creation), c.byref(exited),
            c.byref(kernel_time), c.byref(user_time),
        ):
            return ProcessIdentity("unknown", None)
        creation_time = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        if not creation_time:
            return ProcessIdentity("unknown", None)
        return ProcessIdentity("present", creation_time)
    finally:
        _function(kernel, "CloseHandle", w.BOOL, w.HANDLE)(handle)

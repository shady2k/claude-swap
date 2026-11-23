"""Windows file security queries for fsguard and executable identity."""

from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from claude_swap.fsguard import GuardError


@lru_cache(maxsize=1)
def _libraries():
    return c.WinDLL("kernel32", use_last_error=True), c.WinDLL("advapi32", use_last_error=True)


def _function(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype = result
    fn.argtypes = args
    return fn


def _open_handle(path: Path, access: int, share: int) -> int:
    kernel, _ = _libraries()
    create = _function(kernel, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD,
                       c.c_void_p, w.DWORD, w.DWORD, w.HANDLE)
    # OPEN_EXISTING; BACKUP_SEMANTICS for directories; OPEN_REPARSE_POINT
    # so a symlink's security descriptor is not replaced by its target's.
    handle = create(str(path), access, share, None, 3, 0x02200000, None)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    return handle


def _close_handle(handle: int) -> None:
    kernel, _ = _libraries()
    _function(kernel, "CloseHandle", w.BOOL, w.HANDLE)(handle)


@contextmanager
def _handle(path: Path, access: int, share: int = 7):
    handle = _open_handle(path, access, share)
    try:
        yield handle
    finally:
        _close_handle(handle)


def open_executable(path: Path) -> int:
    """Pin the target against writes and replacement through CreateProcess."""
    import msvcrt
    import os

    handle = _open_handle(path, 0x80000000, 1)  # GENERIC_READ, FILE_SHARE_READ
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
    except OSError:
        _close_handle(handle)
        raise


class _BasicInfo(c.Structure):
    _fields_ = [(name, c.c_int64) for name in ("creation", "access", "write", "change")] + [
        ("attributes", w.DWORD)
    ]


class _FileInfo(c.Structure):
    _fields_ = [
        ("attributes", w.DWORD), ("creation", w.FILETIME), ("access", w.FILETIME),
        ("write", w.FILETIME), ("volume", w.DWORD), ("size_high", w.DWORD),
        ("size_low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD),
        ("index_low", w.DWORD),
    ]


class ExecutableIdentity(NamedTuple):
    volume: int
    file_id: int
    attributes: int
    size: int
    creation_time: int
    write_time: int
    change_time: int | None


def _dwords(high: int, low: int) -> int:
    return (high << 32) | low


def _change_time(handle: int) -> int | None:
    """NTFS ChangeTime, not Python's st_ctime (birth time on Windows)."""
    kernel, _ = _libraries()
    query = _function(kernel, "GetFileInformationByHandleEx", w.BOOL, w.HANDLE, c.c_int,
                      c.c_void_p, w.DWORD)
    info = _BasicInfo()
    if query(handle, 0, c.byref(info), c.sizeof(info)) and info.change > 0:
        return info.change
    return None


def _executable_identity(handle: int) -> ExecutableIdentity:
    # CPython 3.12.10's lstat and fstat do not normalize Windows times alike.
    # Use one native query for handles acquired by path and handles backing fds.
    kernel, _ = _libraries()
    query = _function(kernel, "GetFileInformationByHandle", w.BOOL, w.HANDLE,
                      c.POINTER(_FileInfo))
    info = _FileInfo()
    if not query(handle, c.byref(info)):
        raise c.WinError(c.get_last_error())
    return ExecutableIdentity(
        info.volume, _dwords(info.index_high, info.index_low), info.attributes,
        _dwords(info.size_high, info.size_low),
        _dwords(info.creation.dwHighDateTime, info.creation.dwLowDateTime),
        _dwords(info.write.dwHighDateTime, info.write.dwLowDateTime),
        _change_time(handle),
    )


def executable_identity_at_path(path: Path) -> ExecutableIdentity:
    """Inspect the named entry, including while a read-only pin is held."""
    with _handle(path, 0x80) as handle:  # FILE_READ_ATTRIBUTES
        return _executable_identity(handle)


def executable_identity_at_fd(fd: int) -> ExecutableIdentity:
    """Inspect the same handle that pins the executable against writes/deletion."""
    import msvcrt

    return _executable_identity(msvcrt.get_osfhandle(fd))


def _sid_string(sid: c.c_void_p | int) -> str:
    kernel, advapi = _libraries()
    convert = _function(advapi, "ConvertSidToStringSidW", w.BOOL, c.c_void_p,
                        c.POINTER(w.LPWSTR))
    free = _function(kernel, "LocalFree", w.HLOCAL, w.HLOCAL)
    result = w.LPWSTR()
    if not convert(sid, c.byref(result)):
        raise c.WinError(c.get_last_error())
    try:
        return result.value
    finally:
        free(c.cast(result, c.c_void_p))


@lru_cache(maxsize=1)
def _trusted_sids() -> frozenset[str]:
    kernel, advapi = _libraries()
    get_process = _function(kernel, "GetCurrentProcess", w.HANDLE)
    close = _function(kernel, "CloseHandle", w.BOOL, w.HANDLE)
    open_token = _function(advapi, "OpenProcessToken", w.BOOL, w.HANDLE, w.DWORD,
                           c.POINTER(w.HANDLE))
    query = _function(advapi, "GetTokenInformation", w.BOOL, w.HANDLE, c.c_int,
                      c.c_void_p, w.DWORD, c.POINTER(w.DWORD))
    token = w.HANDLE()
    if not open_token(get_process(), 8, c.byref(token)):  # TOKEN_QUERY
        raise c.WinError(c.get_last_error())
    try:
        size = w.DWORD()
        query(token, 1, None, 0, c.byref(size))  # TokenUser
        info = c.create_string_buffer(size.value)
        if not size.value or not query(token, 1, info, size, c.byref(size)):
            raise c.WinError(c.get_last_error())
        user = _sid_string(c.cast(info, c.POINTER(c.c_void_p)).contents)
        return frozenset({user, "S-1-5-18", "S-1-5-32-544"})  # SYSTEM, Administrators
    finally:
        close(token)


class _ACL(c.Structure):
    _fields_ = [("revision", c.c_ubyte), ("reserved", c.c_ubyte), ("size", w.WORD),
                ("count", w.WORD), ("reserved2", w.WORD)]


class _ACE(c.Structure):
    _fields_ = [("type", c.c_ubyte), ("flags", c.c_ubyte), ("size", w.WORD),
                ("mask", w.DWORD), ("sid_start", w.DWORD)]


# Write data/append/EA/attributes, delete/delete child, change the ACL/owner,
# and the generic write/all rights that can map to them.
_WRITE_RIGHTS = 0x500D0156


def _check_dacl(path: Path, dacl: c.c_void_p, trusted: frozenset[str]) -> None:
    if not dacl:
        raise GuardError(f"Missing access control list: {path}")
    _, advapi = _libraries()
    get_ace = _function(advapi, "GetAce", w.BOOL, c.c_void_p, w.DWORD,
                        c.POINTER(c.c_void_p))
    for index in range(c.cast(dacl, c.POINTER(_ACL)).contents.count):
        entry = c.c_void_p()
        if not get_ace(dacl, index, c.byref(entry)):
            raise c.WinError(c.get_last_error())
        ace = c.cast(entry, c.POINTER(_ACE)).contents
        if ace.flags & 8 or ace.type in {1, 6, 10, 12}:  # inherit-only and access-denied
            continue
        if ace.type != 0:
            raise GuardError(f"Unsupported access control entry: {path}")
        if ace.mask & _WRITE_RIGHTS and _sid_string(entry.value + _ACE.sid_start.offset) not in trusted:
            raise GuardError(f"Writable by another user or group: {path}")


def check_write_access(path: Path) -> None:
    """Reject unknown/foreign write grants; never treat POSIX mode as an ACL."""
    kernel, advapi = _libraries()
    pointer = c.POINTER(c.c_void_p)
    security = _function(advapi, "GetSecurityInfo", w.DWORD, w.HANDLE, c.c_int, w.DWORD,
                         pointer, pointer, pointer, pointer, pointer)
    free = _function(kernel, "LocalFree", w.HLOCAL, w.HLOCAL)
    try:
        with _handle(path, 0x00020000) as handle:  # READ_CONTROL
            owner, dacl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
            # SE_FILE_OBJECT; OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            error = security(handle, 1, 5, c.byref(owner), None, c.byref(dacl), None,
                             c.byref(descriptor))
            if error:
                raise c.WinError(error)
            try:
                trusted = _trusted_sids()
                if not owner or _sid_string(owner) not in trusted:
                    raise GuardError(f"Untrusted owner: {path}")
                _check_dacl(path, dacl, trusted)
            finally:
                free(descriptor)
    except OSError as exc:
        raise GuardError(f"Could not inspect access control: {path}: {exc}") from exc

"""Native ACL setup for Windows test directories."""

import ctypes as c
import sys
from ctypes import wintypes as w
from pathlib import Path

from claude_swap import _win_file_security as security


class _SecurityAttributes(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit_handle", w.BOOL)]


def create_private_directory(path: Path) -> None:
    """Create an isolated test directory with a protected, inheritable DACL."""
    kernel, advapi = security._libraries()
    convert = security._function(
        advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
        w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.POINTER(w.DWORD),
    )
    create = security._function(
        kernel, "CreateDirectoryW", w.BOOL, w.LPCWSTR, c.POINTER(_SecurityAttributes),
    )
    free = security._function(kernel, "LocalFree", w.HLOCAL, w.HLOCAL)
    # P disables inherited grants from the test's parent; OICI propagates
    # these grants to freshly created subdirectories, lock and policy files.
    sddl = "D:P" + "".join(f"(A;OICI;FA;;;{sid})" for sid in sorted(security._trusted_sids()))
    descriptor = c.c_void_p()
    if not convert(sddl, 1, c.byref(descriptor), None):
        raise c.WinError(c.get_last_error())
    try:
        attributes = _SecurityAttributes(c.sizeof(_SecurityAttributes), descriptor, False)
        # ctypes bypasses Python's mkdir audit event. Apply the same guard.
        sys.audit("os.mkdir", str(path), 0o700, -1)
        if not create(str(path), c.byref(attributes)):
            raise c.WinError(c.get_last_error())
    finally:
        free(descriptor)

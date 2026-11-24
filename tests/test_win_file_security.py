"""Native Windows ACL tests using synthetic security descriptors."""

import ctypes as c
import sys
from ctypes import wintypes as w

import pytest

from claude_swap import _win_file_security as security, fsguard
from tests.win_config_diagnostic import _observe_dacl


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows ACL APIs")
@pytest.mark.parametrize("add_subdirectory", [False, True], ids=["inherit-only", "add-subdirectory"])
def test_check_dacl_distinguishes_inherit_only_modify_from_add_subdirectory(
    tmp_path, add_subdirectory,
):
    kernel, advapi = security._libraries()
    pointer = c.POINTER(c.c_void_p)
    convert = security._function(
        advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
        w.LPCWSTR, w.DWORD, pointer, c.POINTER(w.DWORD),
    )
    get_dacl = security._function(
        advapi, "GetSecurityDescriptorDacl", w.BOOL,
        c.c_void_p, c.POINTER(w.BOOL), pointer, c.POINTER(w.BOOL),
    )
    free = security._function(kernel, "LocalFree", w.HLOCAL, w.HLOCAL)
    # AU is Authenticated Users. icacls' (AD) is 0x4; (M) is 0x1301bf.
    sddl = "D:" + ("(A;;0x4;;;AU)" if add_subdirectory else "") + "(A;OICIIO;0x1301bf;;;AU)"
    descriptor = c.c_void_p()
    assert convert(sddl, 1, c.byref(descriptor), None)
    try:
        present, dacl, defaulted = w.BOOL(), c.c_void_p(), w.BOOL()
        assert get_dacl(descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted))
        assert present.value
        trusted = frozenset({"S-1-5-18"})  # SYSTEM, not Authenticated Users
        rejection = []
        if add_subdirectory:
            with pytest.raises(fsguard.GuardError, match="Writable by another user or group"):
                _observe_dacl(security._check_dacl, tmp_path, dacl, trusted, rejection)
            assert rejection == ["allow/explicit/authenticated-users mask=0x00000004 rights=append-data-or-add-subdirectory"]
        else:
            _observe_dacl(security._check_dacl, tmp_path, dacl, trusted, rejection)
            assert not rejection
    finally:
        free(descriptor)

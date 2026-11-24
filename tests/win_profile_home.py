"""Prepare an inherited Windows control HOME before pytest changes the environment.

CI runs ``uv run python -m tests.win_profile_home prepare`` before pytest and
``uv run python -m tests.win_profile_home cleanup`` afterwards (also on failure).
Local Windows runs must provide a scratch GITHUB_ENV file to prepare, import
its CSWAP_PROFILE_CONTROL_HOME assignment into the pytest/cleanup environment,
and run cleanup in a finally block. Never import it as HOME or USERPROFILE.
Only CSWAP_PROFILE_CONTROL_HOME is passed through GITHUB_ENV; HOME stays intact
until the control itself redirects product calls. No ACL is set or repaired.
"""

import ctypes as c
import os
import re
import shutil
import stat
import sys
from ctypes import wintypes as w
from pathlib import Path
from uuid import uuid4

ENV = "CSWAP_PROFILE_CONTROL_HOME"
_PREFIX = "cswap-policy-control-"


def _function(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, args
    return fn


def token_profile():
    """GetUserProfileDirectoryW uses the process token, not HOME or Shell state."""
    kernel = c.WinDLL("kernel32", use_last_error=True)
    advapi = c.WinDLL("advapi32", use_last_error=True)
    userenv = c.WinDLL("userenv", use_last_error=True)
    process = _function(kernel, "GetCurrentProcess", w.HANDLE)
    open_token = _function(advapi, "OpenProcessToken", w.BOOL, w.HANDLE,
                           w.DWORD, c.POINTER(w.HANDLE))
    close = _function(kernel, "CloseHandle", w.BOOL, w.HANDLE)
    locate = _function(userenv, "GetUserProfileDirectoryW", w.BOOL, w.HANDLE,
                       w.LPWSTR, c.POINTER(w.DWORD))
    token = w.HANDLE()
    if not open_token(process(), 8, c.byref(token)):  # TOKEN_QUERY
        raise RuntimeError("profile token query failed")
    try:
        size = w.DWORD()
        locate(token, None, c.byref(size))
        if not size.value:
            raise RuntimeError("profile size query failed")
        buffer = c.create_unicode_buffer(size.value)
        if not locate(token, buffer, c.byref(size)):
            raise RuntimeError("profile directory query failed")
        return Path(buffer.value)
    finally:
        close(token)


def _no_redirects(path):
    # Inspect lexical entries before resolve can hide a junction or symlink.
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("control path has a redirected entry")
    if not path.is_dir():
        raise RuntimeError("control path is not a directory")


def validate(home, *, basetemp=None, empty=False):
    profile = token_profile()
    if not home.is_absolute() or not re.fullmatch(_PREFIX + r"[0-9a-f]{32}", home.name):
        raise RuntimeError("invalid control directory name")
    _no_redirects(home)
    _no_redirects(profile)
    if not home.parent.samefile(profile):
        raise RuntimeError("control parent is not the token profile")
    if basetemp is not None:
        real_home, real_base = home.resolve(strict=True), basetemp.resolve(strict=True)
        if real_home.is_relative_to(real_base) or real_base.is_relative_to(real_home):
            raise RuntimeError("control overlaps pytest basetemp")
        # samefile also detects aliases not normalized by resolve.
        if any(parent.samefile(home) for parent in (basetemp, *basetemp.parents)):
            raise RuntimeError("pytest basetemp aliases the control")
        if any(parent.samefile(basetemp) for parent in (home, *home.parents)):
            raise RuntimeError("control aliases pytest basetemp")
    if empty and any(home.iterdir()):
        raise RuntimeError("control directory is not empty")
    return home


def prepare():
    profile = token_profile()
    _no_redirects(profile)
    home = profile / (_PREFIX + uuid4().hex)
    home.mkdir()  # Default security attributes: inherit directly from profile.
    try:
        validate(home, empty=True)
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            output.write(f"{ENV}={home}\n")
    except BaseException:
        home.rmdir()
        raise


def cleanup():
    value = os.environ.get(ENV)
    if value is None:
        return  # Preparation did not publish a directory.
    home = Path(value)
    validate(home)
    shutil.rmtree(home)


def main():
    try:
        if sys.platform != "win32":
            raise RuntimeError("native Windows required")
        if sys.argv[1:] == ["prepare"]:
            prepare()
        elif sys.argv[1:] == ["cleanup"]:
            cleanup()
        else:
            raise RuntimeError("expected prepare or cleanup")
    except Exception:
        # No OS exception text: it can contain paths or account identifiers.
        print("profile-control setup/cleanup failed (no account data emitted)")
        return 1
    print("profile-control step completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

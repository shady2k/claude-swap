"""Report the first legacy Windows executable identity mismatch, without values."""

import os
import stat
import sys
from pathlib import Path

from claude_swap._win_file_security import executable_identity_at_path, open_executable

_FIELDS = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
_EXECUTE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _legacy_field(before, after, change_before, change_after):
    for name in _FIELDS:
        left, right = getattr(before, name), getattr(after, name)
        if name == "st_mode":
            left, right = left & ~_EXECUTE_BITS, right & ~_EXECUTE_BITS
        if left != right:
            return name
    if change_before is not None and change_before != change_after:
        return "ChangeTime"
    return None


def _probe():
    checkpoint = "resolved-path"
    try:
        path = Path(sys.executable).resolve(strict=True)
        before = path.lstat()
        change_before = executable_identity_at_path(path).change_time
        field = _legacy_field(
            before, path.lstat(), change_before, executable_identity_at_path(path).change_time,
        )
        if field is not None:
            return f"legacy/{checkpoint}:{field}"
        checkpoint = "opened-fd"
        with os.fdopen(open_executable(path), "rb") as stream:
            field = _legacy_field(
                before, os.fstat(stream.fileno()), change_before,
                executable_identity_at_path(path).change_time,
            )
            if field is not None:
                return f"legacy/{checkpoint}:{field}"
            checkpoint = "before-launch-fd"
            field = _legacy_field(
                before, os.fstat(stream.fileno()), change_before,
                executable_identity_at_path(path).change_time,
            )
            if field is not None:
                return f"legacy/{checkpoint}:{field}"
            checkpoint = "before-launch-path"
            field = _legacy_field(
                before, path.lstat(), change_before, executable_identity_at_path(path).change_time,
            )
            if field is not None:
                return f"legacy/{checkpoint}:{field}"
    except (OSError, RuntimeError):
        return f"legacy/{checkpoint}:unavailable"
    return "legacy/no-mismatch"


if __name__ == "__main__":
    print(_probe() if sys.platform == "win32" else "legacy/non-windows")

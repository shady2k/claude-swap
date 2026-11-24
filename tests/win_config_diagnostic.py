"""Probe one Windows config CLI round trip without emitting paths or settings."""

import ctypes as c
import io
import os
import shutil
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from claude_swap import _win_file_security as security, fsguard
from claude_swap.exceptions import ConfigError

_SID_CATEGORIES = {
    "S-1-1-0": "everyone",
    "S-1-5-4": "interactive",
    "S-1-5-11": "authenticated-users",
    "S-1-5-32-545": "builtin-users",
    "S-1-5-32-546": "builtin-guests",
}
_WRITE_RIGHTS = (
    (0x00000002, "write-data"),
    (0x00000004, "append-data-or-add-subdirectory"),
    (0x00000010, "write-extended-attributes"),
    (0x00000040, "delete-child"),
    (0x00000100, "write-attributes"),
    (0x00010000, "delete"),
    (0x00040000, "write-dacl"),
    (0x00080000, "write-owner"),
    (0x10000000, "generic-all"),
    (0x40000000, "generic-write"),
)


def _exception_category(exc):
    if isinstance(exc, fsguard.GuardError):
        return "GuardError"
    if isinstance(exc, ConfigError):
        return "ConfigError"
    if isinstance(exc, PermissionError):
        return "PermissionError"
    if isinstance(exc, OSError):
        return "OSError"
    return "other" if exc is not None else "none"


def _observe_dacl(check_dacl, path, dacl, trusted, rejection):
    """Record the first rejected ACE while its descriptor is still live."""
    ace_pointer = c.c_void_p()
    function = security._function

    def observe(dll, name, result, *args):
        fn = function(dll, name, result, *args)
        if name != "GetAce":
            return fn

        def get_ace(dacl, index, out):
            ok = fn(dacl, index, out)
            if ok:
                ace_pointer.value = c.cast(out, c.POINTER(c.c_void_p)).contents.value
            return ok

        return get_ace

    try:
        with patch.object(security, "_function", observe):
            check_dacl(path, dacl, trusted)
    except fsguard.GuardError as exc:
        if ace_pointer.value and not rejection:
            ace = c.cast(ace_pointer, c.POINTER(security._ACE)).contents
            origin = "inherited" if ace.flags & 0x10 else "explicit"
            if str(exc).startswith("Writable by another user or group:"):
                sid = security._sid_string(ace_pointer.value + security._ACE.sid_start.offset)
                category = _SID_CATEGORIES.get(sid, "other-foreign")
                rights = ",".join(label for mask, label in _WRITE_RIGHTS if mask & ace.mask)
                rejection.append(f"allow/{origin}/{category} mask=0x{ace.mask:08x} rights={rights or 'none'}")
            elif str(exc).startswith("Unsupported access control entry:"):
                rejection.append(f"unsupported/{origin} rights=unknown")
        raise


def _stat_state(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unavailable"
    return "present"


def _config(args):
    from claude_swap import cli

    error = "none"

    def capture_error(*args, **kwargs):
        nonlocal error
        if error == "none":
            error = _exception_category(sys.exception())

    with (
        redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        patch.object(sys, "argv", ["cswap", "config", *args]),
        patch.object(cli, "error", capture_error),
    ):
        try:
            cli.main()
        except SystemExit as exc:
            code = "0" if exc.code in (0, None) else "1" if exc.code == 1 else "other"
        except Exception as exc:
            return "raised", _exception_category(exc)
        else:
            code = "0"
    return code, error


def _probe():
    from claude_swap import launch_policy, paths
    from tests.cli_unit_child import install

    install()  # Retain the CLI unit guard against real network and Keychain use.
    root = paths.get_backup_root()
    set_exit, set_error = _config(["set", "autoswitch.cooldownSeconds", "600"])
    root_state = _stat_state(root)
    print(f"config-set exit={set_exit} first-exception={set_error} root={root_state}")
    policy = root / "transparent.json"
    actual_exit, actual_error = _config(["list"])
    state = _stat_state(policy)
    print(f"config-list exit={actual_exit} first-exception={actual_error} policy={state}")
    actual_ok = (
        (set_exit, set_error, root_state) == ("0", "none", "present")
        and (actual_exit, actual_error, state) == ("0", "none", "absent")
    )

    read = launch_policy._read
    check_dacl = security._check_dacl
    rejection = []

    def root_first(path):
        # Replay the legacy ACL ordering, without changing any checks below it.
        info = launch_policy._windows_entry(path.parent, directory=True)
        if info is not None:
            fsguard.check_leaf(path.parent, info)
        return read(path)

    def inspect(path, dacl, trusted):
        _observe_dacl(check_dacl, path, dacl, trusted, rejection)

    with (
        patch.object(launch_policy, "_read", root_first),
        patch.object(security, "_check_dacl", inspect),
    ):
        legacy_exit, legacy_error = _config(["list"])
    ace = rejection[0] if rejection else "none"
    print(f"legacy-root-first exit={legacy_exit} first-exception={legacy_error} policy={state} ace={ace}")
    return 0 if actual_ok else 1


def main():
    if sys.platform != "win32":
        print("win-config non-windows")
        return 1
    # Use ordinary mkdir inheritance, as pytest's temp homes and the settings
    # writer do. Do not probe or change the developer's real backup directory.
    home = Path(tempfile.gettempdir()) / f"cswap-win-config-{uuid4().hex}"
    try:
        home.mkdir()
        try:
            from claude_swap import test_mode

            clean = dict(os.environ)
            for key in tuple(clean):
                if key.startswith(("CLAUDE_", "ANTHROPIC_", "XDG_")):
                    clean.pop(key)
            clean.update(HOME=str(home), USERPROFILE=str(home), NO_COLOR="1")
            clean[test_mode.MODE] = "1"
            with patch.dict(os.environ, clean, clear=True):
                return _probe()
        finally:
            shutil.rmtree(home)
    except Exception as exc:
        print(f"win-config unavailable first-exception={_exception_category(exc)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

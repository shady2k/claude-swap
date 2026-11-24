"""Transparent policy, consent and shared archive checks.

``transparent.json`` has one writer. Its transaction shares the slot lock so
selection and publication can compare the same recipient identity. Ordinary
preferences have a separate lock; launch publication acquires the slot lock
before the settings lock to make switching off history a publication barrier.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from collections.abc import Callable
from pathlib import Path

from claude_swap import fsguard, paths
from claude_swap.exceptions import ConfigError
from claude_swap.fsutil import atomic_write_text
from claude_swap.locking import FileLock

HISTORY_SCOPE = "all-history-v1"
CONSENT_TEXT = (
    "Shared history covers the entire projects/ archive, including past and future "
    "conversations from the default login and cswap run, even if that account is "
    "not in (or was removed from) the pool. Any approved recipient can resume "
    "these conversations and send them to Claude under that account. "
    "Disabling transparent mode does not take back anything already sent."
)
CONSENT_HINT = "Run cswap transparent enable to approve shared history for the pool (use --accept-shared-history without a terminal)."
_SLOT = re.compile(r"[1-9][0-9]*", re.ASCII)
Identity = tuple[str, str, str, str]


def _windows_entry(path: Path, *, directory: bool) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    is_expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not is_expected_type(info.st_mode)
            or info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or (not directory and info.st_nlink != 1)):
        raise fsguard.GuardError(f"Not an ordinary policy {'directory' if directory else 'file'}: {path}")
    return info


def _windows_policy_root(root: Path) -> os.stat_result | None:
    """Walk the data path without following links or testing ancestor ACLs."""
    if not root.is_absolute() or ".." in root.parts:
        raise fsguard.GuardError(f"Expected an absolute policy directory with no parent traversal: {root}")
    for parent in reversed(root.parents):
        if _windows_entry(parent, directory=True) is None:
            return None
    return _windows_entry(root, directory=True)


def _read(path: Path) -> dict:
    try:
        if sys.platform == "win32":
            root = _windows_policy_root(path.parent)
            if root is None:
                return {}
            info = _windows_entry(path, directory=False)
            if info is None:
                return {}
            # No policy is safe to treat as absent after the path walk. A
            # present policy requires trusted owner and write access on both
            # the backup root and the file, not on OS-owned ancestors.
            fsguard.check_leaf(path.parent, root)
            fsguard.check_leaf(path, info)
        else:
            if not os.path.lexists(path):
                return {}
            fsguard.check_path(path)
            if path.is_symlink() or not path.is_file():
                raise ValueError
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Could not read a valid {path.name}") from exc


def read(root: Path) -> dict:
    return _read(root / "transparent.json")


def update(root: Path, change: Callable[[dict], bool]) -> bool:
    """Read/modify/write under the slot lock. A true result adds one revision."""
    lock = paths.account_lock_path(root)
    if sys.platform == "win32":
        info = _windows_policy_root(root)
        if info is None:
            root.mkdir(parents=True, exist_ok=True)
            info = _windows_policy_root(root)
            if info is None:
                raise ConfigError("Could not create the policy directory")
        fsguard.check_leaf(root, info)
        lock_info = _windows_entry(lock, directory=False)
        if lock_info is not None:
            fsguard.check_leaf(lock, lock_info)
    elif root.exists():
        fsguard.check_path(root)
    with FileLock(lock):
        data = read(root)
        if not change(data):
            return False
        rev = data.get("rev", 0)
        if type(rev) is not int or rev < 0:
            raise ConfigError("Invalid transparent policy revision")
        data["rev"] = rev + 1
        atomic_write_text(root / "transparent.json", json.dumps(data, indent=2),
                          follow_symlinks=False)
        return True


def slots(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or any(
        not isinstance(value, str) or not _SLOT.fullmatch(value) for value in values
    ) or len(set(values)) != len(values):
        raise ConfigError("Transparent pool must contain distinct account numbers")
    return tuple(values)


def accounts(root: Path) -> dict:
    records = _read(root / "sequence.json").get("accounts", {})
    if not isinstance(records, dict):
        raise ConfigError("Invalid accounts in sequence.json")
    return records


def identity(record: object) -> Identity | None:
    if not isinstance(record, dict):
        return None
    fields = (record.get("email"), record.get("organizationUuid") or "",
              record.get("uuid") or "", record.get("kind") or "oauth")
    if not all(isinstance(field, str) for field in fields) or not fields[0] or not fields[2]:
        return None
    return fields


def consent(data: dict) -> dict:
    if data.get("enabled") is not True:
        raise ConfigError("Transparent mode is disabled; run cswap transparent enable")
    zone = data.get("historyZone")
    if not isinstance(zone, dict) or zone.get("scope") != HISTORY_SCOPE or not isinstance(zone.get("members"), dict):
        raise ConfigError(f"Current consent for the entire projects/ archive is required. {CONSENT_HINT}")
    return zone["members"]


def _owned_directory(path: Path) -> int:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ConfigError("Shared history must be a directory, not a link or junction")
    if sys.platform == "win32" or info.st_uid != os.geteuid():
        raise ConfigError("Shared history must be owned by the current user")
    fsguard.check_leaf(path, info)
    return info.st_mode


def archive(*, create: bool = False) -> Path:
    """Check the archive path, never its contents; create it privately if requested."""
    config_home = paths.get_default_claude_config_home()
    try:
        home = fsguard.check_path(config_home.parent)
        _owned_directory(home)
        target = home / config_home.name / "projects"
        for directory in (target.parent, target):
            try:
                mode = _owned_directory(directory)
            except FileNotFoundError:
                if not create:
                    break
                directory.mkdir(mode=0o700, exist_ok=True)
                mode = _owned_directory(directory)
            if directory == target and mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ConfigError("Shared projects/ must not be accessible to group or others")
        return target
    except (OSError, fsguard.GuardError) as exc:
        raise ConfigError("Shared projects/ is not a safe directory owned by the current user") from exc

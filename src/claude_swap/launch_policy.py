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


def _read(path: Path) -> dict:
    try:
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
    if root.exists():
        fsguard.check_path(root)
    with FileLock(paths.account_lock_path(root)):
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
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError("Shared history must be a directory")
    if sys.platform == "win32" or info.st_uid != os.geteuid():
        raise ConfigError("Shared history must be owned by the current user")
    return info.st_mode


def archive(*, create: bool = False) -> Path:
    """Check the archive path, never its contents; create it privately if requested."""
    home = Path.home()
    target = paths.get_default_claude_config_home() / "projects"
    try:
        fsguard.check_path(home, follow_links=False)
        _owned_directory(home)
        for directory in (target.parent, target):
            try:
                directory.lstat()
            except FileNotFoundError:
                if not create:
                    break
                directory.mkdir(mode=0o700, exist_ok=True)
            fsguard.check_path(directory, follow_links=False)
            mode = _owned_directory(directory)
            if directory == target and mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ConfigError("Shared projects/ must not be accessible to group or others")
        return target
    except (OSError, fsguard.GuardError) as exc:
        raise ConfigError("Shared projects/ is not a safe directory owned by the current user") from exc

"""Identity-scoped refresh rights and login generations.

The OS releases a consume right when its holder dies. Slot moves do not
change its path. Callers read credentials and login.gen together under the
account lock; only replacement logins advance login.gen, not token rotation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from claude_swap.fsutil import atomic_write_text
from claude_swap.locking import FileLock


def identity_key(email: str, org_uuid: str = "") -> str:
    value = json.dumps([email.lower(), org_uuid or ""], separators=(",", ":"))
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _directory(backup_dir: Path, email: str, org_uuid: str) -> Path:
    return backup_dir / "launch" / identity_key(email, org_uuid)


def consume_lock(backup_dir: Path, email: str, org_uuid: str = "", timeout: float = 10.0) -> FileLock:
    return FileLock(_directory(backup_dir, email, org_uuid) / "consume.lock", timeout=timeout)


def login_generation(backup_dir: Path, email: str, org_uuid: str = "") -> int:
    try:
        value = (_directory(backup_dir, email, org_uuid) / "login.gen").read_text(encoding="ascii")
    except FileNotFoundError:
        return 0
    generation = int(value)
    if generation < 0:
        raise ValueError("Invalid login generation")
    return generation


def advance_login_generation(backup_dir: Path, email: str, org_uuid: str = "") -> int:
    """Advance under the account lock before publishing a replacement login."""
    generation = login_generation(backup_dir, email, org_uuid) + 1
    path = _directory(backup_dir, email, org_uuid) / "login.gen"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write_text(path, str(generation), mode=0o600)
    return generation


class CredentialSnapshot(str):
    """Credential bytes bound to the identity and generation read with them."""

    def __new__(cls, value: str, identity: dict, login_gen: int):
        obj = super().__new__(cls, value)
        obj.identity = dict(identity)
        obj.login_gen = login_gen
        return obj


def ensure_identity_idle(backup_dir: Path, email: str, org_uuid: str = "") -> None:
    """Probe refresh authority without waiting while holding the account lock."""
    from claude_swap.exceptions import SessionError

    right = consume_lock(backup_dir, email, org_uuid, timeout=0)
    if not right.acquire(timeout=0):
        raise SessionError("Login refresh in progress; retry after it completes")
    right.release()

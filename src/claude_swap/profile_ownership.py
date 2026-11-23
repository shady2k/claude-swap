"""Cross-process ownership of isolated Claude profiles.

Each launch owns a separate record outside the profile, so removing a profile
cannot remove its lease. A reserved record spans preparation and a running
record spans process handoff. Neither has a timeout: elapsed time proves
nothing about a process. Unreadable records and unknown process identity block
mutation. Linux identity uses process start ticks, unchanged across exec.
Publication is unsupported where those ticks are unavailable, including macOS
and Windows; an unknown identity never authorizes handoff.

Callers take ``ownership_lock`` before the switcher lock. The ``*_locked``
functions do local I/O only and never acquire either lock. Network preparation
runs with a logical reservation but without either physical lock. Profile
generations live outside the profile and change only through
``advance_generation_locked`` after a guarded rebuild.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

from claude_swap.exceptions import SessionError
from claude_swap.fsutil import atomic_write_text
from claude_swap.locking import FileLock
from claude_swap.process_detection import process_start_ticks, scan_sessions


def _root(backup_dir: Path) -> Path:
    return backup_dir / "profile-ownership"


def ownership_lock(backup_dir: Path) -> FileLock:
    return FileLock(_root(backup_dir) / "state.lock")


def _pid_alive(pid: int) -> bool | None:
    """False only for proven absence; every other failure is unknown."""
    if sys.platform == "win32":
        # OpenProcess failures cannot distinguish denial from absence.
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return None
    return True


def _live(pid: int, ticks: str | None) -> bool:
    alive = _pid_alive(pid)
    if alive is False:
        return False
    current = process_start_ticks(pid)
    return not (ticks is not None and current is not None and ticks != current)


def _record_path(backup_dir: Path, launch_id: str) -> Path:
    # IDs are created here, never supplied as paths by a caller.
    if not isinstance(launch_id, str) or len(launch_id) != 32:
        raise SessionError("Invalid profile launch identifier")
    try:
        int(launch_id, 16)
    except ValueError as exc:
        raise SessionError("Invalid profile launch identifier") from exc
    return _root(backup_dir) / "launches" / f"{launch_id}.json"


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write_text(path, json.dumps(data), mode=0o600)


def _read(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Invalid ownership record")
    return data


def _validate(data: dict) -> None:
    for key in ("launchId", "accountNum", "profile", "profileGen"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise ValueError("Invalid ownership record")
    if data.get("state") not in ("reserved", "running"):
        raise ValueError("Invalid ownership state")
    if type(data.get("ownerPid")) is not int or data["ownerPid"] <= 0:
        raise ValueError("Invalid ownership process")
    if data.get("ownerTicks") is not None and not isinstance(data["ownerTicks"], str):
        raise ValueError("Invalid process identity")
    if type(data.get("warming")) is not bool:
        raise ValueError("Invalid warming state")
    if data["state"] == "running":
        if type(data.get("pid")) is not int or data["pid"] <= 0:
            raise ValueError("Invalid running process")
        if data.get("procStart") is not None and not isinstance(data["procStart"], str):
            raise ValueError("Invalid running identity")


def _records(backup_dir: Path) -> list[dict]:
    directory = _root(backup_dir) / "launches"
    try:
        paths = list(directory.iterdir())
    except FileNotFoundError:
        return []
    records = []
    for path in paths:
        record = _read(path)
        _validate(record)
        if path != _record_path(backup_dir, record["launchId"]):
            raise ValueError("Mismatched launch identifier")
        records.append(record)
    return records


def _profile_key(profile: Path) -> str:
    return os.path.normcase(str(profile.resolve()))


def profile_busy_locked(
    backup_dir: Path, account_num: str, session_dir: Path | None = None,
    *, ignore_launch_id: str | None = None,
) -> bool:
    """Whether any live or uncertain owner blocks this slot/profile.

    Corruption cannot safely be attributed to any slot, so blocks all slots.
    Dead reservations are ignored, not removed by a snapshot. Running records
    require explicit completion because a handoff can leave descendants.
    """
    try:
        records = _records(backup_dir)
        for data in records:
            if data["launchId"] == ignore_launch_id:
                continue
            if data["accountNum"] != str(account_num) and (
                session_dir is None or data["profile"] != _profile_key(session_dir)
            ):
                continue
            if data["state"] == "running":
                # A handoff may leave descendants after this PID exits.
                # Only explicit completion can relinquish running ownership.
                return True
            elif _live(data["ownerPid"], data.get("ownerTicks")):
                return True
        if session_dir is not None:
            live, unreadable = scan_sessions(session_dir)
            return bool(live or unreadable)
        return False
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return True


def _generation_path(backup_dir: Path, profile: Path) -> Path:
    import hashlib
    key = hashlib.sha256(_profile_key(profile).encode("utf-8")).hexdigest()
    return _root(backup_dir) / "generations" / f"{key}.json"


def _generation(backup_dir: Path, profile: Path) -> str:
    path = _generation_path(backup_dir, profile)
    try:
        generation = _read(path)["profileGen"]
    except FileNotFoundError:
        generation = uuid.uuid4().hex
        _write(path, {"profileGen": generation})
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise SessionError("Profile generation cannot be read") from exc
    if not isinstance(generation, str) or not generation:
        raise SessionError("Invalid profile generation")
    return generation


def reserve_locked(
    backup_dir: Path, account_num: str, session_dir: Path, *, warming: bool = False,
) -> dict:
    if profile_busy_locked(backup_dir, account_num, session_dir):
        raise SessionError(f"Account-{account_num} profile is busy or ownership is unknown")
    launch_id = uuid.uuid4().hex
    data = {
        "launchId": launch_id, "accountNum": str(account_num),
        "profile": _profile_key(session_dir),
        "profileGen": _generation(backup_dir, session_dir),
        "state": "reserved", "warming": warming,
        "ownerPid": os.getpid(), "ownerTicks": process_start_ticks(os.getpid()),
    }
    _write(_record_path(backup_dir, launch_id), data)
    return data


def verify_reservation_locked(
    backup_dir: Path, launch_id: str, *, expected_profile_gen: str | None = None,
) -> dict:
    """Re-read an own reservation and reject generation or owner changes."""
    try:
        data = _read(_record_path(backup_dir, launch_id))
        _validate(data)
        if data["ownerPid"] != os.getpid():
            raise ValueError("Ownership changed")
        ticks = process_start_ticks(os.getpid())
        if data["ownerTicks"] is not None and ticks is not None and data["ownerTicks"] != ticks:
            raise ValueError("Ownership changed")
        generation = _generation(backup_dir, Path(data["profile"]))
        if data["profileGen"] != generation or (
            expected_profile_gen is not None and expected_profile_gen != generation
        ):
            raise ValueError("Profile generation changed")
        return data
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise SessionError("Profile reservation cannot be verified") from exc


def mark_running_locked(
    backup_dir: Path, launch_id: str, pid: int,
    *, expected_profile_gen: str | None = None,
) -> None:
    if type(pid) is not int or pid <= 0:
        raise SessionError("Invalid running process")
    data = verify_reservation_locked(
        backup_dir, launch_id, expected_profile_gen=expected_profile_gen,
    )
    if data["state"] != "reserved":
        raise SessionError("Only a reserved profile can become running")
    if data["ownerTicks"] is None or process_start_ticks(os.getpid()) is None:
        raise SessionError("Profile owner process identity is unknown")
    ticks = process_start_ticks(pid)
    if ticks is None:
        raise SessionError("Running process identity is unknown")
    data.update(state="running", pid=pid, procStart=ticks, warming=False)
    _write(_record_path(backup_dir, launch_id), data)


def set_warming_locked(backup_dir: Path, launch_id: str, warming: bool) -> None:
    data = verify_reservation_locked(backup_dir, launch_id)
    data["warming"] = bool(warming)
    _write(_record_path(backup_dir, launch_id), data)


def advance_generation_locked(backup_dir: Path, launch_id: str) -> str:
    """Advance a reserved profile generation after its guarded rebuild."""
    data = verify_reservation_locked(backup_dir, launch_id)
    if data["state"] != "reserved":
        raise SessionError("Cannot rebuild a running profile")
    generation = uuid.uuid4().hex
    _write(_generation_path(backup_dir, Path(data["profile"])), {"profileGen": generation})
    data["profileGen"] = generation
    _write(_record_path(backup_dir, launch_id), data)
    return generation


def release_locked(
    backup_dir: Path, launch_id: str, *, confirmed_complete: bool = False,
) -> None:
    """Remove an own record; running work requires proven tree completion."""
    path = _record_path(backup_dir, launch_id)
    if not path.exists():
        return
    try:
        data = _read(path)
        _validate(data)
        ticks = process_start_ticks(os.getpid())
        if data["ownerPid"] != os.getpid() or (
            data["ownerTicks"] is not None and ticks is not None and data["ownerTicks"] != ticks
        ):
            raise ValueError("Ownership changed")
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise SessionError("Profile reservation cannot be released") from exc
    if data["state"] == "running" and not confirmed_complete:
        raise SessionError("Running profile requires confirmed completion")
    path.unlink()


@contextmanager
def reservation(backup_dir: Path, account_num: str, session_dir: Path, *, warming=False):
    with ownership_lock(backup_dir):
        data = reserve_locked(backup_dir, account_num, session_dir, warming=warming)
    try:
        yield data
    finally:
        with ownership_lock(backup_dir):
            path = _record_path(backup_dir, data["launchId"])
            if path.exists() and _read(path).get("state") == "reserved":
                release_locked(backup_dir, data["launchId"])

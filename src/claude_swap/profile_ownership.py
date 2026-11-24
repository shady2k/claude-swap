"""Cross-process ownership of isolated Claude profiles.

Each launch owns a separate record outside the profile, so removing a profile
cannot remove its lease. A reserved record spans preparation and a running
record spans process handoff. Concurrent reservations may prepare the same
profile; generation checks detect changes, while running readers block profile
mutation. Neither record has a timeout: elapsed time proves nothing about a
process. Unreadable records and unknown process identity block mutation.
Linux identity uses process start ticks, unchanged across exec. A trustworthy
machine identity and different boot ID prove an old tree ended; missing or
foreign boot metadata never authorizes clearing running ownership.
Windows identity uses the process creation FILETIME read through one handle.
Saved Windows times are bounded ASCII decimals, compared numerically; unknown
or foreign identities retain protection. Publication requires a confirmed owner
and child identity; it remains unsupported where start times are unavailable,
including macOS.

Callers take ``ownership_lock`` before the switcher lock. The ``*_locked``
functions do local I/O only and never acquire either lock. Network preparation
runs with a logical reservation but without either physical lock. Profile
generations live outside the profile. A backup mutation invalidates the
external generation without touching a busy profile; a guarded rebuild
advances the reserved generation.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from claude_swap.exceptions import SessionError
from claude_swap.fsutil import atomic_write_text
from claude_swap.locking import FileLock
from claude_swap.process_detection import process_start_ticks, scan_sessions


def _root(backup_dir: Path) -> Path:
    return backup_dir / "profile-ownership"


class ProfileGenerationChanged(SessionError):
    """The reservation's profile was rebuilt or invalidated by a peer."""


_ownership_locks = threading.local()


class _OwnershipLock(FileLock):
    """One thread's nested uses share a single OS lock and descriptor."""

    def __init__(self, path: Path):
        super().__init__(path)
        self.depth = 0

    def acquire(self, timeout: float | None = None) -> bool:
        if self.depth:
            self.depth += 1
            return True
        if not super().acquire(timeout):
            return False
        self.depth = 1
        return True

    def release(self) -> None:
        if self.depth:
            self.depth -= 1
            if not self.depth:
                super().release()


def ownership_lock(backup_dir: Path) -> FileLock:
    """State lock, reentrant only in the calling thread and process."""
    key = (os.getpid(), str((_root(backup_dir) / "state.lock").resolve()))
    locks = getattr(_ownership_locks, "locks", None)
    if locks is None:
        locks = _ownership_locks.locks = {}
    if key not in locks:
        locks[key] = _OwnershipLock(Path(key[1]))
    return locks[key]


def _boot_identity() -> tuple[str, str] | None:
    """Identify a Linux boot on this machine, never infer it from PID ticks.

    Both identifiers come from OS files, not the profile or environment. A
    different machine ID cannot prove completion of a copied ownership store.
    """
    if sys.platform != "linux":
        return None
    try:
        machine = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        if len(machine) != 32 or uuid.UUID(hex=machine).hex != machine.lower():
            return None
        if not int(machine, 16):
            return None
        boot_id = uuid.UUID(boot)
        if not boot_id.int:
            return None
        return machine.lower(), str(boot_id)
    except (OSError, ValueError, UnicodeError):
        return None


def _previous_boot(data: dict) -> bool:
    current = _boot_identity()
    if not current or data.get("machineId") != current[0]:
        return False
    try:
        recorded = uuid.UUID(data["bootId"])
        current_boot = uuid.UUID(current[1])
    except (ValueError, TypeError, KeyError, AttributeError):
        return False
    return bool(recorded.int and current_boot.int and recorded != current_boot)


def _pid_alive(pid: int) -> bool | None:
    """False only for proven absence; every other failure is unknown."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return None
    return True


@dataclass(frozen=True)
class _WindowsStart:
    filetime: int


@dataclass(frozen=True)
class _PosixStart:
    ticks: str


@dataclass(frozen=True)
class _ProcessIdentity:
    state: str
    start: _WindowsStart | _PosixStart | None
    platform: str


def _process_identity(pid: int) -> _ProcessIdentity:
    """One locally replaceable reader; Windows uses one handle for both facts."""
    if sys.platform == "win32":
        from claude_swap._win_process import process_identity
        state, ticks = process_identity(pid)
        return _ProcessIdentity(
            "unknown" if state == "denied" else state,
            _WindowsStart(ticks) if ticks is not None else None, "win32",
        )
    alive = _pid_alive(pid)
    ticks = process_start_ticks(pid)
    return _ProcessIdentity(
        "absent" if alive is False else "present" if alive else "unknown",
        _PosixStart(ticks) if ticks is not None else None, sys.platform,
    )


def _parse_start(value: str | None, platform: str) -> _WindowsStart | _PosixStart | None:
    """Decode persisted identity without accepting foreign or unbounded FILETIME."""
    if not isinstance(value, str):
        return None
    if platform != "win32":
        return None if value.startswith("win32:") else _PosixStart(value)
    if not value.startswith("win32:") or len(value) > 256:
        return None
    digits = value[6:]
    if not digits or any(c < "0" or c > "9" for c in digits):
        return None
    number = int(digits)
    return _WindowsStart(number) if 1 <= number <= 2**64 - 1 else None


def _compare_start(stored, current: _ProcessIdentity) -> str:
    """Match/different/unknown; only trustworthy same-type values prove reuse."""
    if stored is None or current.state == "absent" or current.start is None:
        return "unknown"
    if current.platform == "win32" and current.state != "present":
        return "unknown"
    if type(stored) is not type(current.start):
        return "unknown"
    return "match" if stored == current.start else "different"


def _encoded_start(identity: _ProcessIdentity) -> str | None:
    if identity.state != "present":
        return None
    if isinstance(identity.start, _WindowsStart):
        return f"win32:{identity.start.filetime}"
    if isinstance(identity.start, _PosixStart):
        return identity.start.ticks
    return None


def _owner_matches(data: dict, *, require_known: bool = False) -> bool:
    if data["ownerPid"] != os.getpid():
        return False
    current = _process_identity(data["ownerPid"])
    stored = _parse_start(data.get("ownerTicks"), current.platform)
    comparison = _compare_start(stored, current)
    if current.platform == "win32" or require_known or (
        isinstance(data.get("ownerTicks"), str) and data["ownerTicks"].startswith("win32:")
    ):
        return comparison == "match"
    # Preserve POSIX's permissive own-reservation checks when ticks are missing.
    return comparison != "different"


def _live(pid: int, ticks: str | None) -> bool:
    current = _process_identity(pid)
    stored = _parse_start(ticks, current.platform)
    if stored is None and (
        current.platform == "win32" or isinstance(ticks, str) and ticks.startswith("win32:")
    ):
        return True
    if current.state == "absent":
        return False
    return _compare_start(stored, current) != "different"


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
        if path.name.endswith(".tmp"):
            continue
        record = _read(path)
        _validate(record)
        if path != _record_path(backup_dir, record["launchId"]):
            raise ValueError("Mismatched launch identifier")
        records.append(record)
    return records


def profile_key(profile: Path) -> str:
    """Canonical key shared by ownership records and handoff validation."""
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
            if _previous_boot(data):
                continue
            if data["launchId"] == ignore_launch_id:
                continue
            if data["accountNum"] != str(account_num) and (
                session_dir is None or data["profile"] != profile_key(session_dir)
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
    key = hashlib.sha256(profile_key(profile).encode("utf-8")).hexdigest()
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


def profile_running_locked(
    backup_dir: Path, account_num: str, session_dir: Path | None = None,
    *, ignore_launch_id: str | None = None,
) -> bool:
    """Protect profile contents, without treating preparations as readers.

    Reserved/warming peers can invalidate each other's prepared generation.
    A running or unknown owner forbids overwriting or deleting the profile.
    """
    try:
        for data in _records(backup_dir):
            if _previous_boot(data) or data["launchId"] == ignore_launch_id:
                continue
            if data["accountNum"] != str(account_num) and (
                session_dir is None or data["profile"] != profile_key(session_dir)
            ):
                continue
            if data["state"] == "running":
                return True
        if session_dir is not None:
            live, unreadable = scan_sessions(session_dir)
            return bool(live or unreadable)
        return False
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return True


def check_admission_locked(backup_dir: Path, account_num: str, session_dir: Path) -> None:
    """Refuse uncertain legacy ownership before preparation or reuse."""
    # Known supervised peers permit reuse; legacy processes have no external
    # completion authority. Unknown or unreadable legacy ownership refuses
    # admission before any probe or credential preparation.
    try:
        records = _records(backup_dir)
        live, unreadable = scan_sessions(session_dir)
        supervised = any(
            data["state"] == "running" and not _previous_boot(data)
            and data["accountNum"] == str(account_num)
            and data["profile"] == profile_key(session_dir)
            for data in records
        )
        if unreadable or (live and not supervised):
            raise SessionError("Profile has live or unknown legacy ownership")
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        raise SessionError("Profile ownership cannot be read") from exc


def reserve_locked(
    backup_dir: Path, account_num: str, session_dir: Path, *, warming: bool = False,
    refresh_right_held: bool = False,
) -> dict:
    """Reserve under state and account locks; probe unless caller holds the right.

    A caller waiting for the right must acquire it before the account lock
    and verify the selected identity under that lock before passing True.
    """
    from claude_swap.refresh_authority import ensure_identity_idle

    try:
        sequence = json.loads((backup_dir / "sequence.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        sequence = {}
    except (OSError, ValueError) as exc:
        raise SessionError("Login identity cannot be read") from exc
    identity = sequence.get("accounts", {}).get(str(account_num), {})
    if identity.get("email") and not refresh_right_held:
        ensure_identity_idle(
            backup_dir, identity["email"], identity.get("organizationUuid") or ""
        )
    check_admission_locked(backup_dir, account_num, session_dir)
    launch_id = uuid.uuid4().hex
    data = {
        "launchId": launch_id, "accountNum": str(account_num),
        "profile": profile_key(session_dir),
        "profileGen": _generation(backup_dir, session_dir),
        "state": "reserved", "warming": warming,
        "ownerPid": os.getpid(), "ownerTicks": _encoded_start(_process_identity(os.getpid())),
    }
    if boot := _boot_identity():
        data.update(machineId=boot[0], bootId=boot[1])
    _write(_record_path(backup_dir, launch_id), data)
    return data


def verify_reservation_locked(
    backup_dir: Path, launch_id: str, *, expected_profile_gen: str | None = None,
) -> dict:
    """Re-read an own reservation and reject generation or owner changes."""
    return _verified_reservation(backup_dir, launch_id, expected_profile_gen=expected_profile_gen)


def _verified_reservation(
    backup_dir: Path, launch_id: str, *, expected_profile_gen: str | None = None,
    require_known: bool = False,
) -> dict:
    try:
        data = _read(_record_path(backup_dir, launch_id))
        _validate(data)
        if not _owner_matches(data, require_known=require_known):
            raise ValueError("Ownership changed")
        generation = _generation(backup_dir, Path(data["profile"]))
        if data["profileGen"] != generation or (
            expected_profile_gen is not None and expected_profile_gen != generation
        ):
            raise ProfileGenerationChanged("Profile generation changed")
        return data
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise SessionError("Profile reservation cannot be verified") from exc


def mark_running_locked(
    backup_dir: Path, launch_id: str, pid: int,
    *, expected_profile_gen: str | None = None,
) -> None:
    if type(pid) is not int or pid <= 0:
        raise SessionError("Invalid running process")
    data = _verified_reservation(
        backup_dir, launch_id, expected_profile_gen=expected_profile_gen, require_known=True,
    )
    if data["state"] != "reserved":
        raise SessionError("Only a reserved profile can become running")
    ticks = _encoded_start(_process_identity(pid))
    if ticks is None:
        raise SessionError("Running process identity is unknown")
    data.update(state="running", pid=pid, procStart=ticks, warming=False)
    _write(_record_path(backup_dir, launch_id), data)


def acknowledge_generation_locked(
    backup_dir: Path, launch_id: str, expected_previous_gen: str,
) -> str:
    """Adopt the generation produced by a reservation's own warming refresh.

    Before calling, the caller holds state then account lock and verifies
    that the current backup identity and credential equal its refresh result.
    That comparison, not this metadata operation, excludes unrelated writes.
    """
    try:
        path = _record_path(backup_dir, launch_id)
        data = _read(path)
        _validate(data)
        if (
            not _owner_matches(data, require_known=True)
            or data["state"] != "reserved" or not data["warming"]
            or data["profileGen"] != expected_previous_gen
        ):
            raise ValueError("Warming ownership changed")
        generation = _generation(backup_dir, Path(data["profile"]))
        data["profileGen"] = generation
        _write(path, data)
        return generation
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise SessionError("Warming generation cannot be acknowledged") from exc


def set_warming_locked(backup_dir: Path, launch_id: str, warming: bool) -> None:
    data = verify_reservation_locked(backup_dir, launch_id)
    data["warming"] = bool(warming)
    _write(_record_path(backup_dir, launch_id), data)


def invalidate_generation_locked(backup_dir: Path, profile: Path) -> str:
    """Mark a profile stale after a backup mutation, including while busy.

    This changes external metadata only; it never writes a running profile.
    The caller holds the ownership state lock before the account lock.
    """
    generation = uuid.uuid4().hex
    _write(_generation_path(backup_dir, profile), {"profileGen": generation})
    return generation


def invalidate_all_generations_locked(backup_dir: Path) -> None:
    """Reject busy/unknown ownership, then invalidate every known profile.

    Caller holds the state lock across this check and the destructive purge.
    All records and generations are read before any generation is changed.
    """
    try:
        records = _records(backup_dir)
        for data in records:
            if profile_busy_locked(backup_dir, data["accountNum"], Path(data["profile"])):
                raise SessionError("Cannot purge while a profile is busy or ownership is unknown")
        directory = _root(backup_dir) / "generations"
        try:
            generations = list(directory.iterdir())
        except FileNotFoundError:
            generations = []
        for path in generations:
            generation = _read(path)["profileGen"]
            if not isinstance(generation, str) or not generation:
                raise ValueError("Invalid profile generation")
        for path in generations:
            _write(path, {"profileGen": uuid.uuid4().hex})
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise SessionError("Profile ownership cannot be verified for purge") from exc


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
    try:
        path.stat()
    except FileNotFoundError:
        return
    try:
        data = _read(path)
        _validate(data)
        if not _owner_matches(data):
            raise ValueError("Ownership changed")
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise SessionError("Profile reservation cannot be released") from exc
    if data["state"] == "running" and not confirmed_complete:
        raise SessionError("Running profile requires confirmed completion")
    path.unlink()


def _diagnose_release(message: str) -> None:
    """Report release state without letting a failed sink change cleanup."""
    try:
        print(message, file=sys.stderr)
    except (OSError, ValueError):
        pass


def release_aborted(backup_dir: Path, launch_id: str) -> None:
    """Release an own launch refused before fork with one bounded lock wait.

    Publication may have marked the record running, but no child was created.
    On contention retain the record and restore ordinary signal handling
    rather than retrying while termination signals are blocked.
    """
    with ownership_lock(backup_dir):
        release_locked(backup_dir, launch_id, confirmed_complete=True)


def release_completed(backup_dir: Path, launch_id: str) -> None:
    """Release this launch after supervision proved the whole tree empty.

    Lock contention cannot undo completion. Retry each bounded acquisition
    outside all other locks without an overall deadline. I/O errors are not
    contention and are reported rather than retried forever.
    """
    lock = ownership_lock(backup_dir)
    waiting_reported = False
    try:
        while not lock.acquire():
            if not waiting_reported:
                _diagnose_release("Waiting for profile ownership lock to release completed launch.")
                waiting_reported = True
    except OSError as exc:
        _diagnose_release("Error acquiring completed launch state lock; ownership retained.")
        raise SessionError("Completed launch state lock cannot be opened") from exc
    try:
        release_locked(backup_dir, launch_id, confirmed_complete=True)
    except (OSError, SessionError) as exc:
        raise SessionError("Completed launch record cannot be read or removed") from exc
    finally:
        lock.release()


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

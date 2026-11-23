"""External profile ownership, using only synthetic processes and profiles."""

import json

import pytest

from claude_swap import profile_ownership as ownership


@pytest.fixture
def processes(monkeypatch):
    monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
        "present", ownership._PosixStart("123"), "linux",
    ))


def test_reservation_is_external_and_busy(tmp_path, processes):
    profile = tmp_path / "sessions" / "1-user"
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", profile)
        assert record["state"] == "reserved"
        assert record["profileGen"]
        assert ownership.profile_busy_locked(tmp_path, "1", profile)
        assert not ownership.profile_busy_locked(tmp_path, "2")
        assert not ownership.profile_busy_locked(
            tmp_path, "1", profile, ignore_launch_id=record["launchId"]
        )
    assert not profile.exists()


def test_release_removes_only_own_launch(tmp_path, processes):
    profile = tmp_path / "sessions" / "1-user"
    with ownership.ownership_lock(tmp_path):
        first = ownership.reserve_locked(tmp_path, "1", profile)
        second = ownership.reserve_locked(tmp_path, "2", tmp_path / "other")
        ownership.release_locked(tmp_path, first["launchId"])
        assert ownership.profile_busy_locked(tmp_path, "2")
        assert not ownership.profile_busy_locked(tmp_path, "1", profile)
        ownership.release_locked(tmp_path, second["launchId"])
        assert not ownership.profile_busy_locked(tmp_path, "2")


def test_running_record_tracks_child_identity(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
            "present", ownership._PosixStart("999"), "linux",
        ))
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_unknown_process_identity_is_busy(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
            "present", None, "linux",
        ))
        assert ownership.profile_busy_locked(tmp_path, "1")
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity("unknown", None, "linux"))
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_dead_launcher_does_not_block(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity("absent", None, "linux"))
        assert not ownership.profile_busy_locked(tmp_path, "1")


def test_corrupt_record_fails_closed(tmp_path):
    records = tmp_path / "profile-ownership" / "launches"
    records.mkdir(parents=True)
    (records / "broken.json").write_text("{", encoding="utf-8")
    with ownership.ownership_lock(tmp_path):
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_unreadable_claude_session_fails_closed(tmp_path):
    profile = tmp_path / "profile"
    sessions = profile / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "broken.json").write_text("{", encoding="utf-8")
    with ownership.ownership_lock(tmp_path):
        assert ownership.profile_busy_locked(tmp_path, "1", profile)


def test_generation_survives_launch_release(tmp_path, processes):
    profile = tmp_path / "profile"
    with ownership.ownership_lock(tmp_path):
        first = ownership.reserve_locked(tmp_path, "1", profile)
        ownership.release_locked(tmp_path, first["launchId"])
        second = ownership.reserve_locked(tmp_path, "1", profile)
        assert second["profileGen"] == first["profileGen"]


def test_reserved_slot_allows_independent_reservations(tmp_path, processes):
    profile = tmp_path / "profile"
    with ownership.ownership_lock(tmp_path):
        first = ownership.reserve_locked(tmp_path, "1", profile, warming=True)
        second = ownership.reserve_locked(tmp_path, "1", profile)
        assert first["launchId"] != second["launchId"]
        assert not ownership.profile_running_locked(tmp_path, "1", profile)
        ownership.mark_running_locked(tmp_path, first["launchId"], 4242)
        assert ownership.profile_running_locked(tmp_path, "1", profile)
        third = ownership.reserve_locked(tmp_path, "1", profile)
        assert third["launchId"] not in {first["launchId"], second["launchId"]}
        assert ownership.profile_busy_locked(tmp_path, "1", profile)


def test_generation_change_rejects_prepared_launch(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        generation = ownership.advance_generation_locked(tmp_path, record["launchId"])
        assert generation != record["profileGen"]
        with pytest.raises(ownership.SessionError):
            ownership.mark_running_locked(
                tmp_path, record["launchId"], 4242,
                expected_profile_gen=record["profileGen"],
            )
        ownership.mark_running_locked(
            tmp_path, record["launchId"], 4242, expected_profile_gen=generation,
        )


def test_release_cannot_remove_other_process_launch(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership.os, "getpid", lambda: 777777)
        with pytest.raises(ownership.SessionError):
            ownership.release_locked(tmp_path, record["launchId"])
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_running_ownership_survives_holder_death(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity("absent", None, "linux"))
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_malformed_generation_blocks_admission_with_session_error(tmp_path, processes):
    profile = tmp_path / "profile"
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", profile)
        ownership.release_locked(tmp_path, record["launchId"])
        ownership._generation_path(tmp_path, profile).write_text("{", encoding="utf-8")
        with pytest.raises(ownership.SessionError):
            ownership.reserve_locked(tmp_path, "1", profile)


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="POSIX kill probe")
def test_pid_probe_permission_error_is_unknown(monkeypatch):
    def denied(pid, signal):
        raise PermissionError("denied")
    monkeypatch.setattr(ownership.os, "kill", denied)
    assert ownership._pid_alive(12345) is None


def test_unreadable_external_directory_blocks_all_slots(tmp_path, monkeypatch):
    directory = tmp_path / "profile-ownership" / "launches"
    original = ownership.Path.iterdir
    def denied(path):
        if path == directory:
            raise PermissionError("denied")
        return original(path)
    monkeypatch.setattr(ownership.Path, "iterdir", denied)
    assert ownership.profile_busy_locked(tmp_path, "1")


def test_warming_can_be_cleared_only_by_owner(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile", warming=True)
        assert ownership.verify_reservation_locked(tmp_path, record["launchId"])["warming"]
        ownership.set_warming_locked(tmp_path, record["launchId"], False)
        assert not ownership.verify_reservation_locked(tmp_path, record["launchId"])["warming"]


def test_own_release_still_works_after_generation_changed(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        profile = tmp_path / "profile"
        record = ownership.reserve_locked(tmp_path, "1", profile)
        ownership._generation_path(tmp_path, profile).write_text(
            json.dumps({"profileGen": "replacement"}), encoding="utf-8",
        )
        ownership.release_locked(tmp_path, record["launchId"])
        assert not ownership.profile_busy_locked(tmp_path, "1", profile)


def test_running_record_remains_busy_after_target_death(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity("absent", None, "linux"))
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_running_release_requires_confirmed_completion(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        with pytest.raises(ownership.SessionError, match="completion"):
            ownership.release_locked(tmp_path, record["launchId"])
        ownership.release_locked(tmp_path, record["launchId"], confirmed_complete=True)
        assert not ownership.profile_busy_locked(tmp_path, "1")


def test_unknown_owner_ticks_cannot_publish(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
            "present", None, "linux",
        ))
        with pytest.raises(ownership.SessionError):
            ownership.mark_running_locked(tmp_path, record["launchId"], 4242)


def test_reservation_context_retains_running_on_error(tmp_path, processes):
    with pytest.raises(RuntimeError, match="handoff"):
        with ownership.reservation(tmp_path, "1", tmp_path / "profile") as record:
            with ownership.ownership_lock(tmp_path):
                ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
            raise RuntimeError("handoff")
    with ownership.ownership_lock(tmp_path):
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_running_publication_is_one_way(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        with pytest.raises(ownership.SessionError, match="reserved"):
            ownership.mark_running_locked(tmp_path, record["launchId"], 4343)


def test_generation_invalidation_is_external(tmp_path, processes):
    profile = tmp_path / "profile"
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", profile)
        generation = ownership.invalidate_generation_locked(tmp_path, profile)
        assert generation != record["profileGen"]
        assert not profile.exists()
        with pytest.raises(ownership.ProfileGenerationChanged):
            ownership.verify_reservation_locked(tmp_path, record["launchId"])


def test_ownership_lock_reentrant_for_same_thread(tmp_path):
    outer = ownership.ownership_lock(tmp_path)
    with outer:
        with ownership.ownership_lock(tmp_path) as inner:
            assert inner is outer


@pytest.mark.skipif(__import__("sys").platform != "linux", reason="Linux subreaper")
def test_real_supervision_frees_profile_after_descendant_completion(tmp_path):
    import subprocess
    import sys

    code = r"""
import os, sys, time
from pathlib import Path
from claude_swap import spawn, profile_ownership as ownership
root = Path(sys.argv[1])
profile = root / "synthetic-profile"
with ownership.ownership_lock(root):
    record = ownership.reserve_locked(root, "1", profile)
    ownership.mark_running_locked(root, record["launchId"], os.getpid())
def launch():
    if os.fork() == 0:
        os.setsid()
        with ownership.ownership_lock(root):
            assert ownership.profile_busy_locked(root, "1", profile)
        time.sleep(0.05)
        os._exit(0)
    os._exit(0)
assert spawn.supervise(launch) == 0
with ownership.ownership_lock(root):
    ownership.release_locked(root, record["launchId"], confirmed_complete=True)
    assert not ownership.profile_busy_locked(root, "1", profile)
"""
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_invalidate_all_rejects_busy_before_rotating(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        first = ownership.reserve_locked(tmp_path, "1", tmp_path / "one")
        ownership.release_locked(tmp_path, first["launchId"])
        ownership.reserve_locked(tmp_path, "2", tmp_path / "two")
        with pytest.raises(ownership.SessionError, match="busy"):
            ownership.invalidate_all_generations_locked(tmp_path)
        assert ownership._generation(tmp_path, tmp_path / "one") == first["profileGen"]


def test_invalidate_all_rotates_idle_and_rejects_corruption(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "one")
        ownership.release_locked(tmp_path, record["launchId"])
        ownership.invalidate_all_generations_locked(tmp_path)
        assert ownership._generation(tmp_path, tmp_path / "one") != record["profileGen"]
        directory = tmp_path / "profile-ownership" / "launches"
        (directory / "corrupt.json").write_text("{")
        with pytest.raises(ownership.SessionError):
            ownership.invalidate_all_generations_locked(tmp_path)


def test_warming_acknowledgement_requires_reserved_owner_and_previous_generation(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "one", warming=True)
        current = ownership.invalidate_generation_locked(tmp_path, tmp_path / "one")
        with pytest.raises(ownership.SessionError):
            ownership.acknowledge_generation_locked(tmp_path, record["launchId"], "wrong")
        assert ownership.acknowledge_generation_locked(
            tmp_path, record["launchId"], record["profileGen"],
        ) == current
        assert ownership.verify_reservation_locked(tmp_path, record["launchId"])["profileGen"] == current
        ownership.set_warming_locked(tmp_path, record["launchId"], False)
        with pytest.raises(ownership.SessionError):
            ownership.acknowledge_generation_locked(tmp_path, record["launchId"], current)


@pytest.mark.parametrize("old,current,expected", [
    (("machine", "old"), ("machine", "new"), False),
    (("machine", "same"), ("machine", "same"), True),
    (("machine", "old"), None, True),
    (None, ("machine", "new"), True),
    (("foreign", "old"), ("machine", "new"), True),
])
def test_running_completion_requires_proven_same_machine_reboot(
    tmp_path, processes, monkeypatch, old, current, expected,
):
    tags = {"old": "11111111-1111-1111-1111-111111111111",
            "new": "22222222-2222-2222-2222-222222222222",
            "same": "33333333-3333-3333-3333-333333333333"}
    old = (old[0], tags[old[1]]) if old else None
    current = (current[0], tags[current[1]]) if current else None
    monkeypatch.setattr(ownership, "_boot_identity", lambda: old)
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        monkeypatch.setattr(ownership, "_boot_identity", lambda: current)
        assert ownership.profile_busy_locked(tmp_path, "1") is expected


def test_abandoned_atomic_temp_does_not_block_any_profile(tmp_path):
    directory = tmp_path / "profile-ownership" / "launches"
    directory.mkdir(parents=True)
    (directory / "record.json.random.tmp").write_text("{")
    with ownership.ownership_lock(tmp_path):
        assert not ownership.profile_busy_locked(tmp_path, "1")


@pytest.mark.parametrize("current,expected", [("123", True), ("456", False), (None, True)])
def test_reserved_pid_reuse_is_not_running_tree_completion(tmp_path, processes, monkeypatch, current, expected):
    with ownership.ownership_lock(tmp_path):
        ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
            "present", ownership._PosixStart(current) if current is not None else None, "linux",
        ))
        assert ownership.profile_busy_locked(tmp_path, "1") is expected


def test_completed_release_retries_after_lock_timeout(tmp_path, processes, monkeypatch):
    import threading
    from claude_swap.locking import FileLock
    ready = threading.Event()
    timed_out = threading.Event()
    errors = []
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)

    def competitor():
        try:
            with FileLock(ownership._root(tmp_path) / "state.lock"):
                ready.set()
                assert timed_out.wait(5)
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=competitor)
    thread.start()
    try:
        assert ready.wait(5)
        lock = ownership.ownership_lock(tmp_path)
        acquire = lock.acquire
        def acquire_short(timeout=None):
            result = acquire(timeout=0.02)
            if not result:
                timed_out.set()
            return result
        monkeypatch.setattr(lock, "acquire", acquire_short)
        ownership.release_completed(tmp_path, record["launchId"])
    finally:
        timed_out.set()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert timed_out.is_set()
    assert not ownership._record_path(tmp_path, record["launchId"]).exists()


@pytest.mark.parametrize("failure", ["read", "unlink", "lock"])
def test_completed_release_reports_permanent_io_errors(tmp_path, processes, monkeypatch, failure):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
    def denied(*args, **kwargs):
        raise PermissionError("synthetic storage error")
    if failure == "read":
        monkeypatch.setattr(ownership, "_read", denied)
    elif failure == "unlink":
        monkeypatch.setattr(ownership.Path, "unlink", denied)
    else:
        monkeypatch.setattr(ownership.ownership_lock(tmp_path), "acquire", denied)
    with pytest.raises(ownership.SessionError, match="Completed launch"):
        ownership.release_completed(tmp_path, record["launchId"])
    assert ownership._record_path(tmp_path, record["launchId"]).exists()


def test_malformed_boot_tag_does_not_prove_completion(tmp_path, processes, monkeypatch):
    monkeypatch.setattr(ownership, "_boot_identity", lambda: ("a" * 32, "11111111-1111-1111-1111-111111111111"))
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        path = ownership._record_path(tmp_path, record["launchId"])
        data = ownership._read(path)
        data["bootId"] = "not-a-boot-id"
        ownership._write(path, data)
        assert ownership.profile_busy_locked(tmp_path, "1")


@pytest.mark.skipif(__import__("sys").platform != "linux", reason="Linux boot files")
@pytest.mark.parametrize("machine,boot,available", [
    ("a" * 32, "11111111-1111-1111-1111-111111111111", True),
    ("", "11111111-1111-1111-1111-111111111111", False),
    ("0" * 32, "11111111-1111-1111-1111-111111111111", False),
    ("a" * 32, "not-a-boot", False),
    ("a" * 32, "00000000-0000-0000-0000-000000000000", False),
])
def test_boot_identity_requires_os_identifiers(monkeypatch, machine, boot, available):
    def read(path, **kwargs):
        return machine if str(path) == "/etc/machine-id" else boot
    monkeypatch.setattr(ownership.Path, "read_text", read)
    assert (ownership._boot_identity() is not None) is available


def test_completed_release_does_not_hide_record_stat_error(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
    path = ownership._record_path(tmp_path, record["launchId"])
    original = ownership.Path.stat
    def denied(target, *args, **kwargs):
        if target == path:
            raise PermissionError("synthetic unreadable metadata")
        return original(target, *args, **kwargs)
    monkeypatch.setattr(ownership.Path, "stat", denied)
    with pytest.raises(ownership.SessionError, match="Completed launch"):
        ownership.release_completed(tmp_path, record["launchId"])


@pytest.mark.parametrize("supervised,unreadable,allowed", [
    (False, 0, False), (True, 0, True), (True, 1, False),
])
def test_reservation_distinguishes_supervised_reuse_from_unknown_legacy(
    tmp_path, processes, monkeypatch, supervised, unreadable, allowed,
):
    profile = tmp_path / "profile"
    with ownership.ownership_lock(tmp_path):
        if supervised:
            owner = ownership.reserve_locked(tmp_path, "1", profile)
            ownership.mark_running_locked(tmp_path, owner["launchId"], 4242)
        monkeypatch.setattr(ownership, "scan_sessions", lambda _: ([object()], unreadable))
        if allowed:
            peer = ownership.reserve_locked(tmp_path, "1", profile)
            assert peer["state"] == "reserved"
        else:
            with pytest.raises(ownership.SessionError, match="legacy ownership"):
                ownership.reserve_locked(tmp_path, "1", profile)


@pytest.mark.parametrize("check", [ownership.profile_busy_locked, ownership.profile_running_locked])
@pytest.mark.parametrize("stored,current", [
    ("zero", "valid"), ("valid", "zero"), ("zero", "zero"),
])
def test_zero_boot_uuid_never_proves_running_completion(
    tmp_path, processes, monkeypatch, check, stored, current,
):
    boots = {"zero": "00000000-0000-0000-0000-000000000000",
             "valid": "11111111-1111-1111-1111-111111111111"}
    monkeypatch.setattr(ownership, "_boot_identity", lambda: ("a" * 32, boots[stored]))
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        monkeypatch.setattr(ownership, "_boot_identity", lambda: ("a" * 32, boots[current]))
        assert check(tmp_path, "1")


def test_completed_release_reports_waiting_only_on_first_contention(tmp_path, processes, monkeypatch, capsys):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
    lock = ownership.ownership_lock(tmp_path)
    acquire = lock.acquire
    attempts = iter([False, False, True])
    monkeypatch.setattr(lock, "acquire", lambda: acquire() if next(attempts) else False)

    ownership.release_completed(tmp_path, record["launchId"])

    diagnostic = capsys.readouterr()
    assert not diagnostic.out
    assert len(diagnostic.err.splitlines()) == 1
    assert "waiting" in diagnostic.err.lower()
    assert "lock" in diagnostic.err.lower()
    assert not ownership._record_path(tmp_path, record["launchId"]).exists()


def test_completed_release_diagnoses_permanent_lock_error(tmp_path, monkeypatch, capsys):
    import errno

    def fail():
        raise OSError(errno.EIO, "synthetic lock I/O error")

    monkeypatch.setattr(ownership.ownership_lock(tmp_path), "acquire", fail)
    with pytest.raises(ownership.SessionError, match="state lock"):
        ownership.release_completed(tmp_path, "a" * 32)

    diagnostic = capsys.readouterr()
    assert not diagnostic.out
    assert "lock" in diagnostic.err.lower()
    assert "error" in diagnostic.err.lower()


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="POSIX flock")
def test_completed_release_retains_running_record_on_flock_io_error(tmp_path, processes, monkeypatch, capsys):
    import errno
    from claude_swap import locking

    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
    lock = ownership.ownership_lock(tmp_path)
    attempts = []

    def fail(fd, operation):
        attempts.append(fd)
        raise OSError(errno.EIO, "synthetic flock I/O error")

    monkeypatch.setattr(locking.fcntl, "flock", fail)
    with pytest.raises(ownership.SessionError, match="state lock") as caught:
        ownership.release_completed(tmp_path, record["launchId"])
    assert caught.value.__cause__.errno == errno.EIO
    assert len(attempts) == 1
    assert lock._lock_file is None
    assert lock.depth == 0
    assert ownership._read(ownership._record_path(tmp_path, record["launchId"]))["state"] == "running"
    assert "lock" in capsys.readouterr().err.lower()


@pytest.fixture
def windows_identity(monkeypatch):
    reads = []
    values = {}
    def source(pid):
        reads.append(pid)
        if type(pid) is not int or not 1 <= pid <= 0xffffffff:
            return ownership._ProcessIdentity("unknown", None, "win32")
        return values.get(pid, ownership._ProcessIdentity(
            "present", ownership._WindowsStart(200), "win32",
        ))
    monkeypatch.setattr(ownership, "_process_identity", source)
    return values, reads


@pytest.mark.parametrize("stored,current,status,pid,busy", [
    ("win32:0200", 200, "present", 4242, True),
    ("win32:200", 201, "present", 4242, False),
    ("win32:1", 1, "present", 4242, True),
    ("win32:1", 2, "present", 4242, False),
    ("win32:18446744073709551615", 18446744073709551615, "present", 4242, True),
    ("win32:18446744073709551615", 200, "present", 4242, False),
    ("win32:18446744073709551616", 200, "present", 4242, True),
    ("win32:0", 200, "present", 4242, True),
    ("", 200, "present", 4242, True),
    ("123", 200, "present", 4242, True),
    ("win32:unknown", 200, "present", 4242, True),
    ("win32:+200", 200, "present", 4242, True),
    ("win32:２００", 200, "present", 4242, True),
    ("win32:" + "9" * 5000, 200, "present", 4242, True),
    ("win32:200", None, "unknown", 4242, True),
    ("win32:200", None, "absent", 4242, False),
    ("foreign", None, "absent", 4242, True),
])
def test_windows_reservation_cleanup_boundary(
    tmp_path, windows_identity, stored, current, status, pid, busy,
):
    values, reads = windows_identity
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        path = ownership._record_path(tmp_path, record["launchId"])
        record.update(ownerTicks=stored, ownerPid=pid)
        ownership._write(path, record)
        values[pid] = ownership._ProcessIdentity(
            status, ownership._WindowsStart(current) if current is not None else None, "win32",
        )
        assert ownership.profile_busy_locked(tmp_path, "1") is busy
        # A snapshot proves whether the reservation protects the profile; it never unlinks it.
        assert path.exists()


@pytest.mark.parametrize("failure", ["changed-owner", "unknown-owner", "foreign-owner", "unknown-child", None])
def test_windows_publication_checks_each_identity_once(tmp_path, windows_identity, failure):
    values, reads = windows_identity
    owner = ownership.os.getpid()
    child = 4242 if owner != 4242 else 4243
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        path = ownership._record_path(tmp_path, record["launchId"])
        record["ownerTicks"] = "win32:0200"
        if failure == "foreign-owner":
            record["ownerTicks"] = "old-posix"
        ownership._write(path, record)
        if failure == "changed-owner":
            values[owner] = ownership._ProcessIdentity("present", ownership._WindowsStart(201), "win32")
        elif failure == "unknown-owner":
            values[owner] = ownership._ProcessIdentity("unknown", None, "win32")
        if failure == "unknown-child":
            values[child] = ownership._ProcessIdentity("unknown", None, "win32")
        else:
            values[child] = ownership._ProcessIdentity("present", ownership._WindowsStart(300), "win32")
        reads.clear()
        if failure:
            with pytest.raises(ownership.SessionError):
                ownership.mark_running_locked(tmp_path, record["launchId"], child)
            assert ownership._read(path)["state"] == "reserved"
        else:
            ownership.mark_running_locked(tmp_path, record["launchId"], child)
            published = ownership._read(path)
            assert published["state"] == "running"
            assert published["procStart"] == "win32:300"
            assert reads == [owner, child]


@pytest.mark.parametrize("operation", ["verify", "release", "acknowledge"])
@pytest.mark.parametrize("stored,status", [("win32:200", "unknown"), ("foreign", "present")])
def test_windows_uncertain_owner_cannot_mutate(tmp_path, windows_identity, operation, stored, status):
    values, _ = windows_identity
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile", warming=True)
        path = ownership._record_path(tmp_path, record["launchId"])
        record["ownerTicks"] = stored
        ownership._write(path, record)
        values[ownership.os.getpid()] = ownership._ProcessIdentity(
            status, ownership._WindowsStart(200) if status == "present" else None, "win32",
        )
        with pytest.raises(ownership.SessionError):
            if operation == "verify":
                ownership.verify_reservation_locked(tmp_path, record["launchId"])
            elif operation == "release":
                ownership.release_locked(tmp_path, record["launchId"])
            else:
                ownership.acknowledge_generation_locked(tmp_path, record["launchId"], record["profileGen"])
        assert ownership._read(path)["state"] == "reserved"


def test_windows_record_on_posix_retains_protection(tmp_path, processes):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        record["ownerTicks"] = "win32:200"
        ownership._write(ownership._record_path(tmp_path, record["launchId"]), record)
        assert ownership.profile_busy_locked(tmp_path, "1")


@pytest.mark.parametrize("state", ["present", "absent"])
def test_foreign_windows_record_never_authorizes_posix_cleanup(tmp_path, processes, monkeypatch, state):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        record["ownerTicks"] = "win32:200"
        ownership._write(ownership._record_path(tmp_path, record["launchId"]), record)
        monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
            state, ownership._PosixStart("123") if state == "present" else None, "linux",
        ))
        assert ownership.profile_busy_locked(tmp_path, "1")
        with pytest.raises(ownership.SessionError):
            ownership.release_locked(tmp_path, record["launchId"])


@pytest.mark.parametrize("state", ["unknown", "denied"])
def test_windows_different_ticks_require_present_state(tmp_path, windows_identity, state):
    values, _ = windows_identity
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        values[record["ownerPid"]] = ownership._ProcessIdentity(
            state, ownership._WindowsStart(201), "win32",
        )
        assert ownership.profile_busy_locked(tmp_path, "1")


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="POSIX process identity")
@pytest.mark.parametrize("current,busy", [("123", True), ("456", False)])
def test_posix_permission_denied_still_compares_start_ticks(tmp_path, monkeypatch, current, busy):
    def denied(pid, signal):
        raise PermissionError("synthetic EPERM")

    monkeypatch.setattr(ownership, "scan_sessions", lambda _: ([], 0))
    monkeypatch.setattr(ownership, "process_start_ticks", lambda pid: "123")
    with ownership.ownership_lock(tmp_path):
        ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership.os, "kill", denied)
        monkeypatch.setattr(ownership, "process_start_ticks", lambda pid: current)
        assert ownership.profile_busy_locked(tmp_path, "1") is busy


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="POSIX process identity")
@pytest.mark.parametrize("probe,state", [
    (None, "present"), (ProcessLookupError, "absent"), (PermissionError, "unknown"),
])
@pytest.mark.parametrize("ticks", ["123", None])
def test_posix_process_identity(monkeypatch, probe, state, ticks):
    calls = []

    def kill(pid, signal):
        calls.append((pid, signal))
        if probe:
            raise probe("synthetic process probe")

    monkeypatch.setattr(ownership.os, "kill", kill)
    monkeypatch.setattr(ownership, "process_start_ticks", lambda pid: ticks)
    identity = ownership._process_identity(4242)
    assert identity == ownership._ProcessIdentity(
        state, ownership._PosixStart(ticks) if ticks is not None else None,
        ownership.sys.platform,
    )
    assert calls == [(4242, 0)]


def test_windows_length_limit_alone_retains_reservation(tmp_path, windows_identity):
    values, _ = windows_identity
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        path = ownership._record_path(tmp_path, record["launchId"])
        record["ownerTicks"] = "win32:" + "0" * 300 + "200"
        ownership._write(path, record)
        values[record["ownerPid"]] = ownership._ProcessIdentity(
            "present", ownership._WindowsStart(201), "win32",
        )
        assert ownership.profile_busy_locked(tmp_path, "1")
        assert ownership._read(path)["state"] == "reserved"


@pytest.mark.parametrize("pid", [0, -1])
def test_corrupt_record_retains_profile_without_identity_probe(tmp_path, windows_identity, pid):
    _, reads = windows_identity
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        path = ownership._record_path(tmp_path, record["launchId"])
        record["ownerPid"] = pid
        ownership._write(path, record)
        reads.clear()
        assert ownership.profile_busy_locked(tmp_path, "1")
        assert reads == []
        assert ownership._read(path)["state"] == "reserved"


@pytest.mark.parametrize("stored", ["win32:0", "win32:00000000000000000000"])
@pytest.mark.parametrize("operation", ["verify", "release", "acknowledge", "publish"])
def test_zero_windows_start_never_authorizes_owner_mutation(
    tmp_path, windows_identity, stored, operation,
):
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", tmp_path / "profile", warming=True)
        path = ownership._record_path(tmp_path, record["launchId"])
        record["ownerTicks"] = stored
        ownership._write(path, record)
        with pytest.raises(ownership.SessionError):
            if operation == "verify":
                ownership.verify_reservation_locked(tmp_path, record["launchId"])
            elif operation == "release":
                ownership.release_locked(tmp_path, record["launchId"])
            elif operation == "acknowledge":
                ownership.acknowledge_generation_locked(
                    tmp_path, record["launchId"], record["profileGen"],
                )
            else:
                ownership.mark_running_locked(tmp_path, record["launchId"], 4242)
        assert ownership._read(path) == record
        assert ownership.profile_busy_locked(tmp_path, "1")

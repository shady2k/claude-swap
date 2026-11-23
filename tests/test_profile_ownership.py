"""External profile ownership, using only synthetic processes and profiles."""

import json

import pytest

from claude_swap import profile_ownership as ownership


@pytest.fixture
def processes(monkeypatch):
    monkeypatch.setattr(ownership, "process_start_ticks", lambda pid: "123")
    monkeypatch.setattr(ownership, "_pid_alive", lambda pid: True)


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
        monkeypatch.setattr(ownership, "process_start_ticks", lambda pid: "999")
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_unknown_process_identity_is_busy(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership, "process_start_ticks", lambda pid: None)
        assert ownership.profile_busy_locked(tmp_path, "1")
        monkeypatch.setattr(ownership, "_pid_alive", lambda pid: None)
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_dead_launcher_does_not_block(tmp_path, processes, monkeypatch):
    with ownership.ownership_lock(tmp_path):
        ownership.reserve_locked(tmp_path, "1", tmp_path / "profile")
        monkeypatch.setattr(ownership, "_pid_alive", lambda pid: False)
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


def test_reserved_slot_rejects_second_admission(tmp_path, processes):
    profile = tmp_path / "profile"
    with ownership.ownership_lock(tmp_path):
        ownership.reserve_locked(tmp_path, "1", profile, warming=True)
        with pytest.raises(ownership.SessionError, match="busy"):
            ownership.reserve_locked(tmp_path, "1", profile)


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
        monkeypatch.setattr(ownership, "_pid_alive", lambda pid: pid == 4242)
        assert ownership.profile_busy_locked(tmp_path, "1")


def test_malformed_generation_blocks_admission_with_session_error(tmp_path, processes):
    profile = tmp_path / "profile"
    with ownership.ownership_lock(tmp_path):
        record = ownership.reserve_locked(tmp_path, "1", profile)
        ownership.release_locked(tmp_path, record["launchId"])
        ownership._generation_path(tmp_path, profile).write_text("{", encoding="utf-8")
        with pytest.raises(ownership.SessionError):
            ownership.reserve_locked(tmp_path, "1", profile)


def test_pid_probe_permission_error_is_unknown(monkeypatch):
    monkeypatch.setattr(ownership.sys, "platform", "linux")
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
        monkeypatch.setattr(ownership, "_pid_alive", lambda pid: False)
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
        monkeypatch.setattr(ownership, "process_start_ticks", lambda pid: None)
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

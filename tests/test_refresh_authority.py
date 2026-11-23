"""Identity-scoped refresh authority and generation checks (F29)."""
import json
from unittest.mock import patch

import pytest

from claude_swap import oauth
from claude_swap.switcher import ClaudeAccountSwitcher


def credential(name):
    return json.dumps({"claudeAiOauth": {"accessToken": "synthetic-" + name,
        "refreshToken": "synthetic-refresh-" + name, "expiresAt": 1000}})


def seeded(sample_sequence_data):
    s = ClaudeAccountSwitcher()
    s._setup_directories()
    s._write_json(s.sequence_file, sample_sequence_data)
    email = sample_sequence_data["accounts"]["1"]["email"]
    s._write_account_credentials("1", email, credential("old"))
    return s, email


def test_identity_right_survives_slot_number_and_serializes(temp_home, sample_sequence_data):
    from claude_swap import refresh_authority as authority
    s, email = seeded(sample_sequence_data)
    org = s.account_identity("1")["organizationUuid"]
    right = authority.consume_lock(s.backup_dir, email, org)
    assert right.acquire(timeout=0)
    try:
        with patch("claude_swap.oauth.try_refresh_oauth_credentials") as post:
            snapshot = s.credential_snapshot("1", email)
            result = s.consume_backup_grant("1", email, snapshot, timeout=0)
        assert result.error == "consume-busy"
        post.assert_not_called()
    finally:
        right.release()


def test_replaced_generation_never_consumes(temp_home, sample_sequence_data):
    from claude_swap import refresh_authority as authority
    from claude_swap.locking import FileLock
    s, email = seeded(sample_sequence_data)
    snapshot = s.credential_snapshot("1", email)
    with FileLock(s.lock_file):
        authority.advance_login_generation(s.backup_dir, email, snapshot.identity["organizationUuid"])
        s._store._write_account_credentials("1", email, credential("replacement"))
    with patch("claude_swap.oauth.try_refresh_oauth_credentials") as post:
        result = s.consume_backup_grant("1", email, snapshot)
    assert result.error == "superseded"
    post.assert_not_called()
    assert s._read_account_credentials("1", email) == credential("replacement")


def test_old_slot_identity_never_consumes(temp_home, sample_sequence_data):
    s, email = seeded(sample_sequence_data)
    snapshot = s.credential_snapshot("1", email)
    data = s._get_sequence_data()
    data["accounts"]["1"]["organizationUuid"] = "synthetic-other-org"
    s._write_json(s.sequence_file, data)
    with patch("claude_swap.oauth.try_refresh_oauth_credentials") as post:
        result = s.consume_backup_grant("1", email, snapshot)
    assert result.error == "ownership-lost"
    post.assert_not_called()


def test_running_reservation_blocks_grant(temp_home, sample_sequence_data):
    from claude_swap import profile_ownership
    s, email = seeded(sample_sequence_data)
    snapshot = s.credential_snapshot("1", email)
    with profile_ownership.ownership_lock(s.backup_dir):
        record = profile_ownership.reserve_locked(s.backup_dir, "1", s._session_dir("1", email))
    try:
        with patch("claude_swap.oauth.try_refresh_oauth_credentials") as post:
            result = s.consume_backup_grant("1", email, snapshot)
        assert result.error == "profile-busy"
        post.assert_not_called()
    finally:
        with profile_ownership.ownership_lock(s.backup_dir):
            profile_ownership.release_locked(s.backup_dir, record["launchId"])


def test_mutation_refuses_while_identity_refresh_held(temp_home, sample_sequence_data):
    from claude_swap import refresh_authority as authority, profile_ownership
    from claude_swap.locking import FileLock
    from claude_swap.exceptions import SessionError
    s, email = seeded(sample_sequence_data)
    org = s.account_identity("1")["organizationUuid"]
    with authority.consume_lock(s.backup_dir, email, org):
        with profile_ownership.ownership_lock(s.backup_dir), FileLock(s.lock_file):
            with pytest.raises(SessionError, match="refresh|обновление"):
                s._ensure_profile_idle_locked("1", email)


def test_cas_generation_change_stashes_successor(temp_home, sample_sequence_data):
    from claude_swap import refresh_authority as authority
    s, email = seeded(sample_sequence_data)
    snapshot = s.credential_snapshot("1", email)
    def reply(value):
        authority.advance_login_generation(s.backup_dir, email, snapshot.identity["organizationUuid"])
        return oauth.RefreshOutcome(credential("successor"), None)
    with patch("claude_swap.oauth.try_refresh_oauth_credentials", side_effect=reply):
        s.consume_backup_grant("1", email, snapshot)
    assert s._read_account_credentials("1", email) == credential("old")
    assert s.list_unclaimed_credentials()


def test_snapshot_reads_bytes_with_generation_under_same_lock(temp_home, sample_sequence_data):
    from claude_swap import refresh_authority as authority
    from claude_swap.locking import FileLock
    s, email = seeded(sample_sequence_data)
    def generation(*args):
        probe = FileLock(s.lock_file, timeout=0)
        assert not probe.acquire(timeout=0), "generation escaped account lock"
        return 7
    with patch("claude_swap.refresh_authority.login_generation", side_effect=generation):
        snapshot = s.credential_snapshot("1", email)
    assert snapshot.login_gen == 7
    assert snapshot.identity == s.account_identity("1")


def test_reservation_refuses_while_identity_right_held(temp_home, sample_sequence_data):
    from claude_swap import refresh_authority as authority, profile_ownership
    from claude_swap.exceptions import SessionError
    s, email = seeded(sample_sequence_data)
    org = s.account_identity("1")["organizationUuid"]
    with authority.consume_lock(s.backup_dir, email, org):
        with profile_ownership.ownership_lock(s.backup_dir):
            with pytest.raises(SessionError, match="refresh|обновление"):
                profile_ownership.reserve_locked(s.backup_dir, "1", s._session_dir("1", email))


def test_setup_token_gate_never_calls_refresh(temp_home, sample_sequence_data):
    s, email = seeded(sample_sequence_data)
    setup = json.dumps({"claudeAiOauth": {"accessToken": "synthetic-setup"}})
    s._store._write_account_credentials("1", email, setup)
    with patch("claude_swap.oauth.try_refresh_oauth_credentials") as post:
        s.consume_backup_grant("1", email, s.credential_snapshot("1", email))
    post.assert_not_called()


def test_unbound_snapshot_cannot_authorize_post(temp_home, sample_sequence_data):
    s, email = seeded(sample_sequence_data)
    with patch("claude_swap.oauth.try_refresh_oauth_credentials") as post:
        result = s.consume_backup_grant("1", email, credential("old"))
    assert result.error == "superseded"
    post.assert_not_called()


@pytest.mark.parametrize("stored_uuid,current_uuid,adopts", [
    ("", "discovered", True),
    ("known", "", True),
    ("known", "different", False),
])
def test_stash_identity_uuid_is_optional_but_conflicts_refuse(
    temp_home, sample_sequence_data, stored_uuid, current_uuid, adopts,
):
    from claude_swap import refresh_authority as authority
    from claude_swap.locking import FileLock
    s, email = seeded(sample_sequence_data)
    identity = dict(s.account_identity("1"), uuid=stored_uuid)
    s._store._write_unclaimed_credential(credential("successor"), {
        "reason": "active-refresh-persist-failed", "configSlot": "1",
        "identity": identity,
        "loginGen": authority.login_generation(s.backup_dir, email, identity["organizationUuid"]),
        "consumedFp": oauth.credential_fingerprint(credential("old")),
    })
    data = s._get_sequence_data()
    data["accounts"]["1"]["uuid"] = current_uuid
    s._write_json(s.sequence_file, data)
    with FileLock(s.lock_file):
        result = s._adopt_stashed_successor("1", email, credential("old"))
    assert result == (credential("successor") if adopts else None)
    assert s._read_account_credentials("1", email) == credential("successor" if adopts else "old")


def test_session_checker_rejects_consumed_fp_across_guards(
    temp_home, sample_sequence_data,
):
    s, email = seeded(sample_sequence_data)
    old = credential("old")
    s._store._write_unclaimed_credential(credential("successor"), {
        "reason": "consume-gate-superseded", "configSlot": "99",
        "identity": {"email": "other@example.invalid"}, "loginGen": 999,
        "consumedFp": oauth.credential_fingerprint(old),
    })
    assert s._session_credential_stash_status(old) == "consumed"


def test_session_checker_skips_setup_token_and_flags_unknown_rows(
    temp_home, sample_sequence_data,
):
    s, email = seeded(sample_sequence_data)
    s._store._write_stash_manifest({"bad": None})
    assert s._session_credential_stash_status(credential("old")) == "unverifiable"
    setup = json.dumps({"claudeAiOauth": {"accessToken": "synthetic-setup"}})
    with patch.object(s._store, "_stash_snapshot") as scan:
        assert s._session_credential_stash_status(setup) is None
    scan.assert_not_called()


def test_stash_publication_and_removal_hold_manifest_lock(
    temp_home, sample_sequence_data,
):
    from claude_swap.locking import FileLock
    s, email = seeded(sample_sequence_data)
    store = s._store
    original_write = store._atomic_b64_write
    original_unlink = type(store._stash_entry_path("unused")).unlink

    def assert_locked():
        probe = FileLock(store._stash_manifest_path().with_suffix(".lock"), timeout=0)
        assert not probe.acquire(timeout=0)

    def write(path, value):
        assert_locked()
        original_write(path, value)

    def unlink(path, *args, **kwargs):
        if path.name.startswith(".unclaimed-"):
            assert_locked()
        return original_unlink(path, *args, **kwargs)

    with patch.object(store, "_atomic_b64_write", side_effect=write):
        entry = store._write_unclaimed_credential(credential("successor"), {})
    with patch("pathlib.Path.unlink", new=unlink):
        store._remove_unclaimed_credential(entry)
    assert store._stash_snapshot() == ({}, set(), "ok")


def test_stash_lock_failure_preserves_successor_without_publication(
    temp_home, sample_sequence_data,
):
    from claude_swap.exceptions import LockError
    s, email = seeded(sample_sequence_data)
    with patch("claude_swap.locking.FileLock.acquire", return_value=False):
        with pytest.raises(LockError):
            s._store._write_unclaimed_credential(credential("successor"), {})
    entries = s._store._list_unclaimed_credentials()
    assert len(entries) == 1
    assert s._store._read_unclaimed_credential(next(iter(entries)))[0] == credential("successor")
    assert s._store._stash_snapshot() == ({}, set(entries), "ok")


def test_stash_snapshot_distinguishes_contention_and_lock_storage_failure(
    temp_home, sample_sequence_data,
):
    s, email = seeded(sample_sequence_data)
    with patch("claude_swap.locking.FileLock.acquire", return_value=False):
        assert s._store._stash_snapshot() == ({}, set(), "busy")
    with patch("claude_swap.locking.FileLock.acquire", side_effect=OSError("synthetic I/O")):
        assert s._store._stash_snapshot() == ({}, set(), "unreadable")


@pytest.mark.parametrize("manifest,verdict", [("{", "corrupt"), (None, "ok")])
def test_stash_snapshot_keeps_orphan_ids_separate_from_manifest_verdict(
    temp_home, sample_sequence_data, manifest, verdict,
):
    s, email = seeded(sample_sequence_data)
    store = s._store
    store._atomic_b64_write(store._stash_entry_path("orphan"), credential("successor"))
    if manifest is not None:
        store._stash_manifest_path().write_text(manifest)
    assert store._stash_snapshot() == ({}, {"orphan"}, verdict)


def test_stash_snapshot_directory_error_is_unreadable_under_manifest_lock(
    temp_home, sample_sequence_data,
):
    from claude_swap.locking import FileLock
    s, email = seeded(sample_sequence_data)
    store = s._store

    def scan(path):
        probe = FileLock(store._stash_manifest_path().with_suffix(".lock"), timeout=0)
        assert not probe.acquire(timeout=0)
        raise PermissionError("synthetic directory read failure")

    with patch("pathlib.Path.iterdir", new=scan):
        assert store._stash_snapshot() == ({}, set(), "unreadable")


def test_stash_snapshot_never_scans_during_publication(
    temp_home, sample_sequence_data,
):
    from threading import Event, Thread, current_thread
    from claude_swap.locking import FileLock
    s, email = seeded(sample_sequence_data)
    entered = Event()
    resume = Event()
    reader_attempting = Event()
    scanned = Event()
    original_acquire = FileLock.acquire

    def acquire(lock, *args, **kwargs):
        if current_thread().name == "stash-reader":
            reader_attempting.set()
        return original_acquire(lock, *args, **kwargs)
    original_write = s._store._atomic_b64_write
    original_scan = s._store._read_stash_manifest_ex
    errors = []
    snapshots = []

    def write(path, value):
        original_write(path, value)
        entered.set()
        assert resume.wait(2)

    def scan():
        scanned.set()
        return original_scan()

    def publish():
        try:
            s._store._write_unclaimed_credential(credential("successor"), {})
        except Exception as exc:
            errors.append(exc)

    with patch.object(s._store, "_atomic_b64_write", side_effect=write):
        writer = Thread(target=publish)
        writer.start()
        assert entered.wait(2)
        with patch.object(s._store, "_read_stash_manifest_ex", side_effect=scan), patch.object(
            FileLock, "acquire", new=acquire,
        ):
            reader = Thread(
                target=lambda: snapshots.append(s._store._stash_snapshot()),
                name="stash-reader",
            )
            reader.start()
            assert reader_attempting.wait(2)
            # The writer owns the lock across both bytes and manifest. A
            # snapshot may finish only after publication is released.
            assert not scanned.is_set()
            resume.set()
            writer.join(3)
            reader.join(3)
    assert not errors
    assert len(snapshots) == 1
    assert snapshots[0][1:] == (set(), "ok")
    assert len(snapshots[0][0]) == 1


@pytest.mark.parametrize("verdict,error", [("busy", "transient"), ("unreadable", "stash-unreadable")])
def test_backup_gate_defers_on_manifest_lock_failure_without_post(
    temp_home, sample_sequence_data, verdict, error,
):
    s, email = seeded(sample_sequence_data)
    snapshot = s.credential_snapshot("1", email)
    with patch.object(s._store, "_stash_snapshot", return_value=({}, set(), verdict)), patch(
        "claude_swap.oauth.try_refresh_oauth_credentials"
    ) as post:
        result = s.consume_backup_grant("1", email, snapshot)
    assert result.error == error
    post.assert_not_called()
    assert s._read_account_credentials("1", email) == credential("old")


def test_stash_refusal_logs_only_blocking_orphan_id(
    temp_home, sample_sequence_data, caplog,
):
    from claude_swap.exceptions import CredentialReadError
    from claude_swap.locking import FileLock

    s, email = seeded(sample_sequence_data)
    row_id = s._store._write_unclaimed_credential(credential("successor"), {
        "reason": "consume-gate-store-unreadable", "configSlot": "1",
        "consumedFp": oauth.credential_fingerprint(credential("old")),
    })
    s._store._atomic_b64_write(
        s._store._stash_entry_path("blocking-orphan"), credential("orphan"),
    )
    with FileLock(s.lock_file), pytest.raises(CredentialReadError):
        s._checked_refresh_stash("1")
    assert "Account 1" in caplog.text
    assert "blocking-orphan" in caplog.text
    assert row_id not in caplog.text
    assert "synthetic-refresh" not in caplog.text

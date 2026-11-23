"""Active recovery revalidates identity and grant authority before consuming."""
import json

import pytest

from claude_swap import oauth
from claude_swap.switcher import ClaudeAccountSwitcher

EMAIL = "authority@example.com"


def credential(name):
    return json.dumps({"claudeAiOauth": {
        "accessToken": name + "-access", "refreshToken": name + "-refresh",
        "expiresAt": 1000,
    }})


class Snapshot(str):
    login_gen = 0
    identity = {"email": EMAIL, "organizationUuid": "", "uuid": ""}


@pytest.fixture
def active(temp_home, monkeypatch):
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._write_json(switcher.sequence_file, {
        "activeAccountNumber": "1", "accounts": {"1": {"email": EMAIL}},
    })
    monkeypatch.setattr(switcher, "_live_identity_matches", lambda *a: True)
    def usage(*args, **kwargs):
        assert kwargs["refresh_via"] is None
        return oauth.UsageOutcome({"ok": True})
    monkeypatch.setattr(oauth, "try_fetch_usage_for_account", usage)
    calls = []
    def refresh(value, timeout_s):
        calls.append((value, timeout_s))
        return oauth.RefreshOutcome(credential("successor"), None)
    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", refresh)
    return switcher, calls


@pytest.mark.parametrize("unreadable", [True, False])
def test_active_pending_successor_without_readable_bytes_defers(active, monkeypatch, unreadable):
    switcher, calls = active
    original = Snapshot(credential("own"))
    switcher._write_account_credentials("1", EMAIL, original)
    switcher._write_credentials(original)
    switcher._store._write_unclaimed_credential(credential("successor"), {
        "reason": "active-refresh-persist-failed", "configSlot": "1",
        "identity": original.identity, "loginGen": original.login_gen,
        "consumedFp": oauth.credential_fingerprint(original),
    })
    monkeypatch.setattr(switcher._store, "_read_unclaimed_credential", lambda *a: ("", unreadable))
    result = switcher._fetch_active_usage("1", EMAIL, original)
    assert calls == []
    assert result.error == "stash-unreadable"
    assert switcher._read_credentials() == original


def test_active_legacy_stash_without_authority_defers(active):
    switcher, calls = active
    original = Snapshot(credential("own"))
    switcher._write_account_credentials("1", EMAIL, original)
    switcher._write_credentials(original)
    switcher._store._write_unclaimed_credential(credential("unproven-successor"), {
        "reason": "active-refresh-persist-failed", "configSlot": "1",
        "consumedFp": oauth.credential_fingerprint(original),
    })
    result = switcher._fetch_active_usage("1", EMAIL, original)
    assert calls == []
    assert result.error == "stash-unreadable"
    assert switcher._read_credentials() == original
    assert switcher._read_account_credentials("1", EMAIL) == original


def test_active_retry_after_live_persist_failure(active, monkeypatch):
    switcher, calls = active
    original = Snapshot(credential("own"))
    switcher._write_account_credentials("1", EMAIL, original)
    switcher._write_credentials(original)
    with monkeypatch.context() as failure:
        def fail(*args):
            raise OSError("synthetic live persist failure")
        failure.setattr(switcher, "_write_credentials", fail)
        result = switcher._fetch_active_usage("1", EMAIL, original)
    assert result.error == "transient"
    result = switcher._fetch_active_usage("1", EMAIL, original)
    assert result.usage == {"ok": True}
    assert len(calls) == 1
    assert switcher._read_credentials() == credential("successor")


@pytest.mark.parametrize("source", ["live", "backup", "snapshot", "stale-live"])
def test_active_refresh_uses_locked_source(active, source):
    switcher, calls = active
    original = Snapshot(credential("collected"))
    backup = credential("rotated") if source != "snapshot" else ""
    if source == "stale-live":
        payload = json.loads(backup)
        payload["claudeAiOauth"]["expiresAt"] = 2000
        backup = json.dumps(payload)
    if backup:
        switcher._write_account_credentials("1", EMAIL, backup)
    switcher._write_credentials(
        backup if source == "live" else original if source == "stale-live" else ""
    )
    result = switcher._fetch_active_usage("1", EMAIL, original)
    assert calls == [(backup or original, 6.0)]
    assert result.usage == {"ok": True}
    assert switcher._read_credentials() == credential("successor")
    assert switcher._read_account_credentials("1", EMAIL) == credential("successor")


def test_unreadable_backup_never_consumes_snapshot(active, monkeypatch):
    switcher, calls = active
    switcher._write_credentials("")
    monkeypatch.setattr(switcher, "_read_account_credentials_ex", lambda *a: ("", True))
    result = switcher._fetch_active_usage("1", EMAIL, Snapshot(credential("old")))
    assert result.error == "unreadable"
    assert calls == []


def test_changed_generation_never_consumes(active):
    from claude_swap import refresh_authority
    switcher, calls = active
    switcher._write_account_credentials("1", EMAIL, credential("replacement"))
    switcher._write_credentials(credential("replacement"))
    refresh_authority.advance_login_generation(switcher.backup_dir, EMAIL, "")
    result = switcher._fetch_active_usage("1", EMAIL, Snapshot(credential("old")))
    assert result.error == "superseded"
    assert calls == []


def test_foreign_live_grant_is_not_consumed(active):
    switcher, calls = active
    switcher._write_account_credentials("1", EMAIL, credential("own"))
    switcher._write_credentials(credential("foreign"))
    result = switcher._fetch_active_usage("1", EMAIL, Snapshot(credential("own")))
    assert calls == []
    assert result.error == "ownership-lost"


def test_failed_persist_stashes_successor(active, monkeypatch):
    switcher, calls = active
    original = Snapshot(credential("own"))
    switcher._write_account_credentials("1", EMAIL, original)
    switcher._write_credentials(original)
    with monkeypatch.context() as persist_failure:
        def fail(*args):
            raise OSError("synthetic failure")
        persist_failure.setattr(switcher._store, "_write_account_credentials", fail)
        result = switcher._fetch_active_usage("1", EMAIL, original)
    assert len(calls) == 1
    assert result.error == "transient"
    assert switcher.list_unclaimed_credentials()
    data = switcher._get_sequence_data()
    data["accounts"]["1"]["uuid"] = "discovered-uuid"
    switcher._write_json(switcher.sequence_file, data)
    result = switcher._fetch_active_usage("1", EMAIL, original)
    assert result.usage == {"ok": True}
    assert len(calls) == 1
    assert switcher._read_credentials() == credential("successor")
    assert switcher._read_account_credentials("1", EMAIL) == credential("successor")


def test_same_identity_relogin_between_snapshot_and_locks(active, monkeypatch):
    import threading
    from claude_swap import refresh_authority
    from claude_swap.locking import FileLock
    switcher, calls = active
    old = Snapshot(credential("old"))
    switcher._write_account_credentials("1", EMAIL, old)
    switcher._write_credentials(old)
    entered = threading.Event()
    release = threading.Event()
    factory = refresh_authority.consume_lock

    class PausedAuthority:
        def __init__(self, *args, **kwargs):
            self.lock = factory(*args, **kwargs)
        def acquire(self):
            entered.set()
            assert release.wait(5)
            return self.lock.acquire()
        def release(self):
            self.lock.release()

    monkeypatch.setattr(refresh_authority, "consume_lock", PausedAuthority)
    results = []
    worker = threading.Thread(target=lambda: results.append(
        switcher._fetch_active_usage("1", EMAIL, old)
    ))
    worker.start()
    try:
        assert entered.wait(5)
        with FileLock(switcher.lock_file):
            switcher._store._write_account_credentials("1", EMAIL, credential("new-login"))
            refresh_authority.advance_login_generation(switcher.backup_dir, EMAIL, "")
        release.set()
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive()
    assert results[0].error == "superseded"
    assert calls == []
    assert switcher._read_account_credentials("1", EMAIL) == credential("new-login")


def test_setup_token_does_not_reach_refresh_post(active):
    switcher, calls = active
    setup = Snapshot(json.dumps({"claudeAiOauth": {"accessToken": "synthetic-setup", "expiresAt": 1000}}))
    switcher._write_credentials(setup)
    switcher._write_account_credentials("1", EMAIL, setup)
    result = switcher._fetch_active_usage("1", EMAIL, setup)
    assert calls == []
    assert result.error == "no_refresh_token"


def test_changed_uuid_is_not_same_identity(active):
    switcher, calls = active
    old = Snapshot(credential("old"))
    old.identity = {"email": EMAIL, "organizationUuid": "", "uuid": "old-uuid"}
    data = switcher._get_sequence_data()
    data["accounts"]["1"]["uuid"] = "new-uuid"
    switcher._write_json(switcher.sequence_file, data)
    switcher._write_credentials(old)
    switcher._write_account_credentials("1", EMAIL, old)
    result = switcher._fetch_active_usage("1", EMAIL, old)
    assert calls == []
    assert result.error == "ownership-lost"


def test_unproven_backup_does_not_replace_live_snapshot(active):
    switcher, calls = active
    live = Snapshot(credential("live"))
    switcher._write_credentials(live)
    switcher._write_account_credentials("1", EMAIL, credential("unknown-age"))
    result = switcher._fetch_active_usage("1", EMAIL, live)
    assert calls == []
    assert result.error == "ownership-lost"


def test_claude_rotation_before_locked_read_does_not_double_post(active):
    switcher, calls = active
    old = Snapshot(credential("old"))
    switcher._write_credentials(credential("claude-successor"))
    switcher._write_account_credentials("1", EMAIL, old)
    result = switcher._fetch_active_usage("1", EMAIL, old)
    assert calls == []
    assert result.error == "ownership-lost"


def test_active_holds_claude_and_identity_locks_during_post(active, monkeypatch):
    import threading
    from claude_swap import refresh_authority
    from claude_swap.claude_locks import claude_credentials_lock
    from claude_swap.locking import FileLock
    switcher, calls = active
    old = Snapshot(credential("old"))
    switcher._write_credentials(old)
    switcher._write_account_credentials("1", EMAIL, old)
    entered = threading.Event()
    release = threading.Event()
    results = []
    def refresh(value, timeout_s):
        entered.set()
        assert release.wait(5)
        return oauth.RefreshOutcome(credential("successor"), None)
    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", refresh)
    worker = threading.Thread(target=lambda: results.append(
        switcher._fetch_active_usage("1", EMAIL, old)
    ))
    worker.start()
    try:
        assert entered.wait(5)
        # Exercise real cross-process lock protocols, not a mock lock flag.
        locks = [
            refresh_authority.consume_lock(switcher.backup_dir, EMAIL, "", timeout=0),
            FileLock(switcher.lock_file, timeout=0),
        ]
        for lock in locks:
            assert not lock.acquire(timeout=0)
        from claude_swap.exceptions import LockError
        with pytest.raises(LockError):
            with claude_credentials_lock(timeout=0):
                pytest.fail("Claude credential lock was not held during POST")
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive()
    assert results[0].usage == {"ok": True}


def test_unbound_snapshot_never_posts(active):
    switcher, calls = active
    raw = credential("raw")
    switcher._write_credentials(raw)
    switcher._write_account_credentials("1", EMAIL, raw)
    result = switcher._fetch_active_usage("1", EMAIL, raw)
    assert result.error == "superseded"
    assert calls == []


def test_empty_uuid_backfill_preserves_refresh_identity(active):
    switcher, calls = active
    old = Snapshot(credential("old"))
    switcher._write_credentials(old)
    switcher._write_account_credentials("1", EMAIL, old)
    data = switcher._get_sequence_data()
    data["accounts"]["1"]["uuid"] = "newly-bound"
    switcher._write_json(switcher.sequence_file, data)
    result = switcher._fetch_active_usage("1", EMAIL, old)
    assert result.usage == {"ok": True}
    assert len(calls) == 1


@pytest.mark.parametrize("state", ["running", "reserved"])
def test_existing_profile_owner_refuses_active_post(active, monkeypatch, state):
    switcher, calls = active
    old = Snapshot(credential("old"))
    switcher._write_credentials(old)
    switcher._write_account_credentials("1", EMAIL, old)
    from claude_swap import profile_ownership
    # The ownership layer classifies both live reservations and running
    # records as busy; active recovery must honor that verdict before POST.
    monkeypatch.setattr(profile_ownership, "profile_busy_locked", lambda *a, **k: True)
    result = switcher._fetch_active_usage("1", EMAIL, old)
    assert result.error == "ownership-lost"
    assert calls == []

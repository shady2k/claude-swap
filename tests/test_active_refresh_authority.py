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
    def refresh(value, timeout_s=10.0):
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


@pytest.mark.parametrize("source", ["live", "backup", "stale-live"])
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
    if source == "stale-live":
        assert result.error == "credential-unproven"
        assert not calls
        assert switcher._read_credentials() == original
        assert switcher._read_account_credentials("1", EMAIL) == backup
        return
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
    assert result.error == "credential-unproven"


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
    assert result.error == "credential-unproven"


def test_claude_rotation_before_locked_read_does_not_double_post(active):
    switcher, calls = active
    old = Snapshot(credential("old"))
    switcher._write_credentials(credential("claude-successor"))
    switcher._write_account_credentials("1", EMAIL, old)
    result = switcher._fetch_active_usage("1", EMAIL, old)
    assert calls == []
    assert result.error == "credential-unproven"


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
    assert result.error == "profile-busy"
    assert calls == []


@pytest.mark.parametrize("production", [False, True])
@pytest.mark.parametrize("shape", ["live-older", "equal", "only-live", "only-backup"])
@pytest.mark.parametrize("failed_store", ["backup", "live"])
def test_stale_live_retry_consumes_selected_grant_once(active, monkeypatch, failed_store, shape, production):
    switcher, calls = active
    live = Snapshot(credential("A"))
    payload = json.loads(credential("B"))
    payload["claudeAiOauth"]["expiresAt"] = 2000
    backup = json.dumps(payload)
    if shape in {"equal", "only-live"}:
        live = Snapshot(backup)
    stored_live = "" if shape == "only-backup" else live
    stored_backup = "" if shape == "only-live" else backup
    switcher._write_credentials(stored_live)
    if stored_backup:
        switcher._write_account_credentials("1", EMAIL, stored_backup)
    def fetch():
        if production:
            return switcher._fetch_account_usage((1, EMAIL, "", "", True,
                                                  str(switcher._read_credentials()), ""))
        return switcher._fetch_active_usage("1", EMAIL, live)
    if production and shape == "only-backup":
        from claude_swap.switcher import USAGE_NO_CREDENTIALS
        assert fetch().sentinel == USAGE_NO_CREDENTIALS
        assert not calls
        assert switcher._read_account_credentials("1", EMAIL) == stored_backup
        assert not switcher.list_unclaimed_credentials()
        return
    if shape == "live-older":
        for _ in range(2):
            assert fetch().error == "credential-unproven"
        assert not calls
        assert switcher._read_credentials() == stored_live
        assert switcher._read_account_credentials("1", EMAIL) == stored_backup
        assert not switcher.list_unclaimed_credentials()
        return
    with monkeypatch.context() as failure:
        def fail(*args):
            raise OSError("synthetic persist failure")
        if failed_store == "backup":
            failure.setattr(switcher._store, "_write_account_credentials", fail)
        else:
            failure.setattr(switcher, "_write_credentials", fail)
        assert fetch().error == "transient"
    assert switcher.list_unclaimed_credentials()
    manifest, verdict = switcher._store._read_stash_manifest_ex()
    assert verdict != "unreadable"
    row = next(iter(manifest.values()))
    assert row["observedLiveFp"] == (oauth.credential_fingerprint(stored_live) or None)
    assert row["observedBackupFp"] == (oauth.credential_fingerprint(stored_backup) or None)
    result = fetch()
    assert result.usage == {"ok": True}
    assert [json.loads(value)["claudeAiOauth"]["refreshToken"] for value, _ in calls] == ["B-refresh"]
    assert switcher._read_credentials() == credential("successor")
    assert switcher._read_account_credentials("1", EMAIL) == credential("successor")
    assert not switcher.list_unclaimed_credentials()


def aged(name, expiry=1000):
    value = json.loads(credential(name))
    value["claudeAiOauth"]["expiresAt"] = expiry
    return json.dumps(value)


def stash(switcher, consumed, successor=None, *, observed=True, **overrides):
    successor = successor or credential("successor")
    meta = {
        "reason": "active-refresh-persist-failed", "configSlot": "1",
        "identity": Snapshot.identity, "loginGen": 0,
        "consumedFp": oauth.credential_fingerprint(consumed),
        "fingerprint": oauth.credential_fingerprint(successor),
    }
    if observed:
        meta.update({
            "observedLiveFp": oauth.credential_fingerprint(switcher._read_credentials()) or None,
            "observedBackupFp": oauth.credential_fingerprint(
                switcher._read_account_credentials("1", EMAIL)) or None,
        })
    meta.update(overrides)
    return switcher._store._write_unclaimed_credential(successor, meta)


@pytest.mark.parametrize("production", [False, True])
@pytest.mark.parametrize("shape", ["equal", "live-older", "backup-older", "equal-expiry", "only-live", "only-backup"])
@pytest.mark.parametrize("pending", [False, True])
def test_active_acceptance_matrix(active, monkeypatch, shape, pending, production):
    switcher, calls = active
    c = aged("successor", 9999999999999)
    def refresh(value, timeout_s):
        calls.append((value, timeout_s))
        return oauth.RefreshOutcome(c, None)
    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", refresh)
    b = aged("B", 2000)
    pairs = {
        "equal": (b, b), "live-older": (aged("A"), b),
        "backup-older": (b, aged("A")),
        "equal-expiry": (aged("A", 2000), b),
        "only-live": (b, ""), "only-backup": ("", b),
    }
    live, backup = pairs[shape]
    snapshot = Snapshot(live or backup)
    switcher._write_credentials(live)
    if backup:
        switcher._write_account_credentials("1", EMAIL, backup)
    observed = shape not in {"backup-older", "equal-expiry"}
    allowed = observed and (pending or shape != "live-older")
    if pending:
        stash(switcher, b, c, observed=observed)
    for _ in range(2):
        if production:
            result = switcher._fetch_account_usage((1, EMAIL, "", "", True,
                                                  str(switcher._read_credentials()), ""))
            if shape == "only-backup":
                from claude_swap.switcher import USAGE_NO_CREDENTIALS
                assert result.sentinel == USAGE_NO_CREDENTIALS
                assert not calls
                assert switcher._read_account_credentials("1", EMAIL) == backup
                assert bool(switcher.list_unclaimed_credentials()) == pending
                return
        else:
            result = switcher._fetch_active_usage("1", EMAIL, snapshot)
        if allowed:
            assert result.usage == {"ok": True}
            # A new collection sees the committed live credential.
            snapshot = Snapshot(c)
        else:
            assert result.error in {"credential-unproven", "stash-unreadable"}
    if allowed:
        assert switcher._read_credentials() == c
        assert switcher._read_account_credentials("1", EMAIL) == c
        assert not switcher.list_unclaimed_credentials()
    else:
        assert switcher._read_credentials() == live
        assert switcher._read_account_credentials("1", EMAIL) == backup
        assert bool(switcher.list_unclaimed_credentials()) == pending
    assert [json.loads(v)["claudeAiOauth"]["refreshToken"] for v, _ in calls] == ([] if pending or not allowed else ["B-refresh"])


@pytest.mark.parametrize("missing,expected", [("live", "unreadable"), ("backup", "unreadable"), ("both", "no_refresh_token")])
def test_active_missing_or_unreadable_source_defers(active, monkeypatch, missing, expected):
    switcher, calls = active
    snapshot = Snapshot(credential("B"))
    if missing == "live":
        switcher._write_account_credentials("1", EMAIL, snapshot)
        # Reuse the concrete reader result shape, including Keychain status.
        read = switcher._read_active_credentials()
        monkeypatch.setattr(switcher, "_read_active_credentials", lambda: read._replace(value=None))
    elif missing == "backup":
        switcher._write_credentials(snapshot)
        monkeypatch.setattr(switcher, "_read_account_credentials_ex", lambda *a: ("", True))
    result = switcher._fetch_active_usage("1", EMAIL, snapshot)
    assert result.error == expected
    assert not calls


@pytest.mark.parametrize("fault", ["manifest", "bytes"])
@pytest.mark.parametrize("failed_store", ["backup", "live"])
def test_stale_live_unreadable_stash_recovers(active, monkeypatch, fault, failed_store):
    switcher, calls = active
    live, backup = Snapshot(aged("B", 2000)), aged("B", 2000)
    switcher._write_credentials(live)
    switcher._write_account_credentials("1", EMAIL, backup)
    with monkeypatch.context() as failure:
        def fail(*args):
            raise OSError("synthetic failure")
        failure.setattr(switcher._store if failed_store == "backup" else switcher,
                        "_write_account_credentials" if failed_store == "backup" else "_write_credentials", fail)
        assert switcher._fetch_active_usage("1", EMAIL, live).error == "transient"
    before = (switcher._read_credentials(), switcher._read_account_credentials("1", EMAIL))
    entries = switcher.list_unclaimed_credentials()
    with monkeypatch.context() as failure:
        if fault == "manifest":
            failure.setattr(switcher._store, "_read_stash_manifest_ex", lambda: ({}, "unreadable"))
        else:
            failure.setattr(switcher._store, "_read_unclaimed_credential", lambda *a: ("", True))
        assert switcher._fetch_active_usage("1", EMAIL, live).error == "stash-unreadable"
    assert before == (switcher._read_credentials(), switcher._read_account_credentials("1", EMAIL))
    assert switcher.list_unclaimed_credentials() == entries
    assert switcher._fetch_active_usage("1", EMAIL, live).usage == {"ok": True}
    assert len(calls) == 1
    assert switcher._read_credentials() == credential("successor")
    assert switcher._read_account_credentials("1", EMAIL) == credential("successor")
    assert not switcher.list_unclaimed_credentials()


@pytest.mark.parametrize("saved_store", ["live", "backup"])
def test_partial_completion_with_older_backup_or_equal_expiry(active, saved_store):
    switcher, calls = active
    b, c = aged("B", 2000), aged("successor", 2000)
    live, backup = (c, b) if saved_store == "live" else (aged("A", 3000), c)
    switcher._write_credentials(live)
    switcher._write_account_credentials("1", EMAIL, backup)
    stash(switcher, b, c,
          observedLiveFp=oauth.credential_fingerprint(b if saved_store == "live" else live),
          observedBackupFp=oauth.credential_fingerprint(b))
    assert switcher._fetch_active_usage("1", EMAIL, Snapshot(live)).usage == {"ok": True}
    assert not calls
    assert switcher._read_credentials() == c
    assert switcher._read_account_credentials("1", EMAIL) == c
    assert not switcher.list_unclaimed_credentials()


@pytest.mark.parametrize("control", ["identity", "generation", "owner", "ambiguous", "fingerprint"])
def test_active_stash_controls_preserve_copies(active, monkeypatch, control):
    from claude_swap import profile_ownership
    switcher, calls = active
    live, backup = Snapshot(aged("A", 3000)), aged("B", 2000)
    switcher._write_credentials(live)
    switcher._write_account_credentials("1", EMAIL, backup)
    overrides = {}
    if control == "identity":
        overrides["identity"] = {"email": "foreign@example.com"}
    if control == "generation":
        overrides["loginGen"] = 1
    if control == "fingerprint":
        overrides["fingerprint"] = "mismatch"
    stash(switcher, backup, **overrides)
    if control == "owner":
        monkeypatch.setattr(profile_ownership, "profile_busy_locked", lambda *a, **k: True)
    if control == "ambiguous":
        stash(switcher, backup, credential("different-successor"))
    entries = switcher.list_unclaimed_credentials()
    result = switcher._fetch_active_usage("1", EMAIL, live)
    if control == "owner":
        assert result.error == "profile-busy"
    else:
        assert result.error in {"credential-unproven", "stash-unreadable"}
    assert not calls
    assert switcher._read_credentials() == live
    assert switcher._read_account_credentials("1", EMAIL) == backup
    assert switcher.list_unclaimed_credentials() == entries


def test_lazy_backup_refresh_returns_fresh_store_without_post(active):
    switcher, calls = active
    fresh = aged("S", 9999999999999)
    switcher._write_account_credentials("1", EMAIL, fresh)
    outcome = switcher._refresh_usage_backup("1", EMAIL, credential("D"))
    assert outcome.credentials == fresh
    assert not calls


def test_both_saved_successors_retire_stash_without_network(active):
    switcher, calls = active
    b, c = credential("B"), credential("successor")
    switcher._write_credentials(c)
    switcher._write_account_credentials("1", EMAIL, c)
    stash(switcher, b, c)
    result = switcher._fetch_active_usage("1", EMAIL, Snapshot(b))
    assert result.usage == {"ok": True}
    assert not calls
    assert switcher._read_credentials() == c
    assert switcher._read_account_credentials("1", EMAIL) == c
    assert not switcher.list_unclaimed_credentials()


def test_partial_legacy_row_with_unreadable_bytes_never_posts(active, monkeypatch):
    switcher, calls = active
    b, c = credential("B"), credential("successor")
    switcher._write_credentials(b)
    switcher._write_account_credentials("1", EMAIL, c)
    stash(switcher, b, c, observed=False, fingerprint=None)
    with monkeypatch.context() as fault:
        fault.setattr(switcher._store, "_read_unclaimed_credential", lambda *a: ("", True))
        assert switcher._fetch_active_usage("1", EMAIL, Snapshot(b)).error == "stash-unreadable"
    assert not calls
    assert switcher._read_credentials() == b
    assert switcher._read_account_credentials("1", EMAIL) == c
    assert switcher.list_unclaimed_credentials()
    assert switcher._fetch_active_usage("1", EMAIL, Snapshot(b)).usage == {"ok": True}
    assert not calls
    assert switcher._read_credentials() == c
    assert not switcher.list_unclaimed_credentials()


@pytest.mark.parametrize("store", ["backup", "live"])
def test_adoption_write_failure_preserves_stash_until_both_saved(active, monkeypatch, store):
    switcher, calls = active
    live, b = Snapshot(aged("A")), aged("B", 2000)
    switcher._write_credentials(live)
    switcher._write_account_credentials("1", EMAIL, b)
    stash(switcher, b)
    with monkeypatch.context() as fault:
        def fail(*a):
            raise OSError("synthetic adoption write failure")
        fault.setattr(switcher._store if store == "backup" else switcher,
                      "_write_account_credentials" if store == "backup" else "_write_credentials", fail)
        assert switcher._fetch_active_usage("1", EMAIL, live).error == "transient"
    assert not calls
    assert switcher.list_unclaimed_credentials()
    assert switcher._fetch_active_usage("1", EMAIL, live).usage == {"ok": True}
    assert not calls
    assert switcher._read_credentials() == credential("successor")
    assert switcher._read_account_credentials("1", EMAIL) == credential("successor")
    assert not switcher.list_unclaimed_credentials()


@pytest.mark.parametrize("replacement_name", ["D", "X"])
@pytest.mark.parametrize("history", ["changed-after-failure", "legacy-unrelated"])
def test_active_recovery_preserves_unobserved_live(active, monkeypatch, history, replacement_name):
    switcher, calls = active
    a, b, c = aged("B", 2000), aged("B", 2000), credential("successor")
    switcher._write_credentials(a)
    switcher._write_account_credentials("1", EMAIL, b)
    def fetch():
        return switcher._fetch_account_usage((1, EMAIL, "", "", True,
                                              str(switcher._read_credentials()), ""))
    if history == "changed-after-failure":
        with monkeypatch.context() as failure:
            def fail(*args):
                raise OSError("synthetic live failure")
            failure.setattr(switcher, "_write_credentials", fail)
            assert fetch().error == "transient"
        assert [json.loads(v)["claudeAiOauth"]["refreshToken"] for v, _ in calls] == ["B-refresh"]
        replacement = aged(replacement_name, 5000)
    else:
        switcher._write_account_credentials("1", EMAIL, c)
        stash(switcher, b, c, observed=False)
        replacement = aged(replacement_name, 5000)
    switcher._write_credentials(replacement)
    entries = switcher.list_unclaimed_credentials()
    before_posts = len(calls)
    result = fetch()
    assert len(calls) == before_posts
    assert switcher._read_credentials() == replacement
    assert switcher._read_account_credentials("1", EMAIL) == c
    assert switcher.list_unclaimed_credentials() == entries
    assert result.error == "stash-unreadable"


@pytest.mark.parametrize("changed_store", ["live", "backup"])
@pytest.mark.parametrize("failed_store", ["live", "backup"])
def test_active_recovery_requires_both_first_pass_observations(active, monkeypatch, changed_store, failed_store):
    switcher, calls = active
    a, b = aged("B", 2000), aged("B", 2000)
    switcher._write_credentials(a)
    switcher._write_account_credentials("1", EMAIL, b)
    def fetch():
        return switcher._fetch_account_usage((1, EMAIL, "", "", True,
                                              str(switcher._read_credentials()), ""))
    with monkeypatch.context() as failure:
        def fail(*args):
            raise OSError("synthetic failure")
        failure.setattr(switcher if failed_store == "live" else switcher._store,
                        "_write_credentials" if failed_store == "live" else "_write_account_credentials", fail)
        assert fetch().error == "transient"
    replacement = aged("replacement", 5000)
    if changed_store == "live":
        switcher._write_credentials(replacement)
    else:
        switcher._store._write_account_credentials("1", EMAIL, replacement)
    before = (switcher._read_credentials(), switcher._read_account_credentials("1", EMAIL))
    entries = switcher.list_unclaimed_credentials()
    assert fetch().error in {"stash-unreadable", "ownership-lost"}
    assert len(calls) == 1
    assert before == (switcher._read_credentials(), switcher._read_account_credentials("1", EMAIL))
    assert switcher.list_unclaimed_credentials() == entries


@pytest.mark.parametrize("observed", [False, True])
@pytest.mark.parametrize("empty_store", ["live", "backup"])
def test_active_empty_copy_requires_explicit_first_pass_observation(active, empty_store, observed):
    switcher, calls = active
    b = credential("B")
    switcher._write_credentials("" if empty_store == "live" else b)
    if empty_store != "backup":
        switcher._write_account_credentials("1", EMAIL, b)
    stash(switcher, b, observed=observed)
    before = (switcher._read_credentials(), switcher._read_account_credentials("1", EMAIL))
    result = switcher._fetch_active_usage("1", EMAIL, Snapshot(b))
    assert not calls
    if observed:
        assert result.usage == {"ok": True}
        assert not switcher.list_unclaimed_credentials()
    else:
        assert result.error == "stash-unreadable"
        assert before == (switcher._read_credentials(), switcher._read_account_credentials("1", EMAIL))
        assert switcher.list_unclaimed_credentials()


@pytest.mark.parametrize("shape", ["equal", "live-older", "backup-older", "equal-expiry", "only-live"])
def test_collection_orphan_successor_defers_without_second_post(active, monkeypatch, shape):
    import time
    from claude_swap.switcher import _usage_entry_lines
    switcher, calls = active
    b = aged("B", 2000)
    pairs = {
        "equal": (b, b), "live-older": (aged("A"), b),
        "backup-older": (b, aged("A")),
        "equal-expiry": (aged("A", 2000), b), "only-live": (b, ""),
    }
    live, backup = pairs[shape]
    switcher._write_credentials(live)
    if backup:
        switcher._write_account_credentials("1", EMAIL, backup)
    clock = {"now": time.time()}
    switcher._usage_store.clock = lambda: clock["now"]
    def collect():
        info = (1, EMAIL, "", "", True, str(switcher._read_credentials()), "")
        return switcher._collect_usage_entries([info], {"1"})["1"]
    with monkeypatch.context() as failure:
        def fail(*args):
            raise OSError("synthetic persistence failure")
        failure.setattr(switcher._store, "_write_account_credentials", fail)
        failure.setattr(switcher._store, "_write_stash_manifest", fail)
        first = collect()
    assert first.last_error is not None
    entries = switcher.list_unclaimed_credentials()
    if shape in {"equal", "only-live"}:
        assert len(calls) == 1
        assert entries
        entry_id = next(iter(entries))
        assert switcher._store._read_unclaimed_credential(entry_id) == (credential("successor"), False)
        assert switcher._store._read_stash_manifest_ex() == ({}, "ok")
    else:
        assert not calls
    clock["now"] += 3600
    second = collect()
    assert len(calls) == (1 if entries else 0)
    assert switcher._read_credentials() == live
    assert switcher._read_account_credentials("1", EMAIL) == backup
    assert switcher.list_unclaimed_credentials() == entries
    assert "log in" in " ".join(_usage_entry_lines(second)).lower()


@pytest.mark.parametrize("manifest_state", ["missing", "empty", "mapped", "scan-failed"])
def test_active_unmapped_stash_or_uncertain_scan_never_posts(active, monkeypatch, manifest_state):
    switcher, calls = active
    b = Snapshot(credential("B"))
    switcher._write_credentials(b)
    switcher._write_account_credentials("1", EMAIL, b)
    if manifest_state == "mapped":
        stash(switcher, b)
    if manifest_state == "empty":
        switcher._store._write_stash_manifest({})
    if manifest_state != "scan-failed":
        with monkeypatch.context() as failure:
            def fail(*args):
                raise OSError("synthetic manifest write failure")
            failure.setattr(switcher._store, "_write_stash_manifest", fail)
            with pytest.raises(OSError):
                stash(switcher, b, credential("orphan"))
    else:
        from pathlib import Path
        iterdir = Path.iterdir
        def denied(path):
            if path == switcher.credentials_dir:
                raise PermissionError("synthetic stash scan failure")
            return iterdir(path)
        monkeypatch.setattr(Path, "iterdir", denied)
    paths = list(switcher.credentials_dir.glob(".unclaimed-*"))
    before = {path: path.read_bytes() for path in paths}
    for _ in range(2):
        result = switcher._fetch_account_usage((1, EMAIL, "", "", True, str(b), ""))
        assert result.error == "stash-unreadable"
    assert {path: path.read_bytes() for path in paths} == before
    assert not calls
    assert switcher._read_credentials() == b
    assert switcher._read_account_credentials("1", EMAIL) == b


@pytest.mark.parametrize("shape", ["live-older", "backup-older", "equal-expiry"])
def test_expiry_order_is_not_refresh_authority(active, shape):
    switcher, calls = active
    a, b = aged("A"), aged("B", 2000)
    live, backup = {"live-older": (a, b), "backup-older": (b, a),
                    "equal-expiry": (aged("A", 2000), b)}[shape]
    switcher._write_credentials(live)
    switcher._write_account_credentials("1", EMAIL, backup)
    for _ in range(2):
        result = switcher._fetch_account_usage((1, EMAIL, "", "", True, live, ""))
        assert result.error == "credential-unproven"
    assert not calls
    assert switcher._read_credentials() == live
    assert switcher._read_account_credentials("1", EMAIL) == backup


@pytest.mark.parametrize("path", ["active", "backup"])
@pytest.mark.parametrize("state", ["orphan", "unknown-row", "bad-row", "unreadable-manifest", "scan-failed"])
def test_shared_stash_guard_preserves_local_state(active, monkeypatch, path, state):
    switcher, calls = active
    b = Snapshot(credential("B"))
    switcher._write_credentials(b)
    switcher._write_account_credentials("1", EMAIL, b)
    store = switcher._store
    if state == "orphan":
        store._atomic_b64_write(store._stash_entry_path("synthetic-orphan"), credential("pending"))
    elif state == "unknown-row":
        store._write_unclaimed_credential(credential("pending"), {"configSlot": "1"})
    elif state == "bad-row":
        store._write_stash_manifest({"synthetic-invalid": []})
    elif state == "unreadable-manifest":
        monkeypatch.setattr(store, "_read_stash_manifest_ex", lambda: ({}, "unreadable"))
    else:
        from pathlib import Path
        original_iterdir = Path.iterdir
        def fail_stash_scan(directory):
            if directory == switcher.credentials_dir:
                raise OSError("synthetic directory read failure")
            return original_iterdir(directory)
        monkeypatch.setattr(Path, "iterdir", fail_stash_scan)
    paths = list(switcher.credentials_dir.glob(".unclaimed-*"))
    before = {p: p.read_bytes() for p in paths}
    if path == "active":
        result = switcher._fetch_active_usage("1", EMAIL, b)
    else:
        result = switcher.consume_backup_grant("1", EMAIL, switcher.credential_snapshot("1", EMAIL))
    assert result.error == "stash-unreadable"
    assert not calls
    assert switcher._read_credentials() == b
    assert switcher._read_account_credentials("1", EMAIL) == b
    assert {p: p.read_bytes() for p in paths} == before


@pytest.mark.parametrize("path", ["active", "backup"])
@pytest.mark.parametrize("reason", [
    "displaced-live-login", "foreign", "alien", "known-foreign",
    "setup-token-mismatch", "api-key-mismatch",
])
def test_switch_safety_copy_does_not_block_refresh(active, path, reason):
    switcher, calls = active
    b = Snapshot(credential("B"))
    switcher._write_credentials(b)
    switcher._write_account_credentials("1", EMAIL, b)
    entry = switcher._stash_live_credential(b, reason, "1", None)
    before = switcher._store._stash_entry_path(entry).read_bytes()
    if path == "backup":
        data = switcher._read_json(switcher.sequence_file)
        data["activeAccountNumber"] = None
        switcher._write_json(switcher.sequence_file, data)
        switcher._write_credentials(credential("another-account"))
    if path == "active":
        result = switcher._fetch_active_usage("1", EMAIL, b)
        assert result.usage == {"ok": True}
        assert switcher._read_credentials() == credential("successor")
    else:
        result = switcher.consume_backup_grant("1", EMAIL, switcher.credential_snapshot("1", EMAIL))
        assert result.error is None
        assert result.credentials == credential("successor")
    assert len(calls) == 1
    assert switcher._read_account_credentials("1", EMAIL) == credential("successor")
    assert switcher._store._stash_entry_path(entry).read_bytes() == before
    assert entry in switcher.list_unclaimed_credentials()


def test_failed_stash_publication_logs_slot_and_entry_without_credentials(active, monkeypatch, caplog):
    switcher, _ = active
    def fail(*args):
        raise OSError("synthetic publication failure")
    monkeypatch.setattr(switcher._store, "_write_stash_manifest", fail)
    with pytest.raises(OSError):
        switcher._store._write_unclaimed_credential(credential("secret-pending"), {"configSlot": "1"})
    entry = next(iter(switcher.list_unclaimed_credentials()))
    assert "account 1" in caplog.text
    assert entry in caplog.text
    assert "secret-pending" not in caplog.text


def test_busy_profile_never_requests_relogin_in_collected_output(active, monkeypatch):
    from claude_swap import profile_ownership
    from claude_swap.switcher import _usage_entry_lines
    switcher, calls = active
    b = Snapshot(credential("B"))
    switcher._write_credentials(b)
    switcher._write_account_credentials("1", EMAIL, b)
    monkeypatch.setattr(profile_ownership, "profile_busy_locked", lambda *a, **k: True)
    infos = [(1, EMAIL, "", "", True, str(b), "")]
    entry = switcher._collect_usage_entries(infos, {"1"})["1"]
    text = " ".join(_usage_entry_lines(entry)).lower()
    assert "log in again" not in text
    assert "cswap add" not in text
    assert not calls

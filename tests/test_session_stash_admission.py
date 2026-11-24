"""Session admission checks against consumed or unverifiable stash state."""

import json
from unittest.mock import patch

import pytest

from claude_swap import oauth, profile_ownership, refresh_authority
from claude_swap import session as session_mod
from claude_swap.exceptions import SessionError
from claude_swap.locking import FileLock
from claude_swap.session import session_dir_for
from tests.test_session import (
    ACCOUNT_EMAIL, ACCOUNT_NUM, ORG_UUID, CONFIG, CREDS, ROTATED_CREDS,
    _ExecCalled, _admitted_unit_launch, _default_login_signed_in,
    _stub_claude_resolution, auth_status_tracks_seed, capture_exec,
    macos_platform, manager, seeded_switcher,
)

pytestmark = pytest.mark.mock_stand_routing


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials",
                        lambda *a, **k: pytest.fail("unexpected refresh POST"))
    monkeypatch.setattr(oauth, "fetch_usage",
                        lambda *a, **k: pytest.fail("unexpected usage request"))


def ready(switcher, credentials=CREDS):
    profile = session_dir_for(switcher.backup_dir, ACCOUNT_NUM, ACCOUNT_EMAIL)
    profile.mkdir(parents=True, exist_ok=True)
    (profile / ".credentials.json").write_text(credentials)
    (profile / ".claude.json").write_text(CONFIG)
    return profile


def stash(switcher, reason="consume-gate-store-unreadable"):
    snapshot = switcher.credential_snapshot(ACCOUNT_NUM, ACCOUNT_EMAIL)
    return switcher._store._write_unclaimed_credential(ROTATED_CREDS, {
        "reason": reason, "configSlot": ACCOUNT_NUM,
        "identity": snapshot.identity, "loginGen": snapshot.login_gen,
        "consumedFp": oauth.credential_fingerprint(CREDS),
        "fingerprint": oauth.credential_fingerprint(ROTATED_CREDS),
    })


def orphan(switcher):
    switcher.credentials_dir.joinpath(".unclaimed-orphan.enc").write_text("opaque")


@pytest.mark.parametrize("pass_number", [1, 2])
@pytest.mark.parametrize("unreadable", [False, True])
def test_consumed_profile_refused_with_unavailable_backup(
    manager, seeded_switcher, monkeypatch, pass_number, unreadable,
):
    profile = ready(seeded_switcher)
    stash(seeded_switcher)
    before = {p.name: p.read_bytes() for p in profile.iterdir()}
    monkeypatch.setattr(seeded_switcher, "credential_snapshot", lambda *a: "")
    monkeypatch.setattr(seeded_switcher, "read_account_credentials", lambda *a: "")
    monkeypatch.setattr(seeded_switcher, "_read_account_credentials_ex",
                        lambda *a: ("", unreadable))
    calls = []
    def valid(*a, **k):
        calls.append(True)
        return pass_number == 1 or len(calls) > 1
    monkeypatch.setattr(manager, "_is_session_valid", valid)
    cause = "backup is unreadable" if unreadable else "no stored credentials"
    with pytest.raises(SessionError, match=cause):
        manager.setup_session(ACCOUNT_NUM, share=False)
    assert {p.name: p.read_bytes() for p in profile.iterdir()} == before


@pytest.mark.parametrize("pass_number", [1, 2])
def test_consumed_profile_refused_despite_orphan_and_independent_backup(
    manager, seeded_switcher, monkeypatch, pass_number,
):
    profile = ready(seeded_switcher)
    stash(seeded_switcher)
    orphan(seeded_switcher)
    seeded_switcher._store._write_account_credentials(ACCOUNT_NUM, ACCOUNT_EMAIL, ROTATED_CREDS)
    calls = []
    def valid(*a, **k):
        calls.append(True)
        return pass_number == 1 or len(calls) > 1
    monkeypatch.setattr(manager, "_is_session_valid", valid)
    with pytest.raises(SessionError, match="stash recovery is blocked"):
        manager.setup_session(ACCOUNT_NUM, share=False)
    assert (profile / ".credentials.json").read_text() == CREDS


@pytest.mark.parametrize("warm", [False, True])
@pytest.mark.parametrize("has_file", [False, True])
def test_corrupt_manifest_only_blocks_when_files_exist(
    manager, seeded_switcher, auth_status_tracks_seed, monkeypatch, warm, has_file,
):
    profile = ready(seeded_switcher) if warm else session_dir_for(
        seeded_switcher.backup_dir, ACCOUNT_NUM, ACCOUNT_EMAIL)
    seeded_switcher._store._stash_manifest_path().write_text("{broken")
    if has_file:
        orphan(seeded_switcher)
    posts = []
    def post(*a, **k):
        posts.append(True)
        return oauth.RefreshOutcome(ROTATED_CREDS, None)
    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", post)
    if has_file:
        with pytest.raises(SessionError):
            manager.setup_session(ACCOUNT_NUM, share=False)
        assert not posts
        assert (profile / ".credentials.json").read_text() == CREDS if warm else not profile.exists()
    else:
        assert manager.setup_session(ACCOUNT_NUM, share=False)[0] == profile
        assert len(posts) == (0 if warm else 1)


def test_bootstrap_checks_one_read_before_touching_profile(manager, seeded_switcher, monkeypatch):
    profile = ready(seeded_switcher)
    stash(seeded_switcher)
    before = {p.name: p.read_bytes() for p in profile.iterdir()}
    reads = []
    def read(*a):
        reads.append(True)
        return CREDS, False
    monkeypatch.setattr(seeded_switcher, "read_account_credentials", lambda *a: "")
    monkeypatch.setattr(seeded_switcher, "_read_account_credentials_ex", read)
    monkeypatch.setattr(session_mod, "delete_macos_keychain_entry",
                        lambda *a: pytest.fail("Keychain deleted before admission"))
    with pytest.raises(SessionError):
        manager._bootstrap(profile, ACCOUNT_NUM, ACCOUNT_EMAIL, ORG_UUID)
    assert reads == [True]
    assert {p.name: p.read_bytes() for p in profile.iterdir()} == before


def test_bootstrap_writes_exactly_the_checked_snapshot(manager, seeded_switcher, monkeypatch):
    profile = ready(seeded_switcher)
    reads = []
    def read(*a):
        reads.append(True)
        return (ROTATED_CREDS if len(reads) == 1 else CREDS), False
    monkeypatch.setattr(seeded_switcher, "_read_account_credentials_ex", read)
    monkeypatch.setattr(manager, "_guard_profile_rebuild", lambda *a: None)
    manager._bootstrap(profile, ACCOUNT_NUM, ACCOUNT_EMAIL, ORG_UUID)
    assert reads == [True]
    assert (profile / ".credentials.json").read_text() == ROTATED_CREDS


def test_empty_stash_admission_reads_neither_profile_nor_backup(manager, seeded_switcher, monkeypatch):
    profile = ready(seeded_switcher)
    def no_read(*a):
        pytest.fail("empty stash must not read credentials")
    monkeypatch.setattr(seeded_switcher, "read_account_credentials", no_read)
    monkeypatch.setattr(seeded_switcher, "_read_account_credentials_ex", no_read)
    monkeypatch.setattr(session_mod, "read_session_credentials", no_read)
    with FileLock(seeded_switcher.lock_file):
        assert manager._profile_stash_status(profile, ACCOUNT_NUM, ACCOUNT_EMAIL) is None


@pytest.mark.parametrize("error", ["profile-busy", "consume-busy", "store-unmirrored"])
@pytest.mark.parametrize("warm", [False, True])
def test_real_gate_early_exit_cannot_bypass_orphan_admission(
    manager, seeded_switcher, auth_status_tracks_seed, monkeypatch, error, warm,
):
    profile = ready(seeded_switcher) if warm else session_dir_for(
        seeded_switcher.backup_dir, ACCOUNT_NUM, ACCOUNT_EMAIL)
    orphan(seeded_switcher)
    # Skip only the first reuse probe so preparation reaches the real gate.
    valid = manager._is_session_valid
    calls = []
    def probe(*a, **k):
        calls.append(True)
        return False if len(calls) == 1 else valid(*a, **k)
    monkeypatch.setattr(manager, "_is_session_valid", probe)
    gate = seeded_switcher.consume_backup_grant
    outcomes = []
    def observed(*a, **k):
        if error == "store-unmirrored":
            with patch.dict("os.environ", {"CLAUDE_SECURESTORAGE_CONFIG_DIR": str(profile)}):
                outcome = gate(*a, **k)
        elif error == "profile-busy":
            with patch.object(profile_ownership, "profile_busy_locked", return_value=True):
                outcome = gate(*a, **k)
        else:
            right = refresh_authority.consume_lock(seeded_switcher.backup_dir, ACCOUNT_EMAIL, ORG_UUID)
            assert right.acquire(timeout=0)
            try:
                outcome = gate(*a, **{**k, "timeout": 0})
            finally:
                right.release()
        outcomes.append(outcome.error)
        return outcome
    monkeypatch.setattr(seeded_switcher, "consume_backup_grant", observed)
    with pytest.raises(SessionError):
        manager.setup_session(ACCOUNT_NUM, share=False)
    assert outcomes == [error]
    assert (profile / ".credentials.json").read_text() == CREDS if warm else not profile.exists()


@pytest.mark.parametrize("mode", ["safety", "independent", "setup-token", "default"])
def test_safe_launch_controls(manager, seeded_switcher, auth_status_tracks_seed, capture_exec, monkeypatch, mode):
    credentials = CREDS
    if mode == "safety":
        for _ in range(6):
            seeded_switcher._store._write_unclaimed_credential(ROTATED_CREDS, {
                "reason": "displaced-live-login", "configSlot": ACCOUNT_NUM,
                "fingerprint": oauth.credential_fingerprint(ROTATED_CREDS),
            })
        assert len(seeded_switcher._store._list_unclaimed_credentials()) == 6
    elif mode == "independent":
        orphan(seeded_switcher)
        credentials = ROTATED_CREDS
    elif mode == "setup-token":
        orphan(seeded_switcher)
        credentials = json.dumps({"claudeAiOauth": {"accessToken": "synthetic-setup"}})
        seeded_switcher._store._write_account_credentials(ACCOUNT_NUM, ACCOUNT_EMAIL, credentials)
    else:
        orphan(seeded_switcher)
        monkeypatch.setattr(seeded_switcher, "_get_current_account", lambda: (ACCOUNT_EMAIL, ORG_UUID))
    profile = ready(seeded_switcher, credentials)
    if mode == "default":
        with pytest.raises(_ExecCalled) as exc:
            manager.run(ACCOUNT_NUM, [])
        assert exc.value.env is None or "CLAUDE_CONFIG_DIR" not in exc.value.env
    else:
        assert manager.setup_session(ACCOUNT_NUM, share=False)[0] == profile
    assert (profile / ".credentials.json").read_text() == credentials


def credential_state(switcher, profile):
    return (
        {p.name: p.read_bytes() for p in profile.rglob("*") if p.is_file()}
        if profile.exists() else None,
        switcher._read_account_credentials_ex(ACCOUNT_NUM, ACCOUNT_EMAIL),
        {p.name: p.read_bytes() for p in switcher.credentials_dir.glob(".unclaimed*")
         if p.is_file() and p.suffix != ".lock"},
    )


@pytest.mark.parametrize("condition", ["orphan", "corrupt", "busy"])
@pytest.mark.parametrize("setup_token", [False, True])
def test_cold_stash_admission_checks_exact_seed_without_post(
    manager, seeded_switcher, auth_status_tracks_seed, monkeypatch, condition, setup_token,
):
    credentials = (json.dumps({"claudeAiOauth": {"accessToken": "synthetic-setup"}})
                   if setup_token else CREDS)
    seeded_switcher._store._write_account_credentials(ACCOUNT_NUM, ACCOUNT_EMAIL, credentials)
    profile = session_dir_for(seeded_switcher.backup_dir, ACCOUNT_NUM, ACCOUNT_EMAIL)
    orphan(seeded_switcher)
    if condition == "corrupt":
        seeded_switcher._store._stash_manifest_path().write_text("{broken")
    elif condition == "busy":
        monkeypatch.setattr(seeded_switcher._store, "_stash_snapshot",
                            lambda: ({}, set(), "busy"))
    before = credential_state(seeded_switcher, profile)
    posts = []
    def post(*a, **k):
        posts.append(True)
        pytest.fail("stash admission must not POST")
    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", post)
    if setup_token:
        assert manager.setup_session(ACCOUNT_NUM, share=False)[0] == profile
        assert (profile / ".credentials.json").read_text() == credentials
    else:
        with pytest.raises(SessionError, match="busy" if condition == "busy" else "stash recovery is blocked"):
            manager.setup_session(ACCOUNT_NUM, share=False)
        assert credential_state(seeded_switcher, profile) == before
    assert not posts


def test_active_default_login_ignores_busy_stash(
    manager, seeded_switcher, capture_exec, monkeypatch,
):
    monkeypatch.setattr(seeded_switcher._store, "_stash_snapshot",
                        lambda: ({}, set(), "busy"))
    monkeypatch.setattr(seeded_switcher, "_get_current_account",
                        lambda: (ACCOUNT_EMAIL, ORG_UUID))
    profile = session_dir_for(seeded_switcher.backup_dir, ACCOUNT_NUM, ACCOUNT_EMAIL)
    before = credential_state(seeded_switcher, profile)
    with pytest.raises(_ExecCalled) as exc:
        manager.run(ACCOUNT_NUM, [])
    assert exc.value.env is None or "CLAUDE_CONFIG_DIR" not in exc.value.env
    assert credential_state(seeded_switcher, profile) == before

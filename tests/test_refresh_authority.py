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
        assert result.error == "ownership-lost"
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


def test_collector_reads_bytes_with_generation_under_same_lock(temp_home, sample_sequence_data):
    from claude_swap import refresh_authority as authority
    from claude_swap.locking import FileLock
    s, email = seeded(sample_sequence_data)
    def generation(*args):
        probe = FileLock(s.lock_file, timeout=0)
        assert not probe.acquire(timeout=0), "generation escaped account lock"
        return 7
    with patch("claude_swap.refresh_authority.login_generation", side_effect=generation):
        entries = s._build_accounts_info()
    assert entries[0][5].login_gen == 7
    assert entries[0][5].identity == s.account_identity("1")


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

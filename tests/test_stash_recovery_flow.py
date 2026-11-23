"""Collection-level recovery after a successor's stash metadata is lost."""
import json
import time
import urllib.error

import pytest

from claude_swap import oauth
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.usage_store import FetchRecord


EMAIL = "recovery@example.com"
OTHER_EMAIL = "other@example.com"
HISTORY = {"five_hour": {"pct": 23, "resets_at": "2099-01-01T00:00:00Z"}}


def credential(name, *, expired=True):
    return json.dumps({"claudeAiOauth": {
        "accessToken": name + "-access", "refreshToken": name + "-refresh",
        "expiresAt": 1000 if expired else 9999999999999,
    }})


def login(switcher, email, value, slot):
    """Model Claude Code replacing the live login without touching backups."""
    switcher._write_json(switcher._get_claude_config_path(), {
        "oauthAccount": {"emailAddress": email},
    })
    switcher._write_credentials(value)
    data = switcher._get_sequence_data()
    data["activeAccountNumber"] = slot
    switcher._write_json(switcher.sequence_file, data)


@pytest.fixture
def recovery(temp_home, monkeypatch):
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._write_json(switcher.sequence_file, {
        "sequence": [1, 2], "activeAccountNumber": "1",
        "accounts": {"1": {"email": EMAIL}, "2": {"email": OTHER_EMAIL}},
    })
    switcher._write_account_credentials("1", EMAIL, credential("B"))
    other = credential("other", expired=False)
    switcher._write_account_credentials("2", OTHER_EMAIL, other)
    login(switcher, EMAIL, credential("B"), "1")
    now = [time.time()]
    monkeypatch.setattr(switcher._usage_store, "clock", lambda: now[0])
    # Keep a real historical reading, so error guidance cannot rely on an
    # empty quota row to make it visible.
    switcher._usage_store.record({"1": FetchRecord(usage=HISTORY)}, {"1": (EMAIL, "")})
    now[0] += 1000
    calls = []

    def refresh(value, timeout_s=10.0):
        name = json.loads(value)["claudeAiOauth"]["refreshToken"]
        calls.append(name)
        if calls.count(name) > 1:
            return oauth.RefreshOutcome(None, "invalid_grant")
        successor = "C" if name == "B-refresh" else "D-successor"
        return oauth.RefreshOutcome(credential(successor, expired=False), None)

    def usage(access_token):
        if access_token in {"B-access", "D-access"}:
            raise urllib.error.HTTPError("https://synthetic.invalid/usage", 401, "expired", {}, None)
        return {"five_hour": {"utilization": 31, "resets_at": "2099-01-01T00:00:00Z"}}

    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", refresh)
    monkeypatch.setattr(oauth, "request_usage_data", usage)
    monkeypatch.setattr(oauth, "fetch_oauth_profile", lambda *a, **k: None)
    return switcher, calls, now


def collect(switcher):
    return switcher._collect_usage_entries(switcher._build_accounts_info(cached=False), fetch={"1"})["1"]


def fail_persistence(monkeypatch, switcher):
    def fail(*args, **kwargs):
        raise OSError("synthetic persistence failure")
    monkeypatch.setattr(switcher._store, "_write_account_credentials", fail)
    monkeypatch.setattr(switcher._store, "_write_stash_manifest", fail)


def preserved_orphan(switcher):
    entries = switcher.list_unclaimed_credentials()
    assert len(entries) == 1
    entry_id = next(iter(entries))
    assert switcher._store._read_unclaimed_credential(entry_id) == (credential("C", expired=False), False)
    assert switcher._read_account_credentials("1", EMAIL) == credential("B")
    return entry_id


@pytest.mark.parametrize("initial_active", [True, False], ids=["active-then-inactive", "backup-gate"])
def test_orphaned_successor_blocks_collection_until_registered_login_and_purge(recovery, monkeypatch, initial_active):
    switcher, calls, now = recovery
    if not initial_active:
        login(switcher, OTHER_EMAIL, credential("other", expired=False), "2")
    with monkeypatch.context() as failure:
        fail_persistence(failure, switcher)
        first = collect(switcher)
    assert calls == ["B-refresh"]
    assert first.struck_fingerprint is None
    entry_id = preserved_orphan(switcher)
    # The active path must not be the only path that remembers the failed
    # publication. Once inactive, this slot uses consume_backup_grant.
    login(switcher, OTHER_EMAIL, credential("other", expired=False), "2")
    now[0] += 1000
    blocked = collect(switcher)
    assert calls == ["B-refresh"]
    assert blocked.last_error == "stash-unreadable"
    assert blocked.struck_fingerprint is None
    assert blocked.auth_dead_strikes == 0
    assert blocked.last_good == first.last_good
    assert preserved_orphan(switcher) == entry_id
    # A second pass during failure backoff must preserve the same verdict.
    assert collect(switcher).last_error == "stash-unreadable"
    assert calls == ["B-refresh"]

    # The documented recovery order is a fresh /login, registration, then
    # removal of the orphan by ID. Registration must advance real authority.
    login(switcher, EMAIL, credential("D", expired=False), "1")
    switcher.add_account(slot=1, assume_yes=True)
    assert switcher._read_account_credentials("1", EMAIL) == credential("D", expired=False)
    assert entry_id in switcher.list_unclaimed_credentials()
    switcher._store._remove_unclaimed_credential(entry_id)
    assert not switcher.list_unclaimed_credentials()
    # Expiry changes metadata only; the newly registered refresh grant is D.
    switcher._write_credentials(credential("D"))
    switcher._write_account_credentials("1", EMAIL, credential("D"))
    now[0] += 1000
    healed = collect(switcher)
    assert healed.last_error is None
    assert healed.last_good["five_hour"]["pct"] == 31
    assert calls == ["B-refresh", "D-refresh"]
    expected = credential("D-successor", expired=False)
    assert switcher._read_credentials() == expected
    assert switcher._read_account_credentials("1", EMAIL) == expected
    assert collect(switcher).last_good == healed.last_good
    assert calls == ["B-refresh", "D-refresh"]


def assert_recovery_guidance(switcher, capsys):
    from claude_swap.tui.widgets import account_card_text

    switcher.list_accounts(fetch={"1"})
    output = capsys.readouterr().out
    account = next(acc for acc in switcher.accounts_snapshot(fetch={"1"}).accounts if acc.number == "1")
    card = account_card_text(account, width=120).plain
    for rendered in (output, card):
        assert "cswap unclaimed" in rendered
        assert "cswap add --slot N" in rendered
        assert "cswap unclaimed --purge ID" in rendered
    assert account.usage.last_error == "stash-unreadable"
    assert account.usage.last_good == HISTORY
    assert account.usage.struck_fingerprint is None
    assert account.usage.auth_dead_strikes == 0


def test_active_orphan_guidance_survives_cached_usage_and_expiry_backoff(recovery, monkeypatch, capsys):
    switcher, calls, now = recovery
    with monkeypatch.context() as failure:
        fail_persistence(failure, switcher)
        first = collect(switcher)
    assert first.last_error == "stash-unreadable"
    assert_recovery_guidance(switcher, capsys)
    entry_id = preserved_orphan(switcher)
    now[0] += 1000
    # The first list call discovers the blocked stash; the next one renders
    # the persisted error during backoff, with the active-expiry overlay.
    assert_recovery_guidance(switcher, capsys)
    now[0] += 1
    assert_recovery_guidance(switcher, capsys)
    assert calls == ["B-refresh"]
    assert preserved_orphan(switcher) == entry_id

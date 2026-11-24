"""New logins advance identity generation under the mutation locks."""

import json

import pytest

from claude_swap.exceptions import SessionError
from claude_swap.locking import FileLock
from claude_swap.models import Platform
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.transfer import import_accounts


EMAIL = "generation@example.com"


@pytest.fixture
def switcher(temp_home):
    switcher = ClaudeAccountSwitcher()
    switcher.platform = Platform.LINUX
    switcher._setup_directories()
    switcher._init_sequence_file()
    return switcher


def capture(switcher, monkeypatch):
    config = {"oauthAccount": {"emailAddress": EMAIL, "accountUuid": "account"}}
    switcher._get_claude_config_path().write_text(json.dumps(config))
    monkeypatch.setattr(switcher, "_get_current_identity_triple", lambda: (EMAIL, "", "account"))
    monkeypatch.setattr(switcher, "_read_capture_credentials", lambda: '{"claudeAiOauth": {"accessToken": "synthetic"}}')
    monkeypatch.setattr(switcher, "_reject_foreign_credential_capture", lambda creds, *args: creds)
    monkeypatch.setattr(switcher, "_reject_credential_drift_since_verify", lambda *args: None)
    monkeypatch.setattr(switcher, "_reject_identity_drift_since_verify", lambda *args: None)


def replace(switcher, kind, slot=None):
    if kind == "capture":
        switcher.add_account(slot=slot, assume_yes=True)
    else:
        switcher.add_account_from_token("synthetic-token", email=EMAIL, slot=slot, assume_yes=True)


@pytest.mark.parametrize("kind", ["capture", "token"])
@pytest.mark.parametrize("slot", [None, 1, 2])
def test_new_login_advances_generation(switcher, monkeypatch, kind, slot):
    from claude_swap.refresh_authority import login_generation

    capture(switcher, monkeypatch)
    before = login_generation(switcher.backup_dir, EMAIL, "")
    replace(switcher, kind)
    first = login_generation(switcher.backup_dir, EMAIL, "")
    assert first == before + 1
    replace(switcher, kind, slot)
    assert login_generation(switcher.backup_dir, EMAIL, "") == first + 1


@pytest.mark.parametrize("kind", ["capture", "token"])
@pytest.mark.parametrize("slot", [None, 1])
def test_recapture_checks_busy_before_any_write(switcher, monkeypatch, kind, slot):
    capture(switcher, monkeypatch)
    replace(switcher, kind)
    old = switcher._read_account_credentials("1", EMAIL)
    def refuse(*args):
        raise SessionError("busy authority")
    monkeypatch.setattr(switcher, "_ensure_profile_idle_locked", refuse)
    with pytest.raises(SessionError, match="busy authority"):
        replace(switcher, kind, slot)
    assert switcher._read_account_credentials("1", EMAIL) == old


@pytest.mark.parametrize("kind", ["capture", "token"])
def test_in_place_recapture_holds_account_lock(switcher, monkeypatch, kind):
    capture(switcher, monkeypatch)
    replace(switcher, kind)
    original = switcher._write_account_credentials
    def write(*args):
        probe = FileLock(switcher.lock_file, timeout=0)
        acquired = probe.acquire()
        if acquired:
            probe.release()
        assert not acquired, "credential replacement must hold the account lock"
        return original(*args)
    monkeypatch.setattr(switcher, "_write_account_credentials", write)
    replace(switcher, kind)


def test_force_import_advances_but_skip_preserves_generation(switcher, temp_home):
    from claude_swap.refresh_authority import login_generation

    payload = {"version": 1, "accounts": [{
        "number": 1, "email": EMAIL, "credentials": {}, "config": {"oauthAccount": {}},
    }]}
    source = temp_home / "import.json"
    source.write_text(json.dumps(payload))
    import_accounts(switcher, str(source))
    first = login_generation(switcher.backup_dir, EMAIL, "")
    assert first == 1
    import_accounts(switcher, str(source))
    assert login_generation(switcher.backup_dir, EMAIL, "") == first
    import_accounts(switcher, str(source), force=True)
    assert login_generation(switcher.backup_dir, EMAIL, "") == first + 1


@pytest.mark.parametrize("kind", ["capture", "token", "import"])
@pytest.mark.parametrize("existing", [False, True])
def test_incoming_identity_refresh_right_blocks_replacement(
    switcher, monkeypatch, temp_home, kind, existing,
):
    from claude_swap.exceptions import LockError
    from claude_swap.refresh_authority import consume_lock, login_generation

    capture(switcher, monkeypatch)
    if existing:
        replace(switcher, "token")
    generation = login_generation(switcher.backup_dir, EMAIL, "")
    source = temp_home / "import.json"
    source.write_text(json.dumps({"version": 1, "accounts": [{
        "number": 1, "email": EMAIL, "credentials": {}, "config": {"oauthAccount": {}},
    }]}))
    with consume_lock(switcher.backup_dir, EMAIL):
        with pytest.raises((SessionError, LockError)):
            if kind == "import":
                import_accounts(switcher, str(source), force=True)
            else:
                replace(switcher, kind)
    assert login_generation(switcher.backup_dir, EMAIL, "") == generation


@pytest.mark.parametrize("kind", ["capture", "token"])
def test_in_place_recapture_rechecks_planned_identity(switcher, monkeypatch, kind):
    from claude_swap import profile_ownership
    from claude_swap.exceptions import ValidationError
    from contextlib import contextmanager

    capture(switcher, monkeypatch)
    replace(switcher, kind)
    old = switcher._read_account_credentials("1", EMAIL)
    original = profile_ownership.ownership_lock
    @contextmanager
    def raced_lock(*args, **kwargs):
        data = switcher._get_sequence_data()
        data["accounts"]["1"]["email"] = "other@example.com"
        switcher._write_json(switcher.sequence_file, data)
        with original(*args, **kwargs):
            yield
    monkeypatch.setattr(profile_ownership, "ownership_lock", raced_lock)
    with pytest.raises(ValidationError, match="Account changed"):
        replace(switcher, kind)
    assert switcher._read_account_credentials("1", EMAIL) == old

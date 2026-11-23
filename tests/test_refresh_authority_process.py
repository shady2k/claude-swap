"""F29 process barriers use synthetic credentials and never open a network socket."""
from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
import socket
from unittest.mock import patch

import pytest

from claude_swap import paths, oauth, refresh_authority
from claude_swap.exceptions import SessionError
from claude_swap.models import Platform
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.transfer import import_accounts


EMAIL = "process-a@example.com"


def _credential(label, *, fresh=False):
    return json.dumps({"claudeAiOauth": {
        "accessToken": "synthetic-access-" + label,
        "refreshToken": "synthetic-refresh-" + label,
        "expiresAt": 4102444800000 if fresh else 1000,
    }})


def _switcher():
    # The file-backed test store is shared across spawned processes, not Keychain.
    with patch.object(Platform, "detect", return_value=Platform.LINUX):
        return ClaudeAccountSwitcher()


def _no_network(*args, **kwargs):
    raise AssertionError("F29 process test attempted network access")


def _gate_worker(home, connection, snapshot, trace, unreadable=False):
    os.environ.update(HOME=home, USERPROFILE=home)
    for key in ("CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR", "XDG_DATA_HOME"):
        os.environ.pop(key, None)
    with patch.object(Path, "home", return_value=Path(home)), \
         patch.object(socket, "getaddrinfo", _no_network), \
         patch.object(socket.socket, "connect", _no_network):
        switcher = _switcher()
        snapshot = refresh_authority.CredentialSnapshot(*snapshot)
        if unreadable:
            switcher._read_account_credentials_ex = lambda *args, **kwargs: ("", True)

        def synthetic_post(credentials):
            connection.send("before-post")
            assert connection.recv() == "continue"
            # The trace is durable before exposing the second race window.
            with open(trace, "a", encoding="ascii") as stream:
                stream.write(oauth.credential_fingerprint(credentials) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            connection.send("before-cas")
            assert connection.recv() == "continue"
            return oauth.RefreshOutcome(_credential("successor", fresh=True), None)

        with patch("claude_swap.oauth.try_refresh_oauth_credentials", side_effect=synthetic_post):
            while True:
                command = connection.recv()
                if command == "stop":
                    return
                assert command == "consume"
                result = switcher.consume_backup_grant("1", EMAIL, snapshot, timeout=0)
                connection.send(("result", result.error, result.credentials is not None))


def _receive(connection):
    assert connection.poll(20), "refresh subprocess did not reach the expected barrier"
    return connection.recv()


@pytest.fixture
def process_store(temp_home):
    switcher = _switcher()
    switcher._setup_directories()
    accounts = {
        "1": {"email": EMAIL, "uuid": "synthetic-a", "organizationUuid": ""},
        "2": {"email": "process-b@example.com", "uuid": "synthetic-b", "organizationUuid": ""},
    }
    switcher._write_json(switcher.sequence_file, {
        "activeAccountNumber": 2, "sequence": [1, 2], "accounts": accounts,
    })
    for number, account in accounts.items():
        switcher._write_account_credentials(number, account["email"], _credential(number))
        switcher._write_account_config(number, account["email"], json.dumps({"oauthAccount": {
            "emailAddress": account["email"], "accountUuid": account["uuid"],
            "organizationUuid": "",
        }}))
    return switcher


@pytest.fixture
def gate_process(temp_home, process_store):
    context = multiprocessing.get_context("spawn")
    children = []

    def start(snapshot=None, *, unreadable=False):
        parent, child = context.Pipe()
        trace = temp_home / "synthetic-post.trace"
        if snapshot is None:
            snapshot = process_store.credential_snapshot("1", EMAIL)
        process = context.Process(target=_gate_worker, args=(str(temp_home), child, (str(snapshot), snapshot.identity, snapshot.login_gen), str(trace), unreadable))
        process.start()
        child.close()
        children.append((process, parent))
        return process, parent, trace

    yield start
    for process, connection in children:
        if process.is_alive():
            process.terminate()
            process.join(5)
        assert not process.is_alive(), "refresh subprocess survived cleanup"
        connection.close()


def _account_state(switcher):
    # Lock files and diagnostic logs are not account state.
    paths = [switcher.sequence_file]
    for directory in (switcher.credentials_dir, switcher.configs_dir, switcher.backup_dir / "sessions"):
        if directory.exists():
            paths.extend(path for path in directory.rglob("*") if path.is_file() and not path.name.startswith(".unclaimed-"))
    paths.extend(switcher.backup_dir.glob("launch/*/login.gen"))
    return {str(path.relative_to(switcher.backup_dir)): path.read_bytes() for path in paths}


def _mutate(switcher, operation, source):
    if operation == "move":
        switcher.move_account("1", "3")
    elif operation == "swap":
        switcher.swap_accounts("1", "2")
    elif operation == "switch":
        switcher.switch_to("1", json_output=True, force=True)
    elif operation == "remove":
        switcher.remove_account("1", assume_yes=True)
    else:
        import_accounts(switcher, str(source), force=True)


@pytest.mark.parametrize("window", ["before-post", "before-cas"])
@pytest.mark.parametrize("operation", ["move", "swap", "switch", "remove", "force-import"])
def test_mutations_refuse_in_both_refresh_windows(process_store, gate_process, temp_home, window, operation):
    source = temp_home / "synthetic-import.json"
    source.write_text(json.dumps({"version": 1, "accounts": [{
        "email": EMAIL, "number": 1, "organizationUuid": "",
        "credentials": json.loads(_credential("replacement")),
        "config": {"oauthAccount": {"emailAddress": EMAIL}},
    }]}))
    process, connection, trace = gate_process()
    connection.send("consume")
    assert _receive(connection) == "before-post"
    if window == "before-cas":
        connection.send("continue")
        assert _receive(connection) == "before-cas"
    before = _account_state(process_store)
    with pytest.raises(SessionError, match="refresh"):
        _mutate(process_store, operation, source)
    assert _account_state(process_store) == before
    assert not (temp_home / ".claude" / ".credentials.json").exists()
    if window == "before-post":
        assert not trace.exists()
        connection.send("continue")
        assert _receive(connection) == "before-cas"
    connection.send("continue")
    assert _receive(connection) == ("result", None, True)
    assert len(trace.read_text().splitlines()) == 1
    assert process_store._read_account_credentials("1", EMAIL) == _credential("successor", fresh=True)


def test_concurrent_process_gates_post_each_grant_once(process_store, gate_process):
    snapshot = process_store.credential_snapshot("1", EMAIL)
    first, first_connection, trace = gate_process(snapshot)
    second, second_connection, _ = gate_process(snapshot)
    first_connection.send("consume")
    assert _receive(first_connection) == "before-post"
    second_connection.send("consume")
    assert _receive(second_connection) == ("result", "consume-busy", False)
    first_connection.send("continue")
    assert _receive(first_connection) == "before-cas"
    second_connection.send("consume")
    assert _receive(second_connection) == ("result", "consume-busy", False)
    first_connection.send("continue")
    assert _receive(first_connection) == ("result", None, True)
    second_connection.send("consume")
    assert _receive(second_connection) == ("result", None, True)
    assert trace.read_text().splitlines() == [oauth.credential_fingerprint(snapshot)]
    assert refresh_authority.login_generation(process_store.backup_dir, EMAIL) == snapshot.login_gen


@pytest.mark.parametrize("reason", ["ownership-lost", "superseded", "unreadable"])
def test_process_revalidation_refuses_without_post(process_store, gate_process, reason):
    snapshot = process_store.credential_snapshot("1", EMAIL)
    if reason == "ownership-lost":
        data = process_store._get_sequence_data()
        data["accounts"]["1"]["organizationUuid"] = "synthetic-new-org"
        process_store._write_json(process_store.sequence_file, data)
    elif reason == "superseded":
        refresh_authority.advance_login_generation(process_store.backup_dir, EMAIL)
        process_store._store._write_account_credentials("1", EMAIL, _credential("replacement"))
    else:
        # An unreadable generation cannot establish authority to consume.
        path = process_store.backup_dir / "launch" / refresh_authority.identity_key(EMAIL) / "login.gen"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not-a-generation")
    before = _account_state(process_store)
    process, connection, trace = gate_process(snapshot)
    connection.send("consume")
    expected = "transient" if reason == "unreadable" else reason
    assert _receive(connection) == ("result", expected, False)
    assert not trace.exists()
    assert _account_state(process_store) == before


def test_killed_right_holder_releases_os_lock(process_store, gate_process):
    process, connection, trace = gate_process()
    connection.send("consume")
    assert _receive(connection) == "before-post"
    right = refresh_authority.consume_lock(process_store.backup_dir, EMAIL, timeout=0)
    assert not right.acquire(timeout=0)
    process.terminate()
    process.join(5)
    assert not process.is_alive()
    assert right.acquire(timeout=0)
    right.release()
    assert not trace.exists()
    assert process_store._read_account_credentials("1", EMAIL) == _credential("1")


def test_unreadable_backup_never_uses_caller_snapshot(process_store, gate_process):
    snapshot = process_store.credential_snapshot("1", EMAIL)
    before = _account_state(process_store)
    process, connection, trace = gate_process(snapshot, unreadable=True)
    connection.send("consume")
    assert _receive(connection) == ("result", "transient", False)
    assert not trace.exists()
    assert _account_state(process_store) == before


def test_late_response_cannot_overwrite_replacement_generation(process_store, gate_process):
    from claude_swap.locking import FileLock

    snapshot = process_store.credential_snapshot("1", EMAIL)
    process, connection, trace = gate_process(snapshot)
    connection.send("consume")
    assert _receive(connection) == "before-post"
    connection.send("continue")
    assert _receive(connection) == "before-cas"
    # Model an external replacement writer: public mutation APIs are tested
    # above and must refuse instead. This isolates the post-response CAS fence.
    with FileLock(process_store.lock_file):
        refresh_authority.advance_login_generation(process_store.backup_dir, EMAIL)
        process_store._store._write_account_credentials("1", EMAIL, _credential("replacement"))
    replacement = _account_state(process_store)
    connection.send("continue")
    result = _receive(connection)
    assert result[0] == "result"
    assert not result[2]
    assert _account_state(process_store) == replacement
    assert len(trace.read_text().splitlines()) == 1
    stashes = process_store.list_unclaimed_credentials()
    assert len(stashes) == 1
    metadata = next(iter(stashes.values()))
    assert metadata["reason"] == "consume-gate-superseded"
    assert metadata["identity"] == snapshot.identity
    assert metadata["loginGen"] == snapshot.login_gen
    assert metadata["consumedFp"] == oauth.credential_fingerprint(snapshot)

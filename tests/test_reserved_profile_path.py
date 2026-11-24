"""Reserved handoff path matching uses the ownership key on every boundary."""

import ntpath
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import profile_ownership as ownership, session
from claude_swap.exceptions import SessionError


@pytest.mark.parametrize("location", ["same", "different-case", "other", "missing"])
def test_reserved_handoff_path_key(tmp_path, monkeypatch, location):
    # Model Windows path-key semantics without changing the host platform or
    # pathlib: only the ownership module's OS adapter uses Windows normcase.
    monkeypatch.setattr(ownership, "os", SimpleNamespace(**{**vars(os), "path": ntpath}))
    profile = tmp_path / "Profile"
    backup = tmp_path / "backup"
    with ownership.ownership_lock(backup):
        record = ownership.reserve_locked(backup, "2", profile)
    assert record["profile"] == ntpath.normcase(str(profile.resolve()))
    events = []
    switcher = SimpleNamespace(
        backup_dir=backup, lock_file=backup / ".lock",
        resolve_account=lambda _: ("2", "synthetic@example.test", "id"),
        _get_current_account=lambda: None,
    )
    manager = SimpleNamespace(
        switcher=switcher, _launch_reservation=record,
        _admit_profile_launch=lambda _: events.append("admit"),
        _verify_profile_recipient=lambda _: events.append("recipient"),
    )
    monkeypatch.setattr(session.test_mode, "active", lambda: False)
    monkeypatch.setattr(session, "session_dir_for", lambda *args: profile)
    monkeypatch.setattr(ownership, "mark_running_locked", lambda *a, **k: events.append("running"))
    monkeypatch.setattr(ownership, "release_completed", lambda *a: events.append("release"))
    def owned_launch(callback, *, publish, release, abort):
        publish()
        callback()
        release()
        return 0
    monkeypatch.setattr(session.spawn, "owned_launch", owned_launch)
    binary = SimpleNamespace(handoff=lambda *a: events.append("handoff"))
    env = {} if location == "missing" else {"CLAUDE_CONFIG_DIR": str(
        profile if location == "same" else Path(str(profile).swapcase())
        if location == "different-case" else tmp_path / "other"
    )}
    if location in {"same", "different-case"}:
        with pytest.raises(SystemExit) as done:
            session.SessionManager._exec(manager, binary, ["-p", "synthetic"], env)
        assert done.value.code == 0
        assert events == ["admit", "recipient", "running", "handoff", "release"]
    else:
        with pytest.raises(SessionError, match="Reserved profile does not match handoff configuration"):
            session.SessionManager._exec(manager, binary, ["-p", "synthetic"], env)
        assert events == []

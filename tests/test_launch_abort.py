"""Pre-fork refusals use one bounded ownership cleanup attempt."""

import os
from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from claude_swap import profile_ownership as ownership, session, spawn, transparent
from claude_swap.exceptions import LockError, SessionError


@pytest.fixture
def launch_route(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    profile = tmp_path / "profile"
    # Cleanup semantics need a publishable identity, not native supervision.
    monkeypatch.setattr(ownership, "_process_identity", lambda pid: ownership._ProcessIdentity(
        "present", ownership._PosixStart(f"synthetic-{pid}"), "synthetic",
    ))
    monkeypatch.setattr(ownership, "scan_sessions", lambda _: ([], 0))
    with ownership.ownership_lock(root):
        record = ownership.reserve_locked(root, "1", profile)

    def handoff(*args, **kwargs):
        pytest.fail("pre-fork refusal must not hand off")

    binary = SimpleNamespace(handoff=handoff, path=tmp_path / "synthetic")
    manager = session.SessionManager(SimpleNamespace(backup_dir=root, _logger=None))
    manager._launch_reservation = record
    monkeypatch.setattr(manager, "_admit_profile_launch", lambda _: None)
    monkeypatch.setattr(session.test_mode, "active", lambda: False)
    monkeypatch.setattr(transparent, "settings_lock", lambda _: nullcontext())
    monkeypatch.setattr(transparent.launch_policy, "read", lambda _: {})
    monkeypatch.setattr(transparent.launch_policy, "consent", lambda _: None)
    monkeypatch.setattr(transparent, "check_transparent_history", lambda _: None)
    prepared = SimpleNamespace(reservation=record, real=binary, args=[], env={})
    monkeypatch.setattr(transparent, "_prepare_launch", lambda *a, **k: prepared)

    def launch(route):
        if route == "session":
            manager._exec(binary, [], {"CLAUDE_CONFIG_DIR": str(profile)})
        else:
            transparent._launch("synthetic", [], root)

    return root, record, manager, launch


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_prefork_abort_does_not_retry_ownership_contention(launch_route, monkeypatch, route):
    root, record, manager, launch = launch_route
    lock = ownership.ownership_lock(root)
    acquire = lock.acquire
    attempts = []

    def contended_once(timeout=None):
        attempts.append(timeout)
        return False if len(attempts) == 1 else acquire(timeout)

    monkeypatch.setattr(lock, "acquire", contended_once)
    monkeypatch.setattr(spawn, "_Supervision", nullcontext)

    def refuse():
        raise OSError("synthetic supervision refusal")

    monkeypatch.setattr(spawn, "require_supervision", refuse)
    with pytest.raises(LockError):
        launch(route)

    assert len(attempts) == 1
    assert ownership._record_path(root, record["launchId"]).exists()
    if route == "session":
        assert manager._launch_reservation is None


@pytest.mark.parametrize("route", ["session", "transparent"])
@pytest.mark.parametrize("published", [False, True])
def test_prefork_abort_releases_only_own_record(launch_route, monkeypatch, route, published):
    root, record, _, launch = launch_route
    with ownership.ownership_lock(root):
        peer = ownership.reserve_locked(root, "1", Path(record["profile"]))
        if published:
            ownership.mark_running_locked(root, record["launchId"], os.getpid())

    aborted = []

    def abort_before_fork(handoff, *, publish, release, abort):
        abort()
        aborted.append(record["launchId"])
        raise OSError("synthetic pre-fork refusal")

    monkeypatch.setattr(spawn, "owned_launch", abort_before_fork)
    with pytest.raises((OSError, SessionError), match="synthetic pre-fork refusal") as error:
        launch(route)
    refusal = error.value.__cause__ if route == "session" else error.value
    assert str(refusal) == "synthetic pre-fork refusal"
    assert aborted == [record["launchId"]]
    assert not ownership._record_path(root, record["launchId"]).exists()
    assert ownership._record_path(root, peer["launchId"]).exists()


def test_prefork_abort_real_lock_timeout_is_bounded(launch_route, monkeypatch):
    import threading
    from claude_swap.locking import FileLock

    root, record, _, _ = launch_route
    ready = threading.Event()
    done = threading.Event()
    errors = []

    def hold_lock():
        try:
            with FileLock(root / "profile-ownership" / "state.lock"):
                ready.set()
                if not done.wait(5):
                    raise AssertionError("cleanup did not finish within test budget")
        except BaseException as exc:
            errors.append(exc)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    try:
        assert ready.wait(5)
        lock = ownership.ownership_lock(root)
        monkeypatch.setattr(lock, "timeout", 0.02)
        with pytest.raises(LockError):
            ownership.release_aborted(root, record["launchId"])
        assert ownership._record_path(root, record["launchId"]).exists()
    finally:
        done.set()
        holder.join(5)
    assert not holder.is_alive()
    assert not errors

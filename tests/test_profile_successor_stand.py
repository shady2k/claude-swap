"""Deterministic legacy-session handoff using independent local processes."""

import json
import multiprocessing
import os
from contextlib import contextmanager


def _session_owner(profile, ready, transfer, successor_ready, stop, events, successor):
    from pathlib import Path
    from claude_swap.process_detection import process_start_ticks

    if successor:
        transfer.wait()
    sessions = Path(profile) / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    pid = os.getpid()
    (sessions / f"{pid}.json").write_text(json.dumps({
        "pid": pid, "procStart": process_start_ticks(pid),
        "sessionId": "successor" if successor else "original",
    }), encoding="utf-8")
    events.put("successor-published" if successor else "original-published")
    ready.set()
    if successor:
        stop.wait()
    else:
        transfer.wait()
        successor_ready.wait()
        events.put("original-exiting")


@contextmanager
def successor_transfer(profile):
    """Yield a transfer callback; it returns only after publication and exit.

    Event waits have test-failure deadlines, never success-by-timeout rules.
    The old record deliberately remains, as after an abrupt owner exit.
    """
    ctx = multiprocessing.get_context("spawn")
    original_ready, successor_ready = ctx.Event(), ctx.Event()
    transfer, stop = ctx.Event(), ctx.Event()
    events = ctx.Queue()
    successor_events = ctx.Queue()
    original = ctx.Process(target=_session_owner, args=(
        str(profile), original_ready, transfer, successor_ready, stop, events, False,
    ))
    successor = ctx.Process(target=_session_owner, args=(
        str(profile), successor_ready, transfer, successor_ready, stop, successor_events, True,
    ))
    original.start()
    successor.start()
    trace = []
    try:
        assert original_ready.wait(15), "original failed to publish"
        trace.append(events.get(timeout=15))

        def complete_transfer():
            trace.append("enumeration-complete")
            transfer.set()
            assert successor_ready.wait(15), "successor failed to publish"
            original.join(15)
            assert original.exitcode == 0, "original failed to exit"
            trace.append(successor_events.get(timeout=15))
            trace.append(events.get(timeout=15))
            trace.append("original-reaped-before-pid-read")

        yield original.pid, successor.pid, complete_transfer, trace
    finally:
        transfer.set()
        stop.set()
        for child in (original, successor):
            child.join(15)
            if child.is_alive():
                child.kill()
                child.join(15)
        events.close()
        successor_events.close()


import sys
import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Linux admission supervision")
@pytest.mark.parametrize("route,warm,disabled", [
    ("session", False, False),
    ("session", True, True),
    ("transparent", True, False),
])
def test_admission_refuses_successor_transfer(tmp_path, route, warm, disabled):
    from tests.profile_admission_stand import AdmissionStand

    with AdmissionStand(tmp_path, route, warm=warm, disabled=disabled) as stand:
        if disabled:
            assert json.loads((stand.backup / "transparent.json").read_text())["enabled"] is False
            assert not (stand.backup / "shim" / "claude").exists()
            assert (stand.profile / ".credentials.json").is_file()
        with successor_transfer(stand.profile) as (original, successor, transfer, trace):
            before = stand.snapshot()
            child = stand.launch("successor-race", scan_pid=original)
            child.event("pid-read-barrier")
            transfer()
            after_transfer = stand.snapshot()
            child.send("continue")
            child.event("pid-read-resumed")
            trace.append("pid-read-resumed")
            assert child.finish() == 4, (child.errors, trace)
            assert child.counts() == {"launch": 0, "post": 0, "probe": 0}
            assert stand.snapshot() == after_transfer, trace
            assert {key: value for key, value in after_transfer.items() if key in before} == before
            assert trace == [
                "original-published", "enumeration-complete", "successor-published",
                "original-exiting", "original-reaped-before-pid-read", "pid-read-resumed",
            ]

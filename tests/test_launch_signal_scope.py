"""Signal scope acceptance through both admitted profile launch entrances."""
import json
import os
import select
import signal
import sys

import pytest

from tests.profile_admission_stand import AdmissionStand

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision stand")


def assert_relaunch(stand, route):
    again = stand.launch("relaunch")
    if route == "session":
        again.event("probe")
    again.event("launch")
    again.event("live")
    again.send("exit")
    assert again.finish() == 0
    assert stand.free()


@pytest.mark.parametrize("route", ["session", "transparent"])
@pytest.mark.parametrize("phase", ["publication", "before-fork", "live", "after-reap", "release"])
@pytest.mark.parametrize("signum", [getattr(signal, name) for name in
    ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT") if hasattr(signal, name)])
def test_signal_scope_keeps_ownership_until_completion(tmp_path, route, phase, signum):
    with AdmissionStand(tmp_path, route) as stand:
        launch = stand.launch("signal", mode="signal-" + phase)
        if route == "session":
            launch.event("probe")
        if phase in ("publication", "before-fork"):
            launch.event(phase)
            launch.process.send_signal(signum)
            # TERM/HUP may reach the new child before its exec installs
            # synthetic handlers. Either a signaled child or code 7 is valid;
            # the supervisor itself must finish normally and release ownership.
            # Publication barrier holds the real state lock; inspecting via
            # a second locked reader here would deadlock the controller.
            assert any(json.loads(path.read_text()).get("state") == "running"
                       for path in (stand.backup / 'profile-ownership').rglob('*.json'))
            launch.send("continue")
            if signum in (signal.SIGTERM, signal.SIGHUP):
                launch.send("exit")
                launch.process.communicate(timeout=15)
                assert launch.process.returncode in (7, 128 + signum)
                assert stand.free()
                assert launch.counts()["post"] == 0
                assert_relaunch(stand, route)
                return
            launch.event("launch")
            launch.event("live")
        else:
            launch.event("launch")
            # The reaped leader and detached child can report in either order.
            expected = {"live", "after-reap"} if phase == "after-reap" else {"live"}
            while expected:
                while b"\n" not in launch.pending:
                    assert select.select([launch.reader], [], [], 15)[0]
                    launch.pending += os.read(launch.reader, 4096)
                line, launch.pending = launch.pending.split(b"\n", 1)
                expected.remove(line.decode())
            if phase == "release":
                launch.send("exit")
                launch.event("release-wait")
                from claude_swap import profile_ownership
                assert not stand.free()
                assert stand.switch() == 4
                with profile_ownership.ownership_lock(stand.backup):
                    launch.send("release")
                    launch.event("release-attempt")
                    launch.process.send_signal(signum)
                    assert launch.process.poll() is None
                assert launch.finish() == 7
                assert stand.free()
                assert_relaunch(stand, route)
                return
            launch.process.send_signal(signum)
            if phase == "after-reap":
                launch.send_scope("continue")
        assert not stand.free(), "ownership disappeared before completion/release"
        assert stand.switch() == 4
        launch.send("exit")
        assert launch.finish() == 7, "leader result was not preserved through cleanup"
        assert stand.free()
        assert launch.counts()["launch"] == 1
        assert launch.counts()["post"] == 0
        assert_relaunch(stand, route)


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_generation_change_at_publication_refuses_without_reservation_leak(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        launch = stand.launch("generation", mode="generation-publication")
        assert launch.finish() in (3, 4)
        assert launch.counts()["launch"] == 0
        assert launch.counts()["post"] == 0
        assert stand.free()


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_capability_refusal_before_publication_releases_reservation(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        launch = stand.launch("capability", mode="capability-refusal")
        assert launch.finish() in (3, 4)
        assert launch.counts()["launch"] == 0
        assert launch.counts()["post"] == 0
        assert stand.free()


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_supervisor_death_never_claims_tree_completion(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        launch = stand.launch("dead-supervisor")
        if route == "session":
            launch.event("probe")
        launch.event("launch")
        launch.event("live")
        descendant = int(launch.log.with_suffix('.events.pid').read_text())
        pidfd = os.pidfd_open(descendant)
        launch.process.kill()
        assert launch.process.wait(timeout=5) == -signal.SIGKILL
        signal.pidfd_send_signal(pidfd, 0)
        assert not select.select([pidfd], [], [], 0)[0]
        assert not stand.free()
        assert stand.switch() == 4
        launch.send("exit")
        launch.process.communicate(timeout=15)
        assert select.select([pidfd], [], [], 5)[0], "finite descendant did not exit"
        os.close(pidfd)
        assert not stand.free(), "dead supervisor cannot prove even later tree completion"


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_unknown_wait_retains_running_record_with_detached_descendant(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        launch = stand.launch("unknown-wait", mode="unknown-wait")
        if route == "session":
            launch.event("probe")
        launch.event("launch")
        launch.event("live")
        descendant = int(launch.log.with_suffix('.events.pid').read_text())
        pidfd = os.pidfd_open(descendant)
        assert launch.process.wait(timeout=5) == 4
        signal.pidfd_send_signal(pidfd, 0)
        assert not select.select([pidfd], [], [], 0)[0]
        assert not stand.free()
        assert stand.switch() == 4
        launch.send("exit")
        launch.process.communicate(timeout=15)
        assert select.select([pidfd], [], [], 5)[0]
        os.close(pidfd)
        assert not stand.free()

"""The after-reap stand barrier observes a recorded leader result."""
import os
import select
import signal
import sys

import pytest

from tests.profile_admission_stand import AdmissionStand

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision stand")


def test_after_reap_barrier_delivers_int_to_detached_descendant(tmp_path):
    with AdmissionStand(tmp_path, "session") as stand:
        launch = stand.launch("after-reap-int", mode="signal-after-reap")
        launch.event("probe")
        launch.event("launch")
        expected = {"live", "after-reap"}
        while expected:
            while b"\n" not in launch.pending:
                assert select.select([launch.reader], [], [], 5)[0], launch.log.read_text()
                data = os.read(launch.reader, 4096)
                assert data, launch.log.read_text()
                launch.pending += data
            line, launch.pending = launch.pending.split(b"\n", 1)
            expected.remove(line.decode())
        launch.process.send_signal(signal.SIGINT)
        # Keep the supervisor at the barrier until the detached descendant
        # acknowledges INT. A pause inside the first waitpid returns too early:
        # _Supervision.result is still None and INT is suppressed there.
        try:
            assert select.select([launch.reader], [], [], 5)[0], (
                "after-reap barrier preceded the recorded leader result", launch.log.read_text()
            )
            launch.event("descendant-int")
            assert not stand.free()
            assert stand.switch() == 4
        finally:
            launch.send_scope("continue")
            launch.send("exit")
        assert launch.finish() == 7
        assert stand.free()
        assert launch.counts()["post"] == 0

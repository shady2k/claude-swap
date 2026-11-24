"""Publication refusal must not swallow pending termination signals."""
import signal
import sys

import pytest

from tests.profile_admission_stand import AdmissionStand

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision stand")


@pytest.mark.parametrize("route", ["session", "transparent"])
@pytest.mark.parametrize("signum", ["SIGTERM", "SIGHUP"])
def test_publication_refusal_preserves_pending_termination(tmp_path, route, signum):
    signum = getattr(signal, signum)
    with AdmissionStand(tmp_path, route) as stand:
        launch = stand.launch("refusal", mode="signal-publication-refusal")
        if route == "session":
            launch.event("probe")
        launch.event("publication-refusal")
        launch.process.send_signal(signum)
        launch.send_scope("continue")
        try:
            launch.event("abort-complete")
            launch.process.communicate(timeout=10)
            assert launch.process.returncode == -signum
            assert launch.counts()["launch"] == 0
            assert launch.counts()["post"] == 0
            assert launch.log.read_text().splitlines().count("publication-refusal") == 1
            assert stand.free()
        finally:
            if launch.process.poll() is None:
                launch.process.kill()
                launch.process.communicate(timeout=10)

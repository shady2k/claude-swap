"""Real process admission stand; synthetic local auth, no endpoint traffic."""
import sys
import pytest
from tests.profile_admission_stand import AdmissionStand

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision stand")

@pytest.mark.parametrize("route", ["session", "transparent"])
def test_two_launches_exclude_reuse_and_release_after_tree(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        first = stand.launch("winner", barrier=True)
        first.event("reserved")
        before = stand.snapshot()
        loser = stand.launch("loser")
        assert loser.finish() == 4
        assert loser.counts() == {"launch": 0, "post": 0, "probe": 0}
        assert stand.snapshot() == before
        first.send("continue")
        if route == "session":
            first.event("probe")
        first.event("launch")
        first.event("live")
        assert stand.switch() == 4
        first.send("exit")
        assert first.finish() == 0
        assert stand.free()
        assert first.counts()["launch"] == 1


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_recipient_identity_change_before_reuse_refuses(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        first = stand.launch("recipient-race", barrier=True)
        first.event("reserved")
        before = stand.snapshot()
        assert stand.launch("recipient-edit", mode="recipient").finish() == 0
        first.send("continue")
        first.send("exit")
        assert first.finish() == 4
        assert first.counts()["launch"] == 0
        assert first.counts()["post"] == 0
        assert stand.snapshot() == before
        assert stand.free()


def test_foreign_reservation_prevents_invalid_profile_deletion(tmp_path):
    with AdmissionStand(tmp_path, "session", warm=True) as stand:
        first = stand.launch("holder", barrier=True)
        first.event("reserved")
        before = stand.snapshot()
        invalid = stand.launch("invalid", mode="invalid")
        assert invalid.finish() == 4
        assert invalid.counts() == {"launch": 0, "post": 0, "probe": 0}
        assert stand.snapshot() == before
        first.send("continue")
        first.event("probe")
        first.event("launch")
        first.event("live")
        first.send("exit")
        assert first.finish() == 0


def test_default_identity_change_before_reuse_refuses(tmp_path):
    with AdmissionStand(tmp_path, "session") as stand:
        first = stand.launch("identity-race", barrier=True)
        first.event("reserved")
        before = stand.snapshot()
        assert stand.launch("identity-edit", mode="identity").finish() == 0
        first.send("continue")
        assert first.finish() == 4
        assert first.counts() == {"launch": 0, "post": 0, "probe": 0}
        assert stand.snapshot() == before
        assert stand.free()

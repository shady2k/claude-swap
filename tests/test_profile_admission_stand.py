"""Real process admission stand; synthetic local auth, no endpoint traffic."""
import stat
import sys
import pytest
from tests.profile_admission_stand import AdmissionStand

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux supervision stand")

@pytest.mark.parametrize("route", ["session", "transparent"])
def test_two_launches_share_valid_profile_and_release_after_tree(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        first = stand.launch("first", barrier=True)
        first.event("reserved")
        second = stand.launch("second")
        if route == "session":
            second.event("probe")
        second.event("launch")
        second.event("live")
        first.send("continue")
        if route == "session":
            first.event("probe")
        first.event("launch")
        first.event("live")
        assert stand.switch() == 4
        first.send("exit")
        assert first.finish() == 0
        assert not stand.free()
        second.send("exit")
        assert second.finish() == 0
        assert stand.free()
        assert first.counts()["launch"] == second.counts()["launch"] == 1
        assert stand.switch() == 0


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


def test_invalid_profile_deletion_invalidates_foreign_reservation(tmp_path):
    with AdmissionStand(tmp_path, "session", warm=True) as stand:
        first = stand.launch("holder", barrier=True)
        first.event("reserved")
        invalid = stand.launch("invalid", mode="invalid")
        assert invalid.finish() == 4
        assert invalid.counts()["probe"] > 0
        assert not stand.profile.exists()
        first.send("continue")
        first.send("exit")
        assert first.finish() == 4
        assert first.counts()["launch"] == 0
        assert stand.free()


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


@pytest.mark.parametrize("barrier", [False, True])
def test_transparent_excludes_default_login_at_reservation_and_publication(tmp_path, barrier):
    with AdmissionStand(tmp_path, "transparent") as stand:
        if not barrier:
            assert stand.launch("identity-edit", mode="identity").finish() == 0
        launch = stand.launch("default-login", barrier=barrier)
        if barrier:
            launch.event("reserved")
            assert stand.launch("identity-edit", mode="identity").finish() == 0
            launch.send("continue")
        assert launch.finish() in (3, 4)
        assert launch.counts()["launch"] == 0
        assert stand.free()


@pytest.mark.parametrize("failure", ["journal-error", "journal-lock-error"])
def test_journal_failure_before_fork_releases_reservation(tmp_path, failure):
    with AdmissionStand(tmp_path, "transparent") as stand:
        launch = stand.launch(failure, mode=failure)
        assert launch.finish() == 4
        assert launch.counts()["launch"] == 0
        assert stand.free()


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_completed_release_retries_contention_and_preserves_exit(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        launch = stand.launch("completed", mode="release-contention")
        if route == "session":
            launch.event("probe")
        launch.event("launch")
        launch.event("live")
        launch.send("exit")
        launch.event("release-wait")
        assert not stand.free()
        launch.send("release")
        assert launch.finish() == 7
        assert stand.free()


def _assert_f36_credentials_unchanged(before, after, route):
    expected = before.copy()
    lock = "credentials/.unclaimed-manifest.lock"
    if route == "session" and after.keys() - before.keys() == {lock}:
        _, mode, content = after[lock]
        assert stat.S_ISREG(mode)
        assert content == b""
        expected[lock] = after[lock]
    assert after == expected


@pytest.mark.parametrize("route", ["session", "transparent"])
def test_f36_setup_token_same_default_identity_is_admitted(tmp_path, route):
    with AdmissionStand(tmp_path, route) as stand:
        assert stand.launch("setup-identity", mode="setup-identity").finish() == 0
        before = {name: value for name, value in stand.snapshot().items() if name.startswith("credentials/")}
        for index in range(2):
            launch = stand.launch(f"setup-launch-{index}")
            if route == "session":
                launch.event("probe")
            launch.event("launch")
            launch.event("live")
            launch.send("exit")
            assert launch.finish() == 0
            assert launch.counts()["post"] == 0
            after = {name: value for name, value in stand.snapshot().items() if name.startswith("credentials/")}
            if index == 0:
                _assert_f36_credentials_unchanged(before, after, route)
            else:
                assert after == before
            assert stand.free()
            before = after


@pytest.mark.parametrize("change", ["extra-file", "slot-byte", "nonempty-lock", "transparent-lock"])
def test_f36_credential_comparison_rejects_changes(change):
    slot = "credentials/2-target@example.test.json"
    regular = stat.S_IFREG | 0o600
    before = {slot: (101, regular, b"synthetic-slot")}
    after = before.copy()
    route = "session"
    if change == "extra-file":
        after["credentials/unexpected"] = (102, regular, b"")
    elif change == "slot-byte":
        after[slot] = (101, regular, b"synthetic-sloT")
    else:
        content = b"not empty" if change == "nonempty-lock" else b""
        after["credentials/.unclaimed-manifest.lock"] = (102, regular, content)
        if change == "transparent-lock":
            route = "transparent"
    with pytest.raises(AssertionError):
        _assert_f36_credentials_unchanged(before, after, route)

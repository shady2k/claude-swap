"""The required stand cannot go green with a missing control."""

from types import SimpleNamespace

import pytest

from tests.required_stand import _REQUIRED_CONTROLS, _RequiredStand


@pytest.mark.parametrize("renamed", [False, True], ids=["removed", "renamed"])
def test_required_stand_fails_if_a_control_disappears(renamed, capsys):
    missing = "tests/test_stand_linux.py::test_dns_sink_detects_attempt_from_child_with_no_answer"
    nodeids = _REQUIRED_CONTROLS - {missing}
    if renamed:
        nodeids.add(f"{missing}_renamed")
    session = SimpleNamespace(
        items=[SimpleNamespace(nodeid=nodeid) for nodeid in nodeids],
        exitstatus=pytest.ExitCode.OK,
    )
    gate = _RequiredStand()
    for item in session.items:
        gate.pytest_runtest_logreport(
            SimpleNamespace(nodeid=item.nodeid, when="call", skipped=False, passed=True)
        )

    gate.pytest_sessionfinish(session, session.exitstatus)

    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
    assert missing in capsys.readouterr().err

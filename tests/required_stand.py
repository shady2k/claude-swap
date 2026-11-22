"""Fail closed when CI requires the opt-in Linux stand."""

import os
import sys

import pytest

from tests.stand_linux import OPT_IN


_REQUIRED_MODULES = {
    "tests/test_stand_linux.py",
    "tests/test_stand_mock_linux.py",
}


def pytest_configure(config):
    if (
        sys.platform != "linux"
        or os.environ.get(OPT_IN) != "1"
        or os.environ.get("CSWAP_TEST_STAND_REQUIRED") != "1"
    ):
        raise pytest.UsageError(
            f"required stand needs Linux, {OPT_IN}=1 and CSWAP_TEST_STAND_REQUIRED=1"
        )
    config.pluginmanager.register(_RequiredStand())


class _RequiredStand:
    def __init__(self):
        self.skipped = set()
        self.deselected = set()
        self.passed = set()

    def pytest_deselected(self, items):
        self.deselected.update(item.nodeid for item in items)

    def pytest_collectreport(self, report):
        if report.skipped:
            self.skipped.add(report.nodeid)

    def pytest_runtest_logreport(self, report):
        if report.skipped:
            self.skipped.add(report.nodeid)
        if report.when == "call" and report.passed:
            self.passed.add(report.nodeid)

    def pytest_sessionfinish(self, session, exitstatus):
        missing = _REQUIRED_MODULES - {nodeid.split("::", 1)[0] for nodeid in self.passed}
        incomplete = {item.nodeid for item in session.items} - self.passed
        issues = [
            f"{label}: {', '.join(sorted(nodeids))}"
            for label, nodeids in (
                ("no passing tests in required modules", missing),
                ("collected tests did not pass", incomplete),
                ("skips", self.skipped),
                ("deselections", self.deselected),
            )
            if nodeids
        ]
        if issues:
            print("Required Linux stand failed:\n  " + "\n  ".join(issues), file=sys.stderr)
            if exitstatus == pytest.ExitCode.OK:
                session.exitstatus = pytest.ExitCode.TESTS_FAILED

"""Fail closed when CI requires the opt-in Linux stand."""

import os
import sys

import pytest

from tests.stand_linux import OPT_IN


# Pin exact node IDs so another passing test in the same module cannot
# stand in for a missing control.
_REQUIRED_CONTROLS = {
    "tests/test_stand_linux.py::test_detector_reports_failed_connect_sendto_and_sendmsg",
    "tests/test_stand_linux.py::test_dns_sink_detects_attempt_from_child_with_no_answer",
    "tests/test_stand_linux.py::test_runner_fails_closed_without_isolation",
    "tests/test_stand_mock_linux.py::test_cli_rejects_test_endpoint_before_network[malformed_endpoint]",
    "tests/test_stand_mock_linux.py::test_cli_rejects_test_endpoint_before_network[missing_endpoint]",
    "tests/test_stand_mock_linux.py::test_mock_control_direct_tls_is_detected_and_denied",
    "tests/test_stand_mock_linux.py::test_mock_control_hosts_mapping_stops_before_network",
    *(f"tests/test_stand_shim_linux.py::test_path_shim_refuses_before_launch[{name}]" for name in (
        "missing_endpoint", "loopback_endpoint", "public_endpoint", "public_base", "public_proxy",
        "unlisted_claude", "project_env", "user_env", "client_settings", "auth", "update", "unknown", "bypass",
    )),
    "tests/test_stand_shim_linux.py::test_path_shim_hosts_control_stops_before_launch",
    "tests/test_stand_shim_linux.py::test_path_shim_route[shim_positive]",
    "tests/test_stand_shim_linux.py::test_path_shim_route[shim_direct]",
    "tests/test_stand_shim_linux.py::test_path_shim_trace_detects_external_attempt",
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
        missing = _REQUIRED_CONTROLS - self.passed
        incomplete = {item.nodeid for item in session.items} - self.passed
        issues = [
            f"{label}: {', '.join(sorted(nodeids))}"
            for label, nodeids in (
                ("required controls did not pass", missing),
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

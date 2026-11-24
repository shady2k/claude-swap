"""Exercise the isolated trace gate, including attempts that never reach a peer."""

import os
import sys

import pytest

from tests import stand_linux
from tests.stand_linux import DNS_SINK, OPT_IN, LinuxStand, StandError


if sys.platform != "linux" or os.environ.get(OPT_IN) != "1":
    pytest.skip(f"network stand: set {OPT_IN}=1 on Linux", allow_module_level=True)

from tests.stand_linux_control import FAILED_TARGET, LOCAL


def test_normal_trace_contains_only_permitted_loopback_traffic(tmp_path):
    result = LinuxStand(tmp_path).run(
        "stand_linux_control", "normal", allowed={LOCAL},
        listeners={("stand_linux_control", "normal"): {LOCAL}},
    )
    assert result.returncode == 0, result.stderr
    result.require_clean()
    assert any(a.syscall == "connect" and a.target == LOCAL for a in result.attempts)
    assert not any(a.dns for a in result.attempts)


def test_dns_sink_detects_attempt_from_child_with_no_answer(tmp_path):
    result = LinuxStand(tmp_path).run("stand_linux_control", "dns")
    assert result.returncode == 0, result.stderr
    dns = [a for a in result.attempts if a.dns]
    assert any(a.target == DNS_SINK and a.syscall in {"sendto", "sendmsg", "sendmmsg"} for a in dns)
    assert all(not a.permitted and a.role == ("stand_linux_control", "query") for a in dns)
    with pytest.raises(AssertionError, match="DNS"):
        result.require_clean()


def test_runner_fails_closed_without_isolation(tmp_path, monkeypatch):
    false = stand_linux._tool("false")
    monkeypatch.setattr(stand_linux, "_tool", lambda name: false)
    with pytest.raises(StandError, match="stand setup did not complete"):
        LinuxStand(tmp_path).run("stand_linux_control", "normal")


def test_audit_rejects_missing_trace(tmp_path):
    with pytest.raises(StandError, match="strace did not produce any trace files"):
        stand_linux._audit(tmp_path, ("stand_linux_control", "normal"), {}, {})


def test_detector_reports_failed_connect_sendto_and_sendmsg(tmp_path):
    result = LinuxStand(tmp_path).run("stand_linux_control", "failed")
    assert result.returncode == 0, result.stderr
    rejected = [a for a in result.attempts if a.target == FAILED_TARGET]
    assert {a.syscall for a in rejected} == {"connect", "sendto", "sendmsg"}
    assert all(not a.permitted and "ENETUNREACH" in a.result for a in rejected)
    with pytest.raises(AssertionError, match="unapproved destination"):
        result.require_clean()

"""Opt-in Linux controls for HTTPS mock routing."""

import json
import os
import sys

import pytest

from tests import stand_mock as mock

if sys.platform != "linux":
    pytest.skip("network stand is Linux only", allow_module_level=True)


@pytest.fixture
def linux_stand(tmp_path):
    if os.environ.get("CSWAP_TEST_STAND") != "1":
        pytest.skip("requires CSWAP_TEST_STAND=1")
    from tests.stand_linux import LinuxStand

    mock.preflight_hosts()
    return LinuxStand(tmp_path)


def _run(stand, scenario, *, server_allowed, client_allowed):
    result = stand.run(
        "stand_mock", scenario, allowed=set(),
        children={
            ("stand_mock", "serve"): server_allowed,
            ("stand_mock", "client", scenario): client_allowed,
        },
        listeners={("stand_mock", "serve"): {mock.PROXY, mock.ORIGIN}},
    )
    result.require_clean()
    assert result.stdout, result.stderr
    return result, json.loads(result.stdout)


def test_mock_control_hosts_mapping_stops_before_network(linux_stand):
    result = linux_stand.run(
        "stand_mock", "positive", allowed=set(),
        hosts_text=f"127.0.0.1 localhost {mock.HOST}\n",
    )
    result.require_clean()
    assert result.attempts == ()
    assert result.returncode == 4
    assert result.stdout == ""
    assert "hosts file contains a mapping" in result.stderr


def test_mock_positive_https_through_connect(linux_stand):
    result, journal = _run(
        linux_stand, "positive", server_allowed={mock.ORIGIN}, client_allowed={mock.PROXY},
    )
    assert result.returncode == 0, result.stderr
    connects = [attempt for attempt in result.attempts if attempt.syscall == "connect"]
    assert {(attempt.role, attempt.target) for attempt in connects} == {
        (("stand_mock", "client", "positive"), mock.PROXY),
        (("stand_mock", "serve"), mock.ORIGIN),
    }
    assert len(connects) == len({attempt.pid for attempt in connects}) == 2
    assert journal == {
        "records": {
            "connect": [mock.AUTHORITY],
            "https": [["GET", mock.PROBE]],
            "direct": 0,
            "denied_connect": 0,
        },
        "response": {"stand": "synthetic"},
    }


def test_mock_control_direct_tls_is_detected_and_denied(linux_stand):
    # Allow the loopback connection at the syscall layer: only the mock can
    # tell the difference between this connection and the proxy's connection.
    result, journal = _run(
        linux_stand, "direct", server_allowed=set(), client_allowed={mock.ORIGIN},
    )
    assert result.returncode == 1
    connects = [attempt for attempt in result.attempts if attempt.syscall == "connect"]
    assert [(attempt.role, attempt.target) for attempt in connects] == [
        (("stand_mock", "client", "direct"), mock.ORIGIN),
    ]
    assert journal == {
        "records": {"connect": [], "https": [], "direct": 1, "denied_connect": 0},
        "response": None,
    }


def test_mock_proxy_rejects_unlisted_connect_authority(linux_stand):
    result, journal = _run(
        linux_stand, "denied_connect", server_allowed=set(), client_allowed={mock.PROXY},
    )
    assert result.returncode == 1
    assert journal == {
        "records": {"connect": [], "https": [], "direct": 0, "denied_connect": 1},
        "response": None,
    }

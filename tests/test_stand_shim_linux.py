"""Run the ordinary ``claude`` command under the required Linux stand."""

import json
import os
import sys

import pytest

from claude_swap import test_mode
from tests import stand_mock as mock
from tests.stand_linux import LinuxStand, OPT_IN, SHIM_REFUSALS
from tests.stand_shim import ESCAPE

if sys.platform != "linux" or os.environ.get(OPT_IN) != "1":
    pytest.skip(f"network stand: set {OPT_IN}=1 on Linux", allow_module_level=True)


@pytest.fixture
def stand(tmp_path):
    mock.preflight_hosts()
    return LinuxStand(tmp_path)


_ERRORS = {
    "missing_endpoint": test_mode.ENDPOINT,
    "loopback_endpoint": test_mode.ENDPOINT,
    "public_endpoint": test_mode.ENDPOINT,
    "public_base": test_mode.CLAUDE_BASE,
    "public_proxy": test_mode.PROXY,
    "unlisted_claude": test_mode.ALLOW,
    "project_env": f"project/.claude/settings.json: env.{test_mode.CLAUDE_BASE}",
    "user_env": f"home/.claude/settings.json: env.{test_mode.CLAUDE_BASE}",
    "client_settings": "--settings",
    "auth": "'auth'",
    "update": "'update'",
    "unknown": "'future-subcommand'",
    "bypass": "CLAUDE_SWAP_BYPASS",
}


@pytest.mark.parametrize("scenario", SHIM_REFUSALS)
def test_path_shim_refuses_before_launch(stand, scenario):
    result = stand.run("stand_shim", scenario)
    result.require_clean()
    assert result.shim_execs == ("path-shim", "shim-python")
    assert result.attempts == ()
    assert result.returncode == 4, result.stderr
    assert result.stdout == ""
    assert result.stderr.startswith("claude-swap:")
    assert _ERRORS[scenario] in result.stderr


def test_path_shim_hosts_control_stops_before_launch(stand):
    result = stand.run(
        "stand_shim", "escape", hosts_text=f"127.0.0.1 localhost {mock.HOST}\n",
    )
    result.require_clean()
    assert not result.shim_execs and not result.attempts
    assert result.returncode == 4 and not result.stdout
    assert "hosts file contains a mapping" in result.stderr


@pytest.mark.parametrize("scenario", ["shim_positive", "shim_direct"])
def test_path_shim_route(stand, scenario):
    direct = scenario == "shim_direct"
    client_destination = mock.ORIGIN if direct else mock.PROXY
    result = stand.run(
        "stand_mock", scenario,
        children={
            ("stand_mock", "serve"): set() if direct else {mock.ORIGIN},
            ("shim-claude",): {client_destination},
        },
        listeners={("stand_mock", "serve"): {mock.PROXY, mock.ORIGIN}},
    )
    result.require_clean()
    assert result.shim_execs == ("path-shim", "shim-python", "shim-claude")
    assert result.returncode == int(direct), result.stderr
    connects = [(a.role, a.target) for a in result.attempts if a.syscall == "connect"]
    assert connects.count((("shim-claude",), client_destination)) == 1
    assert len(connects) == (1 if direct else 2)
    assert json.loads(result.stdout) == {
        "records": {
            "connect": [] if direct else [mock.AUTHORITY],
            "https": [] if direct else [["GET", mock.PROBE]],
            "direct": int(direct),
            "denied_connect": 0,
        },
        "response": None if direct else {"stand": "synthetic"},
    }


def test_path_shim_trace_detects_external_attempt(stand):
    result = stand.run("stand_shim", "escape")
    assert result.shim_execs == ("path-shim", "shim-python", "shim-claude")
    assert result.returncode == 0, result.stderr
    attempt, = result.attempts
    assert attempt.role == ("shim-claude",) and attempt.target == ESCAPE
    assert not attempt.permitted and "ENETUNREACH" in attempt.result
    with pytest.raises(AssertionError, match="unapproved destination"):
        result.require_clean()

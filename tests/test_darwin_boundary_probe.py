"""Portable controls for the experimental probe, not Darwin OS evidence."""

import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests import darwin_boundary_probe as probe


def test_probe_refuses_other_platform_before_launch(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.sys, "platform", "linux")
    launch = Mock(side_effect=AssertionError("must not launch"))
    monkeypatch.setattr(probe.subprocess, "run", launch)
    with pytest.raises(SystemExit, match="Darwin required"):
        probe.run(tmp_path / "protocol.json")
    launch.assert_not_called()
    assert not list(tmp_path.iterdir())


def test_job_configuration_is_single_run_synthetic_and_isolated(tmp_path):
    config = probe.configuration("unique-test-label", tmp_path, True)
    assert config["KeepAlive"] is False
    assert config["LaunchOnlyOnce"] is True
    assert config["StandardOutPath"] == str(tmp_path / "stdout.log")
    assert config["StandardErrorPath"] == str(tmp_path / "stderr.log")
    assert config["AbandonProcessGroup"] is False
    assert config["EnvironmentVariables"] == {
        "HOME": str(tmp_path / "home"), "PATH": "/usr/bin:/bin"}
    argv = config["ProgramArguments"]
    assert argv == [sys.executable, str(Path(probe.__file__).resolve()),
                    "--target", str(tmp_path), "1"]


@pytest.fixture
def job_root():
    if sys.platform == "win32":
        pytest.skip("launchd job controls require POSIX AF_UNIX paths")
    with tempfile.TemporaryDirectory(prefix="cswap-test-", dir="/tmp") as directory:
        yield Path(directory)


def test_failed_bootstrap_never_opens_target_barrier(job_root, monkeypatch):
    job = probe.Job(job_root, True)
    calls = []
    def reject(*args):
        calls.append(args)
        return Mock(returncode=5, stdout="", stderr="synthetic failure")
    monkeypatch.setattr(probe, "launchctl", reject)
    try:
        with pytest.raises(RuntimeError, match="bootstrap failed"):
            job.start()
        assert not job.submitted
    finally:
        job.close()
    assert calls == [("bootstrap", job.domain, str(job.plist))]


def test_cleanup_only_addresses_this_service(job_root, monkeypatch):
    first = probe.Job(job_root, True)
    second = probe.Job(job_root, False)
    assert first.label != second.label
    calls = []
    monkeypatch.setattr(probe, "launchctl", lambda *args: (
        calls.append(args) or Mock(returncode=0, stdout="", stderr="")))
    first.submitted = True
    first.close()
    second.close()
    assert calls == [("bootout", first.service)]


def test_barrier_timeout_records_service_and_target_logs(job_root, monkeypatch):
    job = probe.Job(job_root, True)
    job.listener.close()
    job.listener = Mock()
    job.listener.accept.side_effect = TimeoutError("synthetic timeout")
    calls = []
    def command(*args):
        calls.append(args)
        return Mock(returncode=0, stdout="state = exited; last exit code = 1", stderr="")
    monkeypatch.setattr(probe, "launchctl", command)
    (job.directory / "stderr.log").write_text("synthetic startup error")
    try:
        with pytest.raises(TimeoutError, match="synthetic timeout"):
            job.start()
        diagnostic = job.diagnostics()
        assert diagnostic["logs"]["stderr.log"] == "synthetic startup error"
        assert diagnostic["events"][1]["command"] == ["print", job.service]
        assert diagnostic["events"][2]["stage"] == "waiting for ready barrier"
        assert diagnostic["events"][3]["stage"] == "ready barrier failed"
        assert diagnostic["events"][4]["stdout"] == "state = exited; last exit code = 1"
    finally:
        job.close()
    assert calls == [("bootstrap", job.domain, str(job.plist)),
                     ("print", job.service), ("print", job.service),
                     ("bootout", job.service)]

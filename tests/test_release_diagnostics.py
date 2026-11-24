"""Completed ownership release must not depend on its diagnostic sink."""
import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Linux ownership supervision")
@pytest.mark.parametrize("diagnostic_errno", ["EPIPE", "EIO"])
def test_owned_launch_releases_after_contention_with_broken_stderr(tmp_path, diagnostic_errno):
    code = r"""
import errno, os, sys
from pathlib import Path
from claude_swap import spawn, profile_ownership as ownership

root = Path(sys.argv[1])
profile = root / "profile"
class BrokenStderr:
    def write(self, text):
        raise OSError(getattr(errno, sys.argv[2]), "unavailable diagnostic sink")
    def flush(self):
        pass

with ownership.ownership_lock(root):
    assert not ownership.profile_busy_locked(root, "1", profile)
    record = ownership.reserve_locked(root, "1", profile)
def publish():
    with ownership.ownership_lock(root):
        ownership.mark_running_locked(root, record["launchId"], os.getpid())
def release():
    lock = ownership.ownership_lock(root)
    acquire = lock.acquire
    attempts = []
    def busy_then_success():
        attempts.append(True)
        return False if len(attempts) == 1 else acquire()
    lock.acquire = busy_then_success
    try:
        ownership.release_completed(root, record["launchId"])
    finally:
        lock.acquire = acquire
    assert len(attempts) == 2, attempts
stderr = sys.stderr
sys.stderr = BrokenStderr()
try:
    result = spawn.owned_launch(lambda: os._exit(23), publish=publish,
        release=release, abort=lambda: None)
finally:
    sys.stderr = stderr
assert result == 23, result
assert not ownership._record_path(root, record["launchId"]).exists()
with ownership.ownership_lock(root):
    assert not ownership.profile_busy_locked(root, "1", profile)
sys.exit(result)
"""
    for launch in range(2):
        result = subprocess.run(
            [sys.executable, "-c", code, str(tmp_path), diagnostic_errno],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "HOME": str(tmp_path)},
        )
        assert result.returncode == 23, (launch, result.stderr)

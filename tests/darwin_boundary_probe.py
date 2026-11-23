"""Darwin-only, synthetic launchd counterexample probe; never admits Claude.

launchd.plist(5) AbandonProcessGroup describes process-group cleanup, not a
closed descendant boundary. launchctl(1) print is diagnostic, not an emptiness
certificate. Even successful observations here MUST NOT release ownership.
Run as ``python -m tests.darwin_boundary_probe OUTPUT.json`` on macos-keychain.
"""

from __future__ import annotations

import json
import os
import platform
import plistlib
import resource
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


def target(directory: Path, detached: bool) -> None:
    # No imports, credentials, network clients or product launch path involved.
    if detached:
        if os.fork():
            os._exit(0)
        os.setsid()
        if os.fork():
            os._exit(0)
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    os.closerange(0, int(maximum))
    channel = socket.socket(socket.AF_UNIX)
    channel.settimeout(60)
    channel.connect(str(directory / "barrier"))
    channel.sendall(json.dumps({"pid": os.getpid(), "sid": os.getsid(0),
                                "pgid": os.getpgrp()}).encode() + b"\n")
    # Independent barrier opened AFTER closing inherited channels and setsid.
    while True:
        command = channel.recv(16)
        if command == b"ping":
            channel.sendall(b"alive")
        elif command == b"exit":
            channel.sendall(b"leaving")
            break
        else:
            break
    channel.close()
    os._exit(0)


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/launchctl", *args], capture_output=True,
                          text=True, timeout=15)


def configuration(label: str, directory: Path, detached: bool) -> dict:
    return {
        "Label": label,
        "ProgramArguments": [sys.executable, str(Path(__file__).resolve()),
                             "--target", str(directory), str(int(detached))],
        "RunAtLoad": True,
        "KeepAlive": False,
        "AbandonProcessGroup": False,
        "EnvironmentVariables": {"HOME": str(directory / "home"),
                                 "PATH": "/usr/bin:/bin"},
        "WorkingDirectory": str(directory),
    }


class Job:
    def __init__(self, root: Path, detached: bool):
        self.directory = root / uuid.uuid4().hex
        self.directory.mkdir()
        (self.directory / "home").mkdir()
        self.label = "org.claude-swap.boundary-probe." + uuid.uuid4().hex
        self.service = f"gui/{os.getuid()}/{self.label}"
        self.domain = f"gui/{os.getuid()}"
        self.plist = self.directory / "job.plist"
        self.plist.write_bytes(plistlib.dumps(configuration(
            self.label, self.directory, detached)))
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.directory / "barrier"))
        self.listener.listen(1)
        self.listener.settimeout(20)
        self.channel = None
        self.submitted = False

    def start(self) -> dict:
        result = launchctl("bootstrap", self.domain, str(self.plist))
        if result.returncode:
            raise RuntimeError(f"bootstrap failed: {result.returncode}: {result.stderr}")
        self.submitted = True
        self.channel, _ = self.listener.accept()
        self.channel.settimeout(5)
        message = b""
        while not message.endswith(b"\n"):
            chunk = self.channel.recv(1024)
            if not chunk:
                raise RuntimeError("EOF before ready barrier")
            message += chunk
            if len(message) > 4096:
                raise RuntimeError("invalid ready barrier")
        return json.loads(message)

    def snapshot(self) -> dict:
        result = launchctl("print", self.service)
        return {"returncode": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr}

    def ping(self) -> bool:
        self.channel.sendall(b"ping")
        return self.channel.recv(16) == b"alive"

    def stop_target(self) -> str:
        self.channel.sendall(b"exit")
        return self.channel.recv(16).decode()

    def close(self) -> None:
        if self.channel is not None:
            try:
                self.channel.sendall(b"exit")
            except OSError:
                pass
            self.channel.close()
        self.listener.close()
        if self.submitted:
            # Never bootout a domain, enumerate jobs or signal a sampled PID.
            result = launchctl("bootout", self.service)
            if result.returncode:
                raise RuntimeError(f"own job bootout failed: {result.stderr}")


def run(output: Path) -> None:
    if sys.platform != "darwin":
        raise SystemExit("Darwin required; no job or target created")
    sha = subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    report = {"sha": sha, "darwin": platform.release(),
              "os": platform.platform(), "claude_launches": 0, "posts": 0,
              "mechanism": "launchd job / process-group cleanup",
              "verdict": "gap: no documented closed descendant-boundary emptiness certificate",
              "scenarios": {}}
    try:
        # /tmp keeps AF_UNIX path below Darwin's sockaddr_un length limit.
        with tempfile.TemporaryDirectory(prefix="cswap-mac-", dir="/tmp") as temporary:
            root = Path(temporary)
            jobs = [Job(root, True), Job(root, False)]
            try:
                main, neighbor = jobs
                report["ready"] = main.start()
                report["neighbor_ready"] = neighbor.start()
                # Observe diagnostics until leader PID disappears, with a budget
                # for the experiment only. No observation authorizes release.
                deadline = time.monotonic() + 10
                while True:
                    snapshot = main.snapshot()
                    if "pid = " not in snapshot["stdout"] or time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                report["after_leader"] = snapshot
                report["grandchild_waiting"] = main.ping()
                report["scenarios"]["1"] = {
                    "status": "gap", "release_authorized": False,
                    "reason": "setsid descendants are not a documented process-group boundary; product admission remains refused"}
                report["controlled_exit"] = main.stop_target()
                report["after_controlled_exit"] = main.snapshot()
                report["neighbor_waiting"] = neighbor.ping()
                report["scenarios"]["2"] = {
                    "status": "gap", "release_authorized": False,
                    "reason": "leaving/EOF/leader exit/print/bootout cannot certify closed-boundary emptiness"}
                report["scenarios"]["3"] = {
                    "status": "not admitted", "release_authorized": False,
                    "reason": "Darwin running publication and supervision are unsupported; no safe launcher-interruption experiment using product ownership"}
                # Creation error must not trigger any fallback target launch.
                rejected = launchctl("bootstrap", main.domain, str(root / "missing.plist"))
                if rejected.returncode == 0:
                    raise RuntimeError("missing plist unexpectedly accepted")
                report["creation_failure"] = {"returncode": rejected.returncode,
                    "target_started": False, "fallback": False}
                assert report["neighbor_waiting"], "neighbor disappeared"
            finally:
                failures = []
                for job in reversed(jobs):
                    try:
                        job.close()
                    except Exception as exc:
                        failures.append(str(exc))
                if failures:
                    raise RuntimeError("cleanup: " + "; ".join(failures))
    except BaseException as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    if sys.platform != "darwin":
        raise SystemExit("Darwin required; no job or target created")
    if sys.argv[1] == "--target":
        target(Path(sys.argv[2]), bool(int(sys.argv[3])))
    else:
        run(Path(sys.argv[1]))

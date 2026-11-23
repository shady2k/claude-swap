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
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


def target(directory: Path, detached: bool) -> None:
    import resource

    # Persist milestones even after inherited stdout/stderr are closed.
    def milestone(stage):
        with (directory / "target-stages.log").open("a") as stream:
            stream.write(stage + "\n")

    milestone("entered target")
    # No credentials, network clients or product launch path involved.
    if detached:
        if os.fork():
            os._exit(0)
        os.setsid()
        milestone("setsid complete")
        if os.fork():
            os._exit(0)
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    os.closerange(0, int(maximum))
    milestone("inherited descriptors closed")
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
        "LaunchOnlyOnce": True,
        "AbandonProcessGroup": False,
        "EnvironmentVariables": {"HOME": str(directory / "home"),
                                 "PATH": "/usr/bin:/bin"},
        "StandardOutPath": str(directory / "stdout.log"),
        "StandardErrorPath": str(directory / "stderr.log"),
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
        self.events = []

    def command(self, *args: str) -> dict:
        event = {"command": list(args)}
        self.events.append(event)
        try:
            result = launchctl(*args)
            event.update(returncode=result.returncode, stdout=result.stdout,
                         stderr=result.stderr)
        except Exception as exc:
            event["error"] = f"{type(exc).__name__}: {exc}"
            raise
        return event

    def diagnostics(self) -> dict:
        logs = {}
        for name in ("stdout.log", "stderr.log", "target-stages.log"):
            path = self.directory / name
            logs[name] = path.read_text(errors="replace") if path.exists() else None
        return {"service": self.service, "events": self.events, "logs": logs}

    def start(self) -> dict:
        result = self.command("bootstrap", self.domain, str(self.plist))
        if result["returncode"]:
            raise RuntimeError(f"bootstrap failed: {result['returncode']}: {result['stderr']}")
        self.submitted = True
        self.events.append({"stage": "waiting for ready barrier"})
        try:
            self.channel, _ = self.listener.accept()
        except Exception as exc:
            self.events.append({"stage": "ready barrier failed",
                                "error": f"{type(exc).__name__}: {exc}"})
            try:
                self.snapshot()
            except Exception:
                # command() already recorded the diagnostic failure.
                pass
            raise
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
        return self.command("print", self.service)

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
            result = self.command("bootout", self.service)
            if result["returncode"]:
                raise RuntimeError(f"own job bootout failed: {result['stderr']}")


def run(output: Path) -> None:
    if sys.platform != "darwin":
        raise SystemExit("Darwin required; no job or target created")
    sha = subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    report = {"sha": sha, "darwin": platform.release(),
              "os": platform.platform(), "claude_launches": 0, "posts": 0,
              "mechanism": "launchd job / process-group cleanup",
              "verdict": "not observed: probe has not reached scenarios",
              "documentation_assessment": "gap: no documented closed descendant-boundary emptiness certificate",
              "scenarios": {}, "stage": "preflight", "jobs": []}
    try:
        # /tmp keeps AF_UNIX path below Darwin's sockaddr_un length limit.
        with tempfile.TemporaryDirectory(prefix="cswap-mac-", dir="/tmp") as temporary:
            root = Path(temporary)
            # Compare availability only; no implicit domain fallback or start.
            report["domains"] = {}
            for kind in ("gui", "user"):
                result = launchctl("print", f"{kind}/{os.getuid()}")
                report["domains"][kind] = {
                    "returncode": result.returncode, "stderr": result.stderr}
            home = root / "preflight-home"
            home.mkdir()
            preflight = subprocess.run(
                [sys.executable, "-c", "import sys, resource, socket; print(sys.executable)"],
                env={"HOME": str(home), "PATH": "/usr/bin:/bin"}, cwd=root,
                capture_output=True, text=True, timeout=15)
            report["interpreter_preflight"] = {
                "argv": [sys.executable], "returncode": preflight.returncode,
                "stdout": preflight.stdout, "stderr": preflight.stderr,
                "launch_only_once": True}
            jobs = [Job(root, True), Job(root, False)]
            primary_error = None
            try:
                main, neighbor = jobs
                report["stage"] = "main start"
                report["ready"] = main.start()
                report["stage"] = "neighbor start"
                report["neighbor_ready"] = neighbor.start()
                report["stage"] = "leader observation"
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
                report["verdict"] = "gap: observed synthetic readiness, no OS emptiness certificate"
                report["stage"] = "controlled exit"
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
                report["stage"] = "creation failure control"
                rejected = launchctl("bootstrap", main.domain, str(root / "missing.plist"))
                if rejected.returncode == 0:
                    raise RuntimeError("missing plist unexpectedly accepted")
                report["creation_failure"] = {"returncode": rejected.returncode,
                    "target_started": False, "fallback": False}
                assert report["neighbor_waiting"], "neighbor disappeared"
                report["stage"] = "observations complete"
            except BaseException as exc:
                primary_error = exc
                raise
            finally:
                failures = []
                for job in reversed(jobs):
                    try:
                        job.close()
                    except Exception as exc:
                        failures.append(str(exc))
                report["jobs"] = [job.diagnostics() for job in jobs]
                report["cleanup_errors"] = failures
                if failures and primary_error is None:
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
        try:
            target(Path(sys.argv[2]), bool(int(sys.argv[3])))
        except BaseException:
            import traceback

            # stderr may already be closed in a detached descendant.
            with (Path(sys.argv[2]) / "target-stages.log").open("a") as stream:
                traceback.print_exc(file=stream)
            raise
    else:
        run(Path(sys.argv[1]))

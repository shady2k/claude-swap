"""Installed only in the throwaway no-network stand's Python environment."""

import hashlib
import inspect
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path


class StandBlocked(BaseException):
    """An audited operation was refused before Python could execute it."""


_ENV_LABELS = {
    "LANG": "locale-lang",
    "LC_ALL": "locale-all",
    "LC_CTYPE": "locale-ctype",
    "__CF_USER_TEXT_ENCODING": "darwin-user-text-encoding",
    "__PYVENV_LAUNCHER__": "venv-launcher",
}


def environment_difference(expected, live):
    def summarize(keys):
        return {
            "count": len(keys),
            "known": sorted(_ENV_LABELS[key] for key in keys if key in _ENV_LABELS),
        }

    return {
        "added": summarize(live.keys() - expected.keys()),
        "missing": summarize(expected.keys() - live.keys()),
        "changed": summarize({key for key in expected.keys() & live.keys()
                              if expected[key] != live[key]}),
    }


def exit_startup(reason, details=None):
    suffix = f" {json.dumps(details)}" if details else ""
    os.write(2, f"no-network stand could not establish audited startup: {reason}{suffix}\n".encode("ascii"))
    os._exit(125)


def install():
    policy = json.loads(Path(__file__).with_name("stand-policy.json").read_text(encoding="utf-8"))
    journal = policy["journal"]
    original_popen = subprocess.Popen
    popen_signature = inspect.signature(original_popen)
    active_launch = threading.local()
    process_events = {"os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.spawn",
                      "os.startfile", "os.startfile/2", "os.system"}
    audit_events = {"subprocess.Popen", "_posixsubprocess.fork_exec", "_winapi.CreateProcess"}

    def record(kind, **fields):
        # One append-mode write so concurrent Python processes do not splice
        # records. Never include argv, environment, addresses or payloads.
        line = json.dumps({"kind": kind, "pid": os.getpid(), **fields}).encode("ascii") + b"\n"
        try:
            fd = os.open(journal, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
            try:
                if os.write(fd, line) != len(line):
                    os._exit(125)
            finally:
                os.close(fd)
        except OSError:
            os._exit(125)

    def blocked(event):
        record("blocked", event=event)
        raise StandBlocked("stand blocked " + event)

    def script_id(path):
        if not isinstance(path, str) or not Path(path).is_absolute():
            return None
        entry = policy["scripts"].get(os.path.normcase(path))
        if entry is None:
            return None
        number, digest = entry
        try:
            if os.path.normcase(str(Path(path).resolve(strict=True))) != os.path.normcase(path):
                return None
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                return None
        except (OSError, ValueError):
            return None
        return number

    shim = policy["shim"]
    shim_main = bool(shim and sys.orig_argv == [
        policy["python"], "-I", "-m", "claude_swap.transparent",
        f'--cswap-shim=0:{shim["dir"]}', *shim["argv"],
    ])
    shim_script = script_id(shim["script"]) if shim else None

    def safe_env(env):
        live = os.environ if env is None else env
        return live == policy["env"]

    supervisor_pid = os.getpid()
    if sys.platform == "linux" and shim_script and script_id(sys.argv[0]) == shim_script:
        observations = [json.loads(line) for line in Path(journal).read_text().splitlines()]
        splits = [entry for entry in observations if entry["kind"] == "supervise"]
        if len(splits) != 1:
            exit_startup("supervisor")
        supervisor_pid = splits[0]["pid"]
    fork_used = False
    exec_used = False

    def expected_shim_child_env():
        return {**shim["child_env"], "CLAUDE_SWAP_LAUNCHED": str(supervisor_pid)}

    def supervised_fork():
        nonlocal fork_used
        if not (sys.platform == "linux" and shim_main and not fork_used and os.getpid() == supervisor_pid):
            return False
        module = sys.modules.get("claude_swap.spawn")
        caller = sys._getframe(2)
        function = getattr(module, "supervise", None)
        if not (function and caller.f_code is function.__code__
                and Path(caller.f_code.co_filename).resolve() == Path(policy["source"]) / "claude_swap" / "spawn.py"):
            return False
        # The real shim must have published its selected profile before the split.
        profile = Path(shim["child_env"]["CLAUDE_CONFIG_DIR"])
        backup = profile.parents[1]
        try:
            records = [json.loads(path.read_text()) for path in
                       (backup / "profile-ownership" / "launches").glob("*.json")]
            owned = [entry for entry in records if entry.get("state") == "running"
                     and entry.get("pid") == supervisor_pid and entry.get("ownerPid") == supervisor_pid
                     and entry.get("profile") == str(profile) and entry.get("accountNum") == "1"]
            if len(owned) != 1:
                return False
        except (OSError, ValueError):
            return False
        fork_used = True  # Consumed before fork, so the child inherits no permit.
        record("supervise")
        return True

    def exec_shim_child(args):
        nonlocal exec_used
        path, argv, env = args
        if sys.platform == "linux" and (not fork_used or os.getpid() == supervisor_pid or exec_used):
            return False
        if not (shim_main and shim_script and path == shim["fake"] and env == expected_shim_child_env()):
            return False
        if len(argv) < 3 or list(argv[:2]) != [path, "--settings"] or list(argv[3:]) != shim["argv"]:
            return False
        layer = Path(argv[2])
        if not layer.is_absolute() or not layer.resolve().is_relative_to(shim["dir"]):
            return False
        try:
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != shim["fake_digest"]:
                return False
        except OSError:
            return False
        if script_id(shim["script"]) != shim_script:
            return False
        exec_used = True
        record("exec", script=shim_script)
        return True

    def hook(event, args):
        # Only detector controls may allocate an unconnected, non-raw
        # socket; bind, connect, sendto, and lookups remain blocked.
        if event == "socket.__new__" and policy["probe_socket_operations"]:
            _, family, kind, proto = args
            if family == socket.AF_INET and kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM) and proto == 0:
                return
        if event == "os.fork" and supervised_fork():
            return
        if event == "os.exec" and exec_shim_child(args):
            return
        if event.startswith("socket.") or event in process_events:
            blocked(event)
        elif event in audit_events and not getattr(active_launch, "allowed", False):
            blocked(event)

    class StandPopen(original_popen):
        def __init__(self, *args, **kwargs):
            call = popen_signature.bind(*args, **kwargs)
            call.apply_defaults()
            options = call.arguments
            argv = options["args"]
            if not isinstance(argv, (list, tuple)) or len(argv) < 3:
                blocked("subprocess.Popen")
            if not all(isinstance(item, str) for item in argv):
                blocked("subprocess.Popen")
            if (
                argv[0] != policy["python"] or argv[1] != "-I"
                or options["executable"] not in (None, policy["python"])
                or options["shell"] or not options["close_fds"] or options["pass_fds"]
                or options["preexec_fn"] is not None or options["startupinfo"] is not None
                or not safe_env(options["env"])
            ):
                blocked("subprocess.Popen")
            number = script_id(argv[2])
            if number is None:
                blocked("subprocess.Popen")
            cwd = options["cwd"] if options["cwd"] is not None else os.getcwd()
            if not Path(cwd).resolve().is_relative_to(policy["root"]):
                blocked("subprocess.Popen")
            record("spawn", script=number)
            active_launch.allowed = True
            try:
                # Passing an explicit cwd keeps CPython on its checked,
                # closed-descriptor Popen path, not direct os.posix_spawn.
                options["cwd"] = cwd
                super().__init__(*call.args, **call.kwargs)
            finally:
                active_launch.allowed = False

    # Each top-level invocation is synchronous and starts with a fresh
    # journal offset. Its audited Popen/exec records before a descendant
    # starts. PPIDs are not reliable: venv launchers may insert a process.
    with open(journal, "rb") as observations:
        observations.seek(policy["launch_journal_start"])
        stage = "descendant" if observations.read(1) else "root"

    def reject_startup(reason, **fields):
        details = {"stage": stage, **fields}
        record("blocked", event="startup", reason=reason, **details)
        exit_startup(reason, details)

    sys.addaudithook(hook)
    subprocess.Popen = StandPopen
    if not (sys.flags.isolated and sys.flags.ignore_environment and sys.flags.no_user_site):
        reject_startup("flags")
    if os.path.normcase(sys.executable) != os.path.normcase(policy["python"]):
        reject_startup("interpreter")
    number = 0 if shim_main else script_id(sys.argv[0])
    if number is None:
        reject_startup("script")
    if shim_script and number == shim_script:
        expected_env = expected_shim_child_env()
    else:
        expected_env = policy["env"]
    if os.environ != expected_env:
        reject_startup("environment", environment=environment_difference(expected_env, os.environ))
    sys.path.insert(0, policy["source"])
    record("startup", script=number, isolated=True, stage=stage)


try:
    install()
except BaseException:
    # site.py normally catches startup errors and runs the user's script anyway.
    exit_startup("setup")

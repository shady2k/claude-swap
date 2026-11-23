"""Native Windows supervision checks using synthetic Python process trees."""

import ctypes
import json
import os
import select
import socket
import subprocess
import sys
from contextlib import contextmanager

import pytest

from claude_swap import spawn

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows Job Objects")

# Bounds protect CI from a broken adapter; they never establish tree completion.
WAIT_SECONDS = 15

_TREE = r"""
import json, os, socket, subprocess, sys
from pathlib import Path
from claude_swap import spawn
mode, port, root, *options = sys.argv[1:]
def channel(role):
    connection = socket.create_connection(("127.0.0.1", int(port)))
    connection.sendall((json.dumps({"role": role, "pid": os.getpid()}) + "\n").encode())
    return connection
if mode == "grandchild":
    connection = channel(mode)
    assert connection.recv(1) == b"x"
    sys.exit(0)
if mode == "leader":
    subprocess.Popen([sys.executable, __file__, "grandchild", port, root], close_fds=True)
    connection = channel(mode)
    assert connection.recv(1) == b"x"
    sys.exit(37)
if not options:
    spawn.require_supervision()
root = Path(root)
connection = channel("supervisor")
assert connection.recv(1) == b"s"
if options:
    from types import SimpleNamespace
    from claude_swap import session, transparent, profile_ownership as ownership, launch_policy
    from claude_swap.switcher import ClaudeAccountSwitcher
    from claude_swap.exceptions import ClaudeSwitchError

    route, *failures = options
    switcher = ClaudeAccountSwitcher()
    assert switcher.backup_dir == root
    profile = session.session_dir_for(root, "1", switcher.resolve_account("1")[1])
    profile.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CLAUDE_CONFIG_DIR=str(profile))
    args = [__file__, "leader", port, str(root)]
    binary = SimpleNamespace(
        path=Path(sys.executable).resolve(),
        handoff=lambda args, env, **kwargs: spawn.handoff(
            str(Path(sys.executable).resolve()), args, env),
    )
    if failures:
        import ctypes
        kernel = spawn._windows_api()
        def failed(*args):
            ctypes.set_last_error(5)
            return 0
        kernel.QueryInformationJobObject = failed
        spawn._windows_api = lambda: kernel
    try:
        if route == "session":
            manager = session.SessionManager(switcher)
            # The native stand supplies an admitted synthetic executable and
            # a prepared profile; publication and cleanup stay in _exec.
            manager._admit_profile_launch = lambda args: None
            with manager._reserve_profile("1"):
                manager._exec(binary, args, env)
        else:
            history = root / "synthetic-history"
            history.mkdir(exist_ok=True)
            (profile / "projects").mkdir(exist_ok=True)
            recipient = transparent._Recipient(
                "1", launch_policy.identity(switcher._get_sequence_data()["accounts"]["1"])
            )
            policy = {"enabled": True, "pool": ["1"], "historyZone": {
                "scope": launch_policy.HISTORY_SCOPE,
                "members": {"1": list(recipient.identity)},
            }}
            switcher._write_json(root / "transparent.json", policy)
            # POSIX shim installation and shared-history validation are not
            # supported on Windows. Supply their prepared result, retaining
            # _launch, _publish_launch and both real storage locks.
            launch_policy.archive = lambda **kwargs: history
            transparent._profile_dir = lambda *args: profile
            # Shim-local telemetry belongs to the unsupported POSIX install,
            # not to profile ownership publication or tree supervision.
            def journal(directory, event=None):
                assert directory == transparent.paths.get_shim_dir(root)
                assert event == "launch"
                return 1
            transparent._journal = journal
            def prepare(*unused, **kwargs):
                with ownership.ownership_lock(root), transparent.FileLock(switcher.lock_file):
                    record = ownership.reserve_locked(root, "1", profile)
                return transparent._Launch(binary, args, env, recipient, profile,
                                           reservation=record)
            transparent._prepare_launch = prepare
            transparent._launch("synthetic", [], root)
    except SystemExit as exc:
        connection.sendall((json.dumps({"complete": exc.code}) + "\n").encode())
        raise
    except (ClaudeSwitchError, OSError):
        if not failures:
            raise
        # Do not release or rewrite ownership here: an observation failure
        # must leave the entrance's published record intact.
        connection.sendall(b'{"unconfirmed": true}\n')
        sys.exit(4)
    raise AssertionError("internal launch returned without status")
def launch():
    spawn.handoff(str(Path(sys.executable).resolve()),
                  [__file__, "leader", port, str(root)], dict(os.environ))
result = spawn.supervise(launch)
connection.sendall((json.dumps({"complete": result}) + "\n").encode())
sys.exit(result)
"""


def _receive(connection):
    message = bytearray()
    while not message.endswith(b"\n"):
        part = connection.recv(1)
        assert part, "synthetic process closed its channel before reporting"
        message.extend(part)
    return json.loads(message)


@pytest.fixture
def kernel():
    from ctypes import wintypes as w

    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    for name, arguments, result in [
        ("OpenProcess", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        ("WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD),
        ("TerminateProcess", [w.HANDLE, w.UINT], w.BOOL),
        ("CloseHandle", [w.HANDLE], w.BOOL),
    ]:
        function = getattr(dll, name)
        function.argtypes = arguments
        function.restype = result
    return dll


@contextmanager
def _tree(tmp_path, kernel, *, route=None, observer_failure=False):
    script = tmp_path / "synthetic_tree.py"
    script.write_text(_TREE, encoding="utf-8")
    connections = {}
    handles = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(3)
        listener.settimeout(WAIT_SECONDS)
        process = subprocess.Popen(
            [sys.executable, str(script), "supervisor", str(listener.getsockname()[1]), str(tmp_path)]
            + ([route] if route else [])
            + (["observer-failure"] if observer_failure else []),
            env={key: value for key, value in os.environ.items()
                 if key != "CLAUDE_SWAP_TEST_MODE"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        )
        try:
            for _ in range(3):
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    if process.poll() is None:
                        process.kill()
                    stdout, stderr = process.communicate(timeout=WAIT_SECONDS)
                    pytest.fail(
                        f"Synthetic tree did not report all roles; received {sorted(connections)}; "
                        f"supervisor exit={process.returncode}; "
                        f"stdout={stdout.decode(errors='replace')!r}; "
                        f"stderr={stderr.decode(errors='replace')!r}"
                    )
                connection.settimeout(WAIT_SECONDS)
                info = _receive(connection)
                role = info["role"]
                connections[role] = connection
                # Retain process identities, not PIDs or job handles. The observer
                # must not keep the kill-on-close job alive by holding a handle.
                handle = kernel.OpenProcess(0x100000 | 0x1000 | 0x0001, False, info["pid"])
                assert handle, ctypes.WinError(ctypes.get_last_error())
                handles[role] = handle
                if role == "supervisor":
                    connection.sendall(b"s")
            yield process, connections, handles
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=WAIT_SECONDS)
            for handle in handles.values():
                if kernel.WaitForSingleObject(handle, 0) == 258:
                    kernel.TerminateProcess(handle, 99)
                    kernel.WaitForSingleObject(handle, WAIT_SECONDS * 1000)
                kernel.CloseHandle(handle)
            for connection in connections.values():
                connection.close()
            process.stdout.close()
            process.stderr.close()


@pytest.mark.mock_stand_routing
@pytest.mark.parametrize("route", ["session", "transparent"])
def test_supervision_waits_for_job_empty_and_releases_ownership(
    temp_home, private_backup_root, sample_sequence_data, kernel, route,
):
    from claude_swap import profile_ownership as ownership
    from claude_swap.switcher import ClaudeAccountSwitcher

    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    for account in sample_sequence_data["accounts"].values():
        account["organizationUuid"] = ""
        account["organizationName"] = ""
    switcher._write_json(switcher.sequence_file, sample_sequence_data)
    before = switcher.sequence_file.read_bytes()
    tmp_path = switcher.backup_dir
    with _tree(tmp_path, kernel, route=route) as (process, connections, handles):
        connections["leader"].sendall(b"x")
        assert kernel.WaitForSingleObject(handles["leader"], WAIT_SECONDS * 1000) == 0
        assert kernel.WaitForSingleObject(handles["grandchild"], 0) == 258
        assert kernel.WaitForSingleObject(handles["supervisor"], 0) == 258
        assert not select.select([connections["supervisor"]], [], [], 0.2)[0]
        with ownership.ownership_lock(tmp_path):
            records = [json.loads(file.read_text())
                       for file in (tmp_path / "profile-ownership").rglob("*.json")]
            assert sum(record.get("state") == "running" for record in records) == 1
            assert ownership.profile_busy_locked(tmp_path, "1")
        with pytest.raises(ownership.SessionError, match="busy"):
            switcher.move_account("1", "3")
        assert switcher.sequence_file.read_bytes() == before
        connections["grandchild"].sendall(b"x")
        assert _receive(connections["supervisor"]) == {"complete": 37}
        assert process.wait(timeout=WAIT_SECONDS) == 37
        assert kernel.WaitForSingleObject(handles["grandchild"], 0) == 0
        with ownership.ownership_lock(tmp_path):
            assert not ownership.profile_busy_locked(tmp_path, "1")
            records = [json.loads(file.read_text())
                       for file in (tmp_path / "profile-ownership").rglob("*.json")]
            assert not any(record.get("state") in ("reserved", "running") for record in records)


def test_supervision_waits_for_job_empty(tmp_path, kernel):
    with _tree(tmp_path, kernel) as (process, connections, handles):
        connections["leader"].sendall(b"x")
        assert kernel.WaitForSingleObject(handles["leader"], WAIT_SECONDS * 1000) == 0
        assert kernel.WaitForSingleObject(handles["grandchild"], 0) == 258
        assert kernel.WaitForSingleObject(handles["supervisor"], 0) == 258
        assert not select.select([connections["supervisor"]], [], [], 0.2)[0]
        connections["grandchild"].sendall(b"x")
        assert _receive(connections["supervisor"]) == {"complete": 37}
        assert process.wait(timeout=WAIT_SECONDS) == 37
        assert kernel.WaitForSingleObject(handles["grandchild"], 0) == 0


def test_killing_supervisor_kills_live_leader_and_grandchild(tmp_path, kernel):
    with _tree(tmp_path, kernel) as (process, connections, handles):
        assert kernel.WaitForSingleObject(handles["leader"], 0) == 258
        assert kernel.WaitForSingleObject(handles["grandchild"], 0) == 258
        process.kill()
        process.wait(timeout=WAIT_SECONDS)
        assert kernel.WaitForSingleObject(handles["leader"], WAIT_SECONDS * 1000) == 0
        assert kernel.WaitForSingleObject(handles["grandchild"], WAIT_SECONDS * 1000) == 0


def test_prepared_job_is_noninherited_kill_on_close_and_excludes_launcher():
    code = r"""
import ctypes
from ctypes import wintypes as w
from claude_swap import spawn
spawn.require_supervision()
job = spawn._job_handle
assert job
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.GetHandleInformation.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
kernel.GetHandleInformation.restype = w.BOOL
flags = w.DWORD()
assert kernel.GetHandleInformation(job, ctypes.byref(flags))
assert not flags.value & 1
kernel.GetCurrentProcess.restype = w.HANDLE
kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)]
kernel.IsProcessInJob.restype = w.BOOL
member = w.BOOL()
assert kernel.IsProcessInJob(kernel.GetCurrentProcess(), job, ctypes.byref(member))
assert not member.value
class Basic(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
               ("flags", w.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
               ("active", w.DWORD), ("affinity", ctypes.c_size_t),
               ("priority", w.DWORD), ("scheduling", w.DWORD)]
class Extended(ctypes.Structure):
    _fields_ = [("basic", Basic), ("io", ctypes.c_ulonglong * 6),
               ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
               ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
kernel.QueryInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                            w.DWORD, ctypes.c_void_p]
kernel.QueryInformationJobObject.restype = w.BOOL
info = Extended()
assert kernel.QueryInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info), None)
assert info.basic.flags & 0x2000
assert not info.basic.flags & (0x800 | 0x1000)
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                            timeout=WAIT_SECONDS)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", ["CreateJobObjectW", "SetInformationJobObject"])
def test_setup_failure_prevents_handoff(failure):
    code = r"""
import ctypes, sys
from claude_swap import spawn
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
real_loader = ctypes.WinDLL
def failed(*args):
    ctypes.set_last_error(5)
    return 0
setattr(kernel, sys.argv[1], failed)
ctypes.WinDLL = lambda name, **kwargs: kernel if name.lower() == "kernel32" else real_loader(name, **kwargs)
def launch():
    raise AssertionError("setup failure reached handoff")
try:
    spawn.require_supervision()
except OSError:
    pass
else:
    raise AssertionError("setup failure was accepted")
assert spawn._job_handle is None
try:
    spawn.supervise(launch)
except OSError:
    pass
else:
    raise AssertionError("failed setup returned completion")
"""
    result = subprocess.run([sys.executable, "-c", code, failure], capture_output=True,
                            text=True, timeout=WAIT_SECONDS)
    assert result.returncode == 0, result.stderr


def test_native_handoff_preserves_stdio_argv_and_environment():
    code = r"""
import os, sys
from pathlib import Path
from claude_swap import spawn
spawn.require_supervision()
child = r'''
import ctypes, json, os, sys
from ctypes import wintypes as w
# Hidden drive keys can be absent from Python's os.environ mapping.
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
get_environment = kernel.GetEnvironmentVariableW
get_environment.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
get_environment.restype = w.DWORD
required = get_environment("=C:", None, 0)
assert required, ctypes.WinError(ctypes.get_last_error())
drive = ctypes.create_unicode_buffer(required)
assert get_environment("=C:", drive, required) == required - 1
print(json.dumps([sys.argv[1:], os.environ["CSWAP_SYNTHETIC"], drive.value,
                  sys.stdin.readline().strip()]))
print("synthetic stderr", file=sys.stderr)
sys.exit(41)
'''
def launch():
    env = dict(os.environ, CSWAP_SYNTHETIC="value with spaces \u03bb")
    env["=C:"] = "C:\\synthetic"
    spawn.handoff(str(Path(sys.executable).resolve()),
                  ["-c", child, "with spaces", "", 'a"b', "one\\two", "\u03bb"], env)
sys.exit(spawn.supervise(launch))
"""
    result = subprocess.run(
        [sys.executable, "-c", code], input="synthetic stdin\n",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        capture_output=True, text=True, encoding="utf-8", timeout=WAIT_SECONDS,
    )
    assert result.returncode == 41, result.stderr
    assert json.loads(result.stdout) == [
        ["with spaces", "", 'a"b', "one\\two", "λ"],
        "value with spaces λ", "C:\\synthetic", "synthetic stdin",
    ]
    assert result.stderr.strip() == "synthetic stderr"


def _check_launch_or_observer_failure(tmp_path, failure, *, ownership=False):
    code = r"""
import ctypes, os, sys
from pathlib import Path
from claude_swap import spawn
root = Path(sys.argv[1])
failure = sys.argv[2]
marker = root / "launched"
spawn.require_supervision()
if "ownership" in sys.argv[3:]:
    from claude_swap import profile_ownership as ownership
    with ownership.ownership_lock(root):
        record = ownership.reserve_locked(root, "1", root / "synthetic-profile")
        ownership.mark_running_locked(root, record["launchId"], os.getpid())
kernel = spawn._windows_api()
def failed(*args):
    ctypes.set_last_error(5)
    return 0
setattr(kernel, failure, failed)
spawn._windows_api = lambda: kernel
def launch():
    spawn.handoff(str(Path(sys.executable).resolve()),
                  ["-c", "from pathlib import Path; Path(%r).write_text('started')" % str(marker)],
                  dict(os.environ))
try:
    spawn.supervise(launch)
except OSError:
    pass
else:
    raise AssertionError("failure returned confirmed completion")
assert marker.exists() == (failure == "QueryInformationJobObject")
if "ownership" in sys.argv[3:]:
    with ownership.ownership_lock(root):
        assert ownership.profile_busy_locked(root, "1")
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path), failure]
        + (["ownership"] if ownership else []),
        capture_output=True, text=True, timeout=WAIT_SECONDS,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", [
    "InitializeProcThreadAttributeList", "UpdateProcThreadAttribute", "CreateProcessW",
    "QueryInformationJobObject",
])
def test_launch_or_observer_failure_cannot_confirm_completion(tmp_path, failure):
    _check_launch_or_observer_failure(tmp_path, failure)


@pytest.mark.parametrize("failure", [
    "InitializeProcThreadAttributeList", "UpdateProcThreadAttribute", "CreateProcessW",
])
def test_launch_or_observer_failure_keeps_ownership_busy(tmp_path, failure):
    _check_launch_or_observer_failure(tmp_path, failure, ownership=True)


@pytest.mark.mock_stand_routing
@pytest.mark.parametrize("route", ["session", "transparent"])
def test_internal_launch_keeps_running_on_observer_failure(
    temp_home, private_backup_root, sample_sequence_data, kernel, route,
):
    from claude_swap import profile_ownership as ownership
    from claude_swap.switcher import ClaudeAccountSwitcher

    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    for account in sample_sequence_data["accounts"].values():
        account["organizationUuid"] = ""
        account["organizationName"] = ""
    switcher._write_json(switcher.sequence_file, sample_sequence_data)
    before = switcher.sequence_file.read_bytes()
    root = switcher.backup_dir
    with _tree(root, kernel, route=route, observer_failure=True) as (process, connections, handles):
        connections["leader"].sendall(b"x")
        assert kernel.WaitForSingleObject(handles["leader"], WAIT_SECONDS * 1000) == 0
        assert _receive(connections["supervisor"]) == {"unconfirmed": True}
        assert process.wait(timeout=WAIT_SECONDS) == 4
        with ownership.ownership_lock(root):
            records = [json.loads(file.read_text())
                       for file in (root / "profile-ownership").rglob("*.json")]
            running = [record for record in records if record.get("state") == "running"]
            assert len(running) == 1
            assert running[0]["accountNum"] == "1"
            assert ownership.profile_busy_locked(root, "1")
        with pytest.raises(ownership.SessionError, match="busy"):
            switcher.move_account("1", "3")
        assert switcher.sequence_file.read_bytes() == before

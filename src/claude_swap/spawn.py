"""Run short-lived helpers (``ps``, ``security``, ``claude``) without ``fork()``.

Once the kernel has sent a process a critical memory-pressure or process-limit
note, libmalloc loads MallocStackLogging.framework and from then on runs that
framework's fork hook in every child the process forks. With stack logging off,
the hook prints

    MallocStackLogging: can't turn off malloc stack logging because it was not enabled.

to the stderr the child inherited, before the exec, so the line lands on the
terminal or across the TUI and past any ``capture_output`` (issue #517). The
hook stays for the life of the process. ``subprocess`` on macOS forks for every
call unless the executable carries a directory component and ``close_fds`` is
False (Darwin has no ``posix_spawn`` closefrom), which is why every polling
spawn added a line once the hook was armed.

:func:`run` takes the ``posix_spawn`` path only when the descriptors present
at call time make it match the fork path. ``close_fds=True`` closes every
descriptor above 2 in the child, while ``posix_spawn`` only drops those marked
close-on-exec; Python marks its own that way (PEP 446), a C library or the
launching process need not. So the switch happens only when no inheritable
descriptor above 2 exists when the call is made. Every other call shape, a
descriptor state that cannot be told, and every other platform run
``subprocess.run`` unchanged. A directory-qualified executable is never looked
up on PATH, so ``/usr/bin/security`` stays pinned; a bare name is searched on
the PATH the child would get, as ``subprocess`` does, and made absolute,
because a relative hit would send CPython back to ``fork``.

The descriptor check is a snapshot, not the fork path's guarantee: a
descriptor another thread makes inheritable between the check and the launch
reaches the child, where ``close_fds=True`` would have closed it. Closing that
window needs Darwin's ``POSIX_SPAWN_CLOEXEC_DEFAULT``, which ``os.posix_spawn``
does not expose, and a native launcher is not worth a cosmetic bug. The
limitation is accepted on these grounds: Python creates descriptors
non-inheritable, no cswap code makes one inheritable, any that already exist
send the call down the fork path, and what a child could pick up is a copy it
holds only until it exits, whether that child is ``ps``, ``security`` or a
``claude auth status`` run.
"""

import logging
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn

_logger = logging.getLogger("claude-swap")

_FD_DIR = "/dev/fd"

# Keyword arguments on which CPython forks regardless, or that change what
# ``cmd[0]`` means. Such calls are passed through untouched.
_PASS_THROUGH = frozenset(
    {
        "close_fds",
        "cwd",
        "executable",
        "extra_groups",
        "group",
        "pass_fds",
        "preexec_fn",
        "process_group",
        "shell",
        "start_new_session",
        "umask",
        "user",
    }
)

_fallback_logged = False


def run(cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run`` for an argv list; see the module docstring."""
    if _spawn_path_applies(cmd, kwargs):
        executable = _resolve(cmd[0], kwargs.get("env"))
        if executable is not None and not _inheritable_fds_above_stdio():
            cmd = [executable, *cmd[1:]]
            kwargs["close_fds"] = False
    return _launch(cmd, kwargs)


def _launch(
    argv: Sequence[str], options: dict[str, Any], *, replace: str | int | None = None
) -> subprocess.CompletedProcess[Any]:
    if replace is not None:
        os.execve(replace, argv, options["env"])
        raise AssertionError("unreachable")  # pragma: no cover
    return subprocess.run(argv, **options)


# Keep only OS/runtime essentials; authentication and profile policy belong
# in the helper's own configuration. Test mode survives the subprocess boundary.
_PYTHON_HELPER_ENV = frozenset({
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "SYSTEMROOT",
    "SYSTEMDRIVE", "WINDIR", "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL",
    "LC_CTYPE", "CLAUDE_SWAP_TEST_MODE", "CLAUDE_SWAP_TEST_ENDPOINT",
})


def run_python(
    module: str, args: Sequence[str], *, backup_root: Path, **run_options: Any
) -> subprocess.CompletedProcess[Any]:
    """Run an internal module with the checked, isolated interpreter and a clean env."""
    from claude_swap import fsguard
    from claude_swap.exceptions import ConfigError
    from claude_swap.python_chain import check_python_chain

    if not module.startswith("claude_swap.") or not all(
        part.isidentifier() for part in module.split(".")
    ):
        raise ValueError("expected an internal Python helper module")
    if run_options.keys() & {"cwd", "env", "executable", "preexec_fn", "shell"}:
        raise ValueError("cannot override the Python helper launch context")
    try:
        executable = check_python_chain()
        cwd = fsguard.check_path(backup_root)
        if not cwd.is_dir():
            raise fsguard.GuardError(f"Not a backup directory: {cwd}")
    except fsguard.GuardError as exc:
        raise ConfigError(f"Untrusted Python helper launch context: {exc}") from exc
    env = {key: value for key, value in os.environ.items() if key in _PYTHON_HELPER_ENV}
    return run([str(executable), "-I", "-m", module, *args], cwd=cwd, env=env, **run_options)


def handoff(
    binary: str, args: Sequence[str], env: dict[str, str], *, fd: int | None = None
) -> NoReturn:
    """Hand over the terminal to an absolute executable path.

    POSIX replaces the current process. Where supported, ``fd`` pins a native
    executable to an already checked file. Windows stays in the console and
    mirrors the child exit status; Ctrl+C is delivered to the child too.
    Callers must release locks before handing off.
    """
    if not os.path.isabs(binary):
        raise ValueError("terminal handoff requires an absolute executable path")
    argv = [binary, *args]
    if fd is not None and (sys.platform == "win32" or os.execve not in os.supports_fd):
        raise OSError("exec by file descriptor is unavailable")
    if sys.platform == "win32":
        try:
            rc = run(argv, env=env).returncode
        except KeyboardInterrupt:
            rc = 130
        sys.exit(rc)
    _launch(argv, {"env": env}, replace=binary if fd is None else fd)
    raise AssertionError("unreachable")  # pragma: no cover


_job_lock = threading.Lock()
_job_handle: int | None = None


def ensure_windows_job() -> None:
    """Contain this process and future descendants in a kill-on-close job.

    Call before the first Claude spawn but after any unrelated helper spawn.
    The non-inheritable handle stays open for the lifetime of this process;
    closing it (including at process exit) terminates remaining descendants.
    An incompatible outer job raises before any Claude process is created.
    """
    global _job_handle
    if sys.platform == "win32":
        with _job_lock:
            if _job_handle is None:
                _job_handle = _assign_current_process_to_job()


def _assign_current_process_to_job() -> int:
    import ctypes
    from ctypes import wintypes as w

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", w.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", w.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", w.DWORD),
            ("SchedulingClass", w.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", ctypes.c_ulonglong * 6),  # IO_COUNTERS
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateJobObjectW
    create.argtypes = [ctypes.c_void_p, w.LPCWSTR]
    create.restype = w.HANDLE
    job_extended_limit_information = 9  # JobObjectExtendedLimitInformation
    job_kill_on_close = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    set_info = kernel32.SetInformationJobObject
    set_info.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    set_info.restype = w.BOOL
    assign = kernel32.AssignProcessToJobObject
    assign.argtypes = [w.HANDLE, w.HANDLE]
    assign.restype = w.BOOL
    current = kernel32.GetCurrentProcess
    current.argtypes = []
    current.restype = w.HANDLE
    close = kernel32.CloseHandle
    close.argtypes = [w.HANDLE]
    close.restype = w.BOOL

    handle = create(None, None)  # No name, no inherited handle.
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = job_kill_on_close
        if not set_info(
            handle, job_extended_limit_information, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not assign(handle, current()):
            raise ctypes.WinError(ctypes.get_last_error())
    except OSError:
        close(handle)
        raise
    return handle


def _spawn_path_applies(cmd: Any, kwargs: dict[str, Any]) -> bool:
    return (
        sys.platform == "darwin"
        and isinstance(cmd, (list, tuple))
        and bool(cmd)
        and not (_PASS_THROUGH & kwargs.keys())
    )


def _resolve(name: Any, env: Any = None) -> str | None:
    """``name`` when directory-qualified, else its absolute PATH hit, else None.

    The search path is the one the child would get: ``env``'s PATH, the
    parent's when no env is given, and ``os.defpath`` for an env without one,
    exactly as ``subprocess`` searches.
    """
    if not isinstance(name, str):
        return None
    if os.path.dirname(name):
        return name
    found = shutil.which(name, path=os.pathsep.join(os.get_exec_path(env)))
    return None if found is None else os.path.abspath(found)


def _inheritable_fds_above_stdio() -> bool:
    """Would a descriptor above 2 survive an exec? True too when that cannot be told."""
    try:
        names = os.listdir(_FD_DIR)
    except OSError:
        return True
    for name in names:
        try:
            fd = int(name)
        except ValueError:
            continue
        if fd <= 2:
            continue
        try:
            inheritable = os.get_inheritable(fd)
        except OSError:  # closed between the listing and the check
            continue
        if inheritable:
            _note_fallback(fd)
            return True
    return False


def _note_fallback(fd: int) -> None:
    global _fallback_logged
    if not _fallback_logged:
        _fallback_logged = True
        _logger.debug("spawn: descriptor %d is inheritable, keeping the fork path", fd)


def require_supervision() -> None:
    """Reject launch contexts where descendant completion cannot be proved.

    Linux subreapers adopt orphaned descendants even when they change session
    or process group. A dedicated, single-threaded launcher with no existing
    children can therefore wait until ECHILD to prove tree completion. Other
    platforms are deliberately unsupported rather than treating leader exit
    as tree completion.
    """
    import signal

    if sys.platform != "linux":
        raise OSError("Profile tree supervision is unsupported on this platform")
    tasks = list(Path("/proc/self/task").iterdir())
    if len(tasks) != 1 or threading.active_count() != 1:
        raise OSError("Profile tree supervision requires a single-threaded launcher")
    if (tasks[0] / "children").read_text().strip():
        raise OSError("Profile tree supervision requires a launcher without children")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise OSError("Profile tree supervision requires the default SIGCHLD handler")


def supervise(handoff) -> int:
    """Run a terminal handoff and return only after every descendant exits.

    The caller publishes running ownership before entering and releases it
    only on normal return. Any supervisor failure or death leaves ownership
    busy. This process must remain a dedicated launcher: it may not create
    unrelated children concurrently. No timeout can establish completion.
    """
    import ctypes
    import signal

    require_supervision()
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    # PR_SET_CHILD_SUBREAPER. Set before forking, so even an immediate orphan
    # is adopted by this supervisor rather than escaping to init.
    if prctl(36, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    forwarded = (signal.SIGTERM, signal.SIGHUP)
    # Prevent TERM/HUP from killing the supervisor between fork and handler
    # installation. The child deliberately unblocks these before exec.
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, forwarded)
    old_handlers = {}
    leader_alive = True
    pid = None

    def forward(signum, frame):
        if not leader_alive or pid is None:
            return
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    try:
        try:
            pid = os.fork()
        except OSError:
            # A failed fork creates no child; the precondition excludes
            # existing children, so returning proves the tree is empty.
            return 127
        if pid == 0:
            try:
                signal.pthread_sigmask(signal.SIG_UNBLOCK, forwarded)
                handoff()
            except BaseException:
                # Do not print callback exceptions that may contain secrets.
                os._exit(127)
            os._exit(127)

        # Terminal INT/QUIT reach the child directly. TERM/HUP addressed to
        # the supervisor must reach the child without abandoning reaping.
        for sig in (signal.SIGINT, signal.SIGQUIT):
            old_handlers[sig] = signal.signal(sig, signal.SIG_IGN)
        for sig in forwarded:
            old_handlers[sig] = signal.signal(sig, forward)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, forwarded)
        result = None
        while True:
            try:
                reaped, status = os.waitpid(-1, 0)
            except InterruptedError:
                continue
            except ChildProcessError:
                if result is None:
                    raise OSError("Profile leader completion could not be observed")
                return result
            if reaped == pid:
                leader_alive = False
                result = os.waitstatus_to_exitcode(status)
                if result < 0:
                    result = 128 - result
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)

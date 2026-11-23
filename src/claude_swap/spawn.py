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
            rc = (_windows_handoff(argv, env) if _job_handle is not None
                  else run(argv, env=env).returncode)
        except KeyboardInterrupt:
            rc = 130
        sys.exit(rc)
    _launch(argv, {"env": env}, replace=binary if fd is None else fd)
    raise AssertionError("unreachable")  # pragma: no cover


_job_lock = threading.Lock()
_job_handle: int | None = None


def ensure_windows_job() -> None:
    """Prepare an unnamed kill-on-close job, owned only by this launcher.

    The launcher is not a member: only the child tree enters the job, atomically
    at CreateProcessW via PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10+).
    Neither breakaway flag is enabled. Nested-job restrictions fail creation
    before child code can execute. The sole, non-inheritable handle remains
    open until launcher exit, including when observation fails.
    """
    global _job_handle
    if sys.platform == "win32":
        with _job_lock:
            if _job_handle is None:
                _job_handle = _create_windows_job()


def _windows_api():
    import ctypes
    from ctypes import wintypes as w

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
        "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
        "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
        "CloseHandle": ([w.HANDLE], w.BOOL),
        "InitializeProcThreadAttributeList": ([ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t)], w.BOOL),
        "UpdateProcThreadAttribute": ([ctypes.c_void_p, w.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p], w.BOOL),
        "DeleteProcThreadAttributeList": ([ctypes.c_void_p], None),
        "CreateProcessW": ([w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p], w.BOOL),
        "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
        "GetExitCodeProcess": ([w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
        "GetStdHandle": ([w.DWORD], w.HANDLE),
        "GetCurrentProcess": ([], w.HANDLE),
        "DuplicateHandle": ([w.HANDLE, w.HANDLE, w.HANDLE, ctypes.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD], w.BOOL),
    }
    for name, (args, result) in signatures.items():
        fn = getattr(kernel, name)
        fn.argtypes, fn.restype = args, result
    return kernel


def _create_windows_job() -> int:
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
            ("IoInfo", ctypes.c_ulonglong * 6),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = _windows_api()
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE, no breakaway
        if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return handle


_windows_supervising = False
_windows_leader_complete = False


def _windows_handoff(argv: Sequence[str], env: dict[str, str]) -> int:
    import ctypes
    import signal
    from ctypes import wintypes as w

    class StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", w.DWORD), ("lpReserved", w.LPWSTR),
            ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR),
            ("dwX", w.DWORD), ("dwY", w.DWORD),
            ("dwXSize", w.DWORD), ("dwYSize", w.DWORD),
            ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD),
            ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD),
            ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE),
        ]

    class StartupInfoEx(ctypes.Structure):
        _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", ctypes.c_void_p)]

    class ProcessInformation(ctypes.Structure):
        _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                    ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]

    for key, value in env.items():
        if not key or "\0" in key or "=" in key[1:] or key == "=":
            raise ValueError("illegal environment variable name")
        if "\0" in value:
            raise ValueError("embedded null character")

    old_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        kernel = _windows_api()
        size = ctypes.c_size_t()
        kernel.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
        attributes = ctypes.create_string_buffer(size.value)
        if not kernel.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = ProcessInformation()
        duplicates = []
        try:
            jobs = (w.HANDLE * 1)(_job_handle)
            if not kernel.UpdateProcThreadAttribute(attributes, 0, 0x0002000D, jobs,
                                                   ctypes.sizeof(jobs), None, None):
                raise ctypes.WinError(ctypes.get_last_error())
            startup = StartupInfoEx()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.lpAttributeList = ctypes.addressof(attributes)
            # Inherit the console and stdio, but never the job handle. No new
            # process group: console Ctrl+C reaches the leader directly.
            startup.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
            current = kernel.GetCurrentProcess()
            for field, number in (("hStdInput", -10), ("hStdOutput", -11), ("hStdError", -12)):
                source = kernel.GetStdHandle(number & 0xffffffff)
                if not source or source == ctypes.c_void_p(-1).value:
                    setattr(startup.StartupInfo, field, source)
                    continue
                duplicate = w.HANDLE()
                if not kernel.DuplicateHandle(current, source, current, ctypes.byref(duplicate),
                                              0, True, 2):  # DUPLICATE_SAME_ACCESS
                    raise ctypes.WinError(ctypes.get_last_error())
                duplicates.append(duplicate.value)
                setattr(startup.StartupInfo, field, duplicate.value)
            if duplicates:
                handles = (w.HANDLE * len(duplicates))(*duplicates)
                if not kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020002, handles,
                                                       ctypes.sizeof(handles), None, None):
                    raise ctypes.WinError(ctypes.get_last_error())
            environment = ctypes.create_unicode_buffer(
                "\0".join(f"{key}={value}" for key, value in sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0"
            )
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            if not kernel.CreateProcessW(argv[0], command, None, None, bool(duplicates),
                                         0x00080000 | 0x00000400, environment, None,
                                         ctypes.byref(startup), ctypes.byref(process)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            for handle in duplicates:
                kernel.CloseHandle(handle)
            kernel.DeleteProcThreadAttributeList(attributes)
        kernel.CloseHandle(process.hThread)
        try:
            while True:
                status = kernel.WaitForSingleObject(process.hProcess, 100)
                if status == 0:
                    break
                if status != 258:  # WAIT_TIMEOUT
                    raise ctypes.WinError(ctypes.get_last_error())
            result = w.DWORD()
            if not kernel.GetExitCodeProcess(process.hProcess, ctypes.byref(result)):
                raise ctypes.WinError(ctypes.get_last_error())
            global _windows_leader_complete
            _windows_leader_complete = True
            return result.value
        finally:
            kernel.CloseHandle(process.hProcess)
    finally:
        signal.signal(signal.SIGINT, old_handler)


def _supervise_windows(handoff) -> int:
    import ctypes
    import signal
    import time
    from ctypes import wintypes as w

    class Accounting(ctypes.Structure):
        _fields_ = [("times", ctypes.c_longlong * 4),
                    ("TotalPageFaultCount", w.DWORD), ("TotalProcesses", w.DWORD),
                    ("ActiveProcesses", w.DWORD), ("TotalTerminatedProcesses", w.DWORD)]

    global _windows_supervising, _windows_leader_complete
    if _windows_supervising:
        raise OSError("Profile supervision is already active")
    _windows_supervising = True
    _windows_leader_complete = False
    old_handlers = {}
    try:
        # Console signals reach the child tree directly, including after the
        # leader exits. Keep observing the job until all descendants finish.
        for name in ("SIGINT", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is not None:
                old_handlers[sig] = signal.signal(sig, signal.SIG_IGN)
        try:
            handoff()
        except SystemExit as exc:
            result = exc.code
        else:
            raise OSError("Profile handoff returned without leader completion")
        if not _windows_leader_complete:
            raise OSError("Profile leader completion could not be observed")
        kernel = _windows_api()
        while True:
            info = Accounting()
            if not kernel.QueryInformationJobObject(_job_handle, 1, ctypes.byref(info),
                                                    ctypes.sizeof(info), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.ActiveProcesses == 0:
                return result
            time.sleep(0.05)
    finally:
        _windows_supervising = False
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


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
    children can therefore wait until ECHILD to prove tree completion.
    Windows prepares an unassigned kill-on-close job before publication and
    requires observed leader exit plus an empty job. Other platforms reject
    rather than treating leader exit as tree completion.
    """
    import signal

    if sys.platform == "win32":
        ensure_windows_job()
        return
    if sys.platform != "linux":
        raise OSError("Profile tree supervision is unsupported on this platform")
    tasks = list(Path("/proc/self/task").iterdir())
    if len(tasks) != 1 or threading.active_count() != 1:
        raise OSError("Profile tree supervision requires a single-threaded launcher")
    if (tasks[0] / "children").read_text().strip():
        raise OSError("Profile tree supervision requires a launcher without children")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise OSError("Profile tree supervision requires the default SIGCHLD handler")
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot enable profile subreaper")
    fd = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(fd, 0)
    finally:
        os.close(fd)


def _signal_descendants(signum: int) -> None:
    """Signal a snapshot of proven descendants using Linux pidfds.

    The dedicated subreaper owns every direct child. Walk each child's task
    children list, pin its PID with a pidfd, and check its parent while both
    pidfds still name live processes. A dead parent may cause an orphan to
    move to us during traversal, so repeat discovery before delivery. Never
    broadcast to a process group: descendants may have called setsid, and a
    group can also contain processes we do not own. No numeric PID is used
    for signal delivery, so exit and PID reuse cannot target a stranger.
    """
    import signal

    root = os.getpid()
    pinned = {root: os.pidfd_open(root)}
    try:
        while True:
            added = False
            for parent, parent_fd in list(pinned.items()):
                try:
                    children = []
                    for task in Path(f"/proc/{parent}/task").iterdir():
                        try:
                            children.extend((task / "children").read_text().split())
                        except (ProcessLookupError, FileNotFoundError):
                            continue
                except ProcessLookupError:
                    continue
                except FileNotFoundError:
                    continue
                for child in map(int, children):
                    if child in pinned:
                        continue
                    fd = None
                    try:
                        fd = os.pidfd_open(child)
                        # comm may contain spaces and parentheses; fields
                        # after its closing parenthesis start with state, ppid.
                        stat = Path(f"/proc/{child}/stat").read_text()
                        ppid = int(stat.rsplit(")", 1)[1].split()[1])
                        signal.pidfd_send_signal(fd, 0)
                        signal.pidfd_send_signal(parent_fd, 0)
                        if ppid != parent:
                            continue
                        pinned[child] = fd
                        fd = None
                        added = True
                    except (ProcessLookupError, FileNotFoundError):
                        continue
                    finally:
                        if fd is not None:
                            os.close(fd)
            if not added:
                break
        for child, fd in pinned.items():
            if child != root:
                try:
                    signal.pidfd_send_signal(fd, signum)
                except ProcessLookupError:
                    pass
    finally:
        for fd in pinned.values():
            os.close(fd)


def _diagnose(message: str) -> None:
    """Report launch state without allowing a broken stderr to change it."""
    try:
        print(message, file=sys.stderr)
    except OSError:
        pass


class _WindowsSupervision:
    """Protect console signal delivery from admission through ownership cleanup.

    Children keep the console's direct signal delivery. After confirmed job
    completion this dedicated launcher consumes console signals through exit,
    preserving the leader's status while storage cleanup finishes.
    """

    def __enter__(self):
        import signal

        self.handlers = {}
        self.completed = False
        for name in ("SIGINT", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is not None:
                self.handlers[sig] = signal.signal(sig, signal.SIG_IGN)
        return self

    def __exit__(self, *args):
        import signal

        if not self.completed:
            for sig, handler in self.handlers.items():
                signal.signal(sig, handler)

    def wait(self, handoff):
        result = _supervise_windows(handoff)
        self.completed = True
        return result


class _Supervision:
    """One signal lifetime from admission through the caller's storage cleanup.

    Publication and fork run with termination signals blocked. During wait,
    TERM/HUP reach verified descendants; INT does so only after leader reap,
    because the foreground leader already receives terminal INT. QUIT reaches
    terminal children directly. After ECHILD, handlers consume signals until
    cleanup finishes and through this dedicated launcher's exit, preserving
    the leader's status. Refusal before fork restores pending signal delivery.
    Delivery failures never establish completion and never unwind wait.
    """

    def __enter__(self):
        import signal

        self.signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
        self.mask = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        self.handlers = {}
        self.waiting = False
        self.forwarding = False
        self.result = None
        self.completed = False
        for sig in self.signals:
            self.handlers[sig] = signal.signal(sig, self.forward)
        return self

    def forward(self, signum, frame):
        import signal

        if (not self.waiting or self.forwarding or signum == signal.SIGQUIT
                or (signum == signal.SIGINT and self.result is None)):
            return
        self.forwarding = True
        try:
            _signal_descendants(signum)
        except (OSError, ValueError):
            _diagnose("claude-swap: Could not deliver profile signal; still waiting for descendants")
        finally:
            self.forwarding = False

    def __exit__(self, *args):
        import signal

        self.waiting = False
        signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        if self.completed:
            # This dedicated launcher now owns only delivery of the leader's
            # status to its caller. Keep consuming handlers through process
            # exit: draining pending signals cannot close the unmask race.
            while signal.sigtimedwait(self.signals, 0) is not None:
                continue
        else:
            # A refusal before fork (or unconfirmed wait) is not completion.
            # Pending termination must reach the original handlers.
            for sig, handler in self.handlers.items():
                signal.signal(sig, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)

    def wait(self, handoff):
        import signal

        try:
            pid = os.fork()
        except OSError:
            _diagnose("claude-swap: Could not fork profile leader; no child launched")
            return 127
        if pid == 0:
            try:
                for sig, handler in self.handlers.items():
                    signal.signal(sig, handler)
                signal.pthread_sigmask(signal.SIG_SETMASK, set(self.mask) - set(self.signals))
                handoff()
            except BaseException:
                # Callback exceptions may contain secrets.
                os._exit(127)
            os._exit(127)
        self.waiting = True
        signal.pthread_sigmask(signal.SIG_UNBLOCK, self.signals)
        try:
            while True:
                try:
                    reaped, status = os.waitpid(-1, 0)
                except InterruptedError:
                    continue
                except ChildProcessError:
                    if self.result is None:
                        raise OSError("Profile leader completion could not be observed")
                    self.completed = True
                    return self.result
                if reaped == pid:
                    self.result = os.waitstatus_to_exitcode(status)
                    if self.result < 0:
                        self.result = 128 - self.result
        except OSError:
            _diagnose("claude-swap: Profile completion is unconfirmed; ownership remains running")
            raise
        finally:
            self.waiting = False


def owned_launch(handoff, *, publish, release, abort) -> int:
    """Admit, publish, supervise and release within one protected signal scope.

    Callbacks take their own storage locks. Before successful publication any
    failure removes only this launch's reservation. After publication only a
    proven empty tree permits release; uncertain completion retains running.
    A dedicated launcher must exit with the returned status, or with any
    propagated storage error. After proven completion it consumes termination
    through process exit; it must not resume unrelated work or launch again.
    """
    if sys.platform not in ("linux", "win32"):
        try:
            require_supervision()
        except OSError:
            _diagnose("claude-swap: Profile launch refused before fork")
            abort()
            raise
    with (_WindowsSupervision() if sys.platform == "win32" else _Supervision()) as scope:
        try:
            require_supervision()
            publish()
        except BaseException:
            _diagnose("claude-swap: Profile launch refused before fork")
            abort()
            raise
        result = scope.wait(handoff)
        try:
            release()
        except OSError:
            _diagnose("claude-swap: Could not release completed profile ownership; record retained")
            raise
        return result


def supervise(handoff) -> int:
    """Wait for a dedicated Linux or Windows launch without an ownership record.

    Profile launch callers use owned_launch so signal protection also spans
    publication and release. No unrelated children may exist in this process.
    This dedicated launcher must exit with the result, not resume other work.
    """
    with (_WindowsSupervision() if sys.platform == "win32" else _Supervision()) as scope:
        try:
            require_supervision()
        except OSError:
            if sys.platform == "win32":
                raise
            _diagnose("claude-swap: Profile subreaper/pidfd supervision unavailable; no child launched")
            return 127
        return scope.wait(handoff)

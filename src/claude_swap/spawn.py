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
import signal
import subprocess
import sys
import threading
from collections.abc import Sequence
from typing import Any

_logger = logging.getLogger("claude-swap")

_FD_DIR = "/dev/fd"
_SIGNAL_POLL_S = 0.25

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
    cmd, kwargs = _spawn_args(cmd, kwargs)
    return subprocess.run(cmd, **kwargs)


def foreground(
    cmd: Sequence[str], *, env: dict[str, str], cancel_on_interrupt: bool = False
) -> int:
    """Keep the terminal and wait for the child before the caller cleans up.

    Ctrl+C reaches both processes through their foreground group. SIGTERM
    addressed only to this process is forwarded, including during startup.
    Only the main thread can install a signal handler. An interrupted login
    cancels even if the child exits successfully; a session mirrors the
    child's status.
    """
    cmd, kwargs = _spawn_args(cmd, {"env": env})
    terminated = False

    def request_termination(_signum, _frame):
        nonlocal terminated
        terminated = True

    main_thread = threading.current_thread() is threading.main_thread()
    previous = signal.signal(signal.SIGTERM, request_termination) if main_thread else None
    # SIGTERM can land on a bridge thread while the main thread is in waitpid.
    # Wake it within 250 ms to run the Python handler; the child has no deadline.
    timeout = _SIGNAL_POLL_S if main_thread and os.name == "posix" else None
    try:
        process = subprocess.Popen(cmd, **kwargs)
        forwarded = interrupted = False
        while True:
            if terminated and not forwarded:
                process.send_signal(signal.SIGTERM)
                forwarded = True
            try:
                returncode = process.wait(timeout=timeout)
                break
            except subprocess.TimeoutExpired:
                continue
            except KeyboardInterrupt:
                interrupted = True
        if cancel_on_interrupt:
            if interrupted:
                raise KeyboardInterrupt
            if terminated and returncode == 0:
                return -signal.SIGTERM
        return returncode
    finally:
        if main_thread:
            signal.signal(signal.SIGTERM, previous)


def _spawn_args(
    cmd: Sequence[str], kwargs: dict[str, Any]
) -> tuple[Sequence[str], dict[str, Any]]:
    if _spawn_path_applies(cmd, kwargs):
        executable = _resolve(cmd[0], kwargs.get("env"))
        if executable is not None and not _inheritable_fds_above_stdio():
            return [executable, *cmd[1:]], {"close_fds": False, **kwargs}
    return cmd, kwargs


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

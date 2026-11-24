"""The one Claude Code lookup and launch path.

On POSIX, PATH search ignores the client cwd, relative entries, writable
directory chains and our own shim. Until PR1, Windows sessions and auth probes
use the legacy shutil.which lookup without strict path-chain checks; installing
the Windows shim remains disabled. Windows compares handle-based identities
at resolution, on the pinned file, and on the named entry before spawning.
POSIX uses descriptor-based exec for native executables when supported.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from claude_swap import fsguard, paths, spawn
from claude_swap.exceptions import ClaudeSwitchError, SessionError

if TYPE_CHECKING:
    from claude_swap._win_file_security import ExecutableIdentity

SHIM_MARKER = "# claude-swap transparent shim"
SHIM_METADATA = ".cswap-shim.json"


class ResolveError(SessionError):
    """No trustworthy Claude executable is available, or it changed."""


def _hash(stream) -> str:
    return hashlib.file_digest(stream, "sha256").hexdigest()


def is_shim(path: Path | str) -> bool:
    """Recognize copied POSIX shims and Windows shims with their manifest."""
    path = Path(path)
    try:
        path = path.resolve(strict=True)
        if not path.is_file():
            return False
        with path.open("rb") as stream:
            header = stream.read(256)
            if SHIM_MARKER.encode("ascii") in header.splitlines():
                return True
            # A launcher manifest also marks a binary copied separately
            # into this directory under a different name.
            metadata = path.parent / SHIM_METADATA
            if header[:2] != b"MZ" or not metadata.is_file():
                return False
            try:
                with metadata.open(encoding="utf-8") as manifest:
                    expected = json.load(manifest)["sha256"]
            except (ValueError, TypeError, KeyError):
                return False
            stream.seek(0)
            return _hash(stream) == expected
    except (OSError, RuntimeError):
        return False


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass
class RealClaude:
    """The resolved file, not the PATH entry or symlink that located it."""

    path: Path
    _identity: tuple[int, ...] | ExecutableIdentity
    _digest: str | None = field(default=None, init=False, repr=False)

    def _verify(self, identity: tuple[int, ...] | ExecutableIdentity, checkpoint: str) -> None:
        if sys.platform == "win32":
            for name, before, after in zip(self._identity._fields, self._identity, identity):
                if before is not None and before != after:
                    raise ResolveError(
                        f"Claude executable changed after resolution ({checkpoint}:{name})"
                    )
        elif self._identity != identity:
            raise ResolveError(f"Claude executable changed after resolution: {self.path}")

    def _verify_path(self, checkpoint: str) -> None:
        if sys.platform == "win32":
            from claude_swap._win_file_security import executable_identity_at_path

            self._verify(executable_identity_at_path(self.path), checkpoint)
        else:
            self._verify(_identity(self.path.lstat()), checkpoint)

    def _verify_fd(self, fd: int, checkpoint: str) -> None:
        if sys.platform == "win32":
            from claude_swap._win_file_security import executable_identity_at_fd

            self._verify(executable_identity_at_fd(fd), checkpoint)
        else:
            self._verify(_identity(os.fstat(fd)), checkpoint)

    def _use_digest_cache(self) -> bool:
        return sys.platform != "win32" or self._identity.change_time is not None

    def _open(self):
        if sys.platform != "win32":
            try:
                checked = fsguard.check_path(self.path)
            except fsguard.GuardError as exc:
                raise ResolveError(f"Claude executable changed after resolution: {exc}") from exc
            if checked != self.path:
                raise ResolveError(f"Claude executable changed after resolution: {self.path}")
        if sys.platform == "win32":
            from claude_swap._win_file_security import open_executable

            fd = open_executable(self.path)
        else:
            # Don't follow a swapped-in symlink or block on a FIFO.
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        stream = os.fdopen(fd, "rb")
        try:
            self._verify_fd(fd, "opened-fd")
        except BaseException:
            stream.close()
            raise
        return stream

    def fingerprint(self) -> str:
        """Hash the checked object; never cache when Windows ChangeTime is absent."""
        with self._open() as stream:
            if self._digest is not None and self._use_digest_cache():
                return self._digest
            digest = _hash(stream)
            self._verify_fd(stream.fileno(), "after-hash")
            if self._digest is not None and self._digest != digest:
                if sys.platform == "win32":
                    raise ResolveError("Claude executable changed after resolution (after-hash:digest)")
                raise ResolveError(f"Claude executable changed after resolution: {self.path}")
            self._digest = digest
            return digest

    def _check_fingerprint(self, stream) -> None:
        if not self._use_digest_cache() and self._digest is not None:
            if _hash(stream) != self._digest:
                raise ResolveError("Claude executable changed after resolution (before-launch:digest)")
            stream.seek(0)
        self._verify_fd(stream.fileno(), "before-launch-fd")

    def handoff(self, args: Sequence[str], env: dict[str, str], *, job: bool = False) -> NoReturn:
        if job:
            spawn.ensure_windows_job()
        with self._open() as stream:
            self._check_fingerprint(stream)
            # A shebang interpreter may need to reopen the script by filename.
            if sys.platform != "win32" and os.execve in os.supports_fd and stream.read(2) != b"#!":
                spawn.handoff(str(self.path), args, env, fd=stream.fileno())
            self._verify_path("before-launch-path")
            spawn.handoff(str(self.path), args, env)

    def run(self, args: Sequence[str], **kwargs: Any):
        """Run a probe without handing over the caller's terminal."""
        with self._open() as stream:
            self._check_fingerprint(stream)
            self._verify_path("before-launch-path")
            return spawn.run([str(self.path), *args], **kwargs)


def _candidate(path: Path, shim: Path, *, cwd: Path | None = None) -> RealClaude:
    if not path.is_absolute():
        raise ResolveError(f"Not an absolute path: {path}")
    checked = path.resolve(strict=True) if sys.platform == "win32" else fsguard.check_path(path)
    if checked.parent == cwd:
        raise ResolveError(f"Claude candidate is in the current directory: {path}")
    info = checked.lstat()
    if not stat.S_ISREG(info.st_mode) or (
        sys.platform != "win32" and not os.access(checked, os.X_OK)
    ):
        raise ResolveError(f"Claude candidate is not an executable file: {path}")
    if sys.platform == "win32":
        from claude_swap._win_file_security import executable_identity_at_path

        identity = executable_identity_at_path(checked)
        if identity.attributes & (stat.FILE_ATTRIBUTE_DIRECTORY | stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ResolveError("Claude executable changed after resolution (resolved-path:attributes)")
    else:
        identity = _identity(info)
    try:
        same_as_shim = checked.samefile(shim)
    except FileNotFoundError:
        same_as_shim = False
    if same_as_shim or is_shim(checked):
        raise ResolveError(f"Claude candidate resolves to the cswap shim: {path}")
    candidate = RealClaude(checked, identity)
    candidate._verify_path("resolved-path")
    return candidate


def path_command(path: str | None = None) -> Path | None:
    """Show the hit in this PATH, even if the resolver would not trust it."""
    if sys.platform == "win32":
        found = shutil.which("claude", path=path)
        return Path(found).absolute() if found is not None else None
    if path is None:
        path = os.environ.get("PATH", os.defpath)
    for entry in path.split(os.pathsep):
        candidate = Path(entry) / "claude"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.absolute()
    return None


def resolve(
    *, backup_root: Path | None = None, configured_path: Path | str | None = None,
    path: str | None = None, skipped: list[str] | None = None,
) -> RealClaude:
    """Resolve an override or search PATH once, filling optional diagnostics."""
    from claude_swap.settings import load_transparent_settings

    if backup_root is None:
        backup_root = paths.get_backup_root()
    if configured_path is None:
        try:
            configured_path = load_transparent_settings(backup_root).claude_path
        except ClaudeSwitchError as exc:
            raise ResolveError(str(exc)) from exc
    shim_dir = paths.get_shim_dir(backup_root)
    shim = shim_dir / ("claude.exe" if sys.platform == "win32" else "claude")
    try:
        shim_dir = shim_dir.resolve()
        shim = shim.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ResolveError(f"Could not resolve cswap shim path: {shim}") from exc
    try:
        cwd = Path.cwd().resolve()
    except (OSError, RuntimeError) as exc:
        raise ResolveError("Could not verify the current directory for Claude lookup") from exc
    if configured_path is not None:
        try:
            configured = Path(configured_path)
            if configured.is_absolute() and configured.parent.resolve() == cwd:
                raise ResolveError(f"Claude candidate is in the current directory: {configured}")
            return _candidate(configured, shim, cwd=cwd)
        except (OSError, RuntimeError, ValueError, fsguard.GuardError, ResolveError) as exc:
            raise ResolveError(f"transparent.claudePath: {exc}") from exc

    first_rejected = None
    if sys.platform == "win32":
        candidate = path_command(path)
        if candidate is not None:
            try:
                return _candidate(candidate, shim)
            except (OSError, RuntimeError, ValueError, ResolveError) as exc:
                first_rejected = f"{candidate}: {exc}"
                if skipped is not None:
                    skipped.append(first_rejected)
    else:
        if path is None:
            path = os.environ.get("PATH", os.defpath)
        for entry in path.split(os.pathsep):
            directory = Path(entry)
            try:
                if not directory.is_absolute():
                    raise ResolveError("empty or relative PATH entry")
                checked = fsguard.check_path(directory)
                if checked == cwd:
                    raise ResolveError("current directory")
                if not checked.is_dir():
                    raise ResolveError("not a directory")
                if checked == shim_dir:
                    continue
            except (OSError, ValueError, fsguard.GuardError, ResolveError) as exc:
                if skipped is not None:
                    skipped.append(f"{entry or '(empty)'}: {exc}")
                # An unusable PATH directory alone does not mean Claude was found.
                if first_rejected is None and directory.is_absolute():
                    rejected = directory / "claude"
                    try:
                        rejected.lstat()
                    except (OSError, ValueError):
                        pass
                    else:
                        first_rejected = f"{rejected}: {exc}"
                continue
            try:
                candidate = checked / "claude"
                candidate.lstat()
                return _candidate(candidate, shim, cwd=cwd)
            except FileNotFoundError:
                continue
            except (OSError, ValueError, fsguard.GuardError, ResolveError) as exc:
                diagnostic = f"{candidate}: {exc}"
                if first_rejected is None:
                    first_rejected = diagnostic
                if skipped is not None:
                    skipped.append(diagnostic)
    if first_rejected is not None:
        raise ResolveError(f"Claude candidate rejected: {first_rejected}")
    raise ResolveError("Real 'claude' was not found on PATH. Install Claude Code or set transparent.claudePath.")

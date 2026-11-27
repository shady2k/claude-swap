"""The thin ``claude`` wrapper: launch the recorded active account.

``cswap wrapper`` prints the path of the shipped script (``scripts/claude``).
A symlink to it in a directory ahead of the real Claude Code in ``PATH`` makes
every ``claude``, ``claude --resume`` included, run

    cswap run --active -- "$@"

so the slot recorded in ``sequence.json`` (``cswap switch``) is started in its
own session profile with its own proxy, and the global ``~/.claude`` login is
never read, written or switched. What a user sees is in
``docs/auto-launch.md``.

The script resolves nothing and searches nothing: it checks that ``cswap`` is
on ``PATH`` and replaces itself with ``cswap run --active -- "$@"``. Finding
the real Claude Code is ``session.find_claude``'s single job, so there is one
answer to "which binary is Claude Code" and it cannot disagree with itself.
Its ``--version``/``-v``/``--help``/``-h`` passthrough uses the same rule, so
a caller asking which version is installed gets an answer without an account.

One rule keeps the two from handing the terminal to each other in a loop:
``find_claude`` never returns this file. Started as ``cswap run 3`` with the
wrapper on ``PATH``, it walks ``PATH`` past the wrapper to the real binary, so
an explicit account is not replaced by the wrapper's own launch, and the
``claude auth status`` probe does not become a second cswap. :func:`is_wrapper`
recognises the script by a marker line in its first kilobytes — cheap on a
377 MB binary, and still true of an edited copy or another version.

Installation owns a symlink and a marked PATH block for its directory.
Profile edits preserve the original bytes outside the block and follow a
symlinked profile. The cached list of custom directories lets status find the
wrapper before PATH is updated. A lock serializes CLI and TUI setup changes.

With no ``--dir`` the installer prefers ``~/.local/bin`` when that directory
already comes before the real Claude Code on ``PATH`` and its ``claude`` is
free: the symlink is active in the running session and visible to background
services and IDEs that never read a shell profile, and no profile is edited.
A shell that already resolved the real ``claude`` keeps it cached until
``hash -r`` (Bash) or ``rehash`` (Zsh), so the message names the one for
``$SHELL``. Every other case falls back to the private
``~/.local/claude-swap/bin`` and the marked profile block, which is what an
install always did.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from claude_swap import paths
from claude_swap.exceptions import ConfigError
from claude_swap.fsutil import atomic_write_bytes, atomic_write_text
from claude_swap.locking import FileLock

#: The shipped script. ``cswap wrapper`` prints this; the wheel carries it.
WRAPPER_PATH = Path(__file__).with_name("scripts") / "claude"

#: The line that makes a file this wrapper, scanned for in its head only.
MARKER = b"# claude-swap thin wrapper"

#: How much of a candidate is read: the marker is in the first line, and a
#: binary the size of Claude Code must never be read whole (measured: 0.21 s
#: and 391 MiB for 377 MB, per check).
HEAD_BYTES = 4096

INSTALL_HINT = "Run cswap wrapper install to launch the active account with 'claude'."
UNSUPPORTED = "The Claude wrapper is available on Linux and macOS only."

_PROFILES = {
    "bash": ".bashrc",
    "zsh": ".zshrc",
    "fish": ".config/fish/config.fish",
}
_BLOCK_START = b"# >>> claude-swap wrapper "
_BLOCK_END = b"# <<< claude-swap wrapper\n"
_BLOCK = re.compile(
    rb"^" + re.escape(_BLOCK_START) + rb"(.+)\n[^\n]*\n" + re.escape(_BLOCK_END),
    re.MULTILINE,
)


def is_wrapper(path: str | os.PathLike[str]) -> bool:
    """Whether ``path`` is this shipped wrapper, symlinked, copied or edited.

    The marker line is what it is recognised by, not the bytes of the shipped
    file, so a copy someone adjusted (a different install directory in its
    comment, a newer version of the script) is still known to be a wrapper and
    is still never launched as Claude Code. Anything unreadable is not the
    wrapper: a broken path must not be walked past as if it were our own
    script.
    """
    try:
        if not os.path.isfile(path):
            return False
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError:
        return False
    return MARKER in head


def supported() -> bool:
    return sys.platform in ("linux", "darwin")


def _preferred_directory() -> Path:
    """The user directory that is usually on PATH ahead of an installed tool."""
    return Path.home() / ".local" / "bin"


def _fallback_directory() -> Path:
    """The private directory an install falls back to."""
    return Path.home() / ".local" / "claude-swap" / "bin"


def _standard_directories() -> tuple[Path, Path]:
    """Both places an install without ``--dir`` may put the wrapper."""
    return (_preferred_directory(), _fallback_directory())


def _directory(directory: str | Path | None = None) -> Path:
    if directory is None:
        return _fallback_directory()
    if not directory:
        raise ConfigError("Provide a directory after --dir.")
    try:
        return Path(directory).expanduser().absolute()
    except RuntimeError as exc:
        raise ConfigError(f"Could not expand wrapper directory {directory}.") from exc


def _path_dirs() -> list[Path]:
    # An empty PATH searches nothing. ``os.get_exec_path`` answers it with
    # ``[""]``, which would become the current directory: a wrapper in the
    # directory cswap happens to run in would look installed.
    if os.environ.get("PATH") == "":
        return []
    return [Path(os.path.expanduser(entry)) for entry in os.get_exec_path()]


def _same_directory(left: Path, right: Path) -> bool:
    """Whether ``left`` is the directory ``right``.

    ``os.path.samefile`` raises when either side cannot be stat'ed: a PATH
    entry below a plain file (``ENOTDIR``), a directory we may not enter,
    a looping symlink. Such an entry is not this directory, so the answer is
    ``False``. ``fsutil.same_path`` is not used here because it answers
    ``True`` on an unreadable path, which would skip the profile edit for a
    directory that is not on PATH at all.
    """
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _directory_index(directory: Path, dirs: list[Path]) -> int | None:
    """The first ``dirs`` entry that is ``directory``, following symlinks."""
    canonical = os.path.realpath(directory)
    for index, entry in enumerate(dirs):
        if os.path.realpath(entry) == canonical or _same_directory(entry, directory):
            return index
    return None


def _first_real_index(dirs: list[Path]) -> int | None:
    """The first ``dirs`` entry whose ``claude`` is a real binary, not ours."""
    for index, entry in enumerate(dirs):
        candidate = entry / "claude"
        if (
            os.path.isfile(candidate)
            and os.access(candidate, os.X_OK)
            and not is_wrapper(candidate)
        ):
            return index
    return None


def _can_create(directory: Path) -> bool:
    """Whether ``directory`` can be created, or written to when it exists.

    ``lexists`` asks whether the name is taken, which is what ``mkdir`` runs
    into: a symlink to a removed directory is not a directory and cannot be
    written or created at, so it must not be mistaken for a missing path.
    """
    if os.path.lexists(directory):
        return os.path.isdir(directory) and os.access(directory, os.W_OK | os.X_OK)
    parent = directory.parent
    while not os.path.lexists(parent) and parent != parent.parent:
        parent = parent.parent
    return os.path.isdir(parent) and os.access(parent, os.W_OK | os.X_OK)


def _preferred_fits() -> bool:
    """Whether ``~/.local/bin`` can take the wrapper ahead of the real claude.

    A directory that is not on ``PATH``, comes after the first real ``claude``
    there, cannot be written, or already holds someone else's ``claude`` would
    make the install inactive, destructive, or both, so it is not chosen.
    Toolchain and virtualenv directories on ``PATH`` are never considered:
    ``~/.local/bin`` is the one default, which keeps ``status`` and
    ``uninstall`` predictable.
    """
    directory = _preferred_directory()
    target = directory / "claude"
    if os.path.lexists(target) and not is_wrapper(target):
        return False
    dirs = _path_dirs()
    index = _directory_index(directory, dirs)
    if index is None or not _can_create(directory):
        return False
    first_real = _first_real_index(dirs)
    return first_real is None or index < first_real


def needs_setup(*, for_add: bool = False) -> bool:
    """Whether to suggest setup in text status or after a successful add.

    The prompt after ``add`` is about the standard install only. A wrapper
    someone put in a custom ``--dir`` that is not on ``PATH`` yet still
    leaves ``claude`` resolving elsewhere, so it does not suppress the
    suggestion.
    """
    if not supported():
        return False
    if for_add and any(
        is_wrapper(directory / "claude") for directory in _standard_directories()
    ):
        return False
    command = shutil.which("claude")
    return command is None or not is_wrapper(command)


@dataclass(frozen=True)
class WrapperStatus:
    installed: Path | None
    command: str | None
    real: str | None
    active: bool

    @property
    def summary(self) -> str:
        if self.installed:
            return f"Installed at {self.installed}"
        return "Wrapper is not installed"

    @property
    def path_summary(self) -> str:
        if self.command is None:
            return "Inactive in PATH (claude not found)"
        state = "Active in PATH" if self.active else "Inactive in PATH"
        return f"{state} (claude resolves to {self.command})"


def status() -> WrapperStatus:
    """Find an installation in PATH, the default location or a custom directory."""
    from claude_swap.session import find_claude

    command = shutil.which("claude")
    active = command is not None and is_wrapper(command)
    installed = Path(command).absolute() if active else _installed_path()
    return WrapperStatus(installed, command, find_claude(), active)


def _installed_path() -> Path | None:
    for directory in (*_standard_directories(), *_path_dirs()):
        target = directory.absolute() / "claude"
        if is_wrapper(target):
            return target
    try:
        directories = _read_custom_dirs(_cache_dir() / "wrapper-dirs.json")
    except OSError:
        return None
    for directory in sorted(directories):
        target = Path(directory) / "claude"
        if is_wrapper(target):
            return target
    return None


def _cache_dir() -> Path:
    return paths.get_backup_root() / "cache"


def _read_custom_dirs(registry: Path) -> set[str]:
    try:
        dirs = json.loads(registry.read_bytes())
    except (FileNotFoundError, ValueError):
        return set()
    if not isinstance(dirs, list):
        return set()
    return {directory for directory in dirs
            if isinstance(directory, str) and os.path.isabs(directory)}


def _record_custom_dir(directory: Path, *, installed: bool) -> None:
    registry = _cache_dir() / "wrapper-dirs.json"
    dirs = _read_custom_dirs(registry)
    key = os.path.realpath(directory)
    if (key in dirs) == installed:
        return
    if installed:
        dirs.add(key)
    else:
        dirs.remove(key)
    atomic_write_text(registry, json.dumps(sorted(dirs)) + "\n")


def _read_profile(profile: Path) -> bytes:
    if profile.is_file():
        return profile.read_bytes()
    if os.path.lexists(profile):
        raise OSError(f"Shell profile {profile} is not a regular file.")
    return b""


def _write_profile(profile: Path, content: bytes) -> None:
    mode = stat.S_IMODE(profile.stat().st_mode) if profile.is_file() else 0o600
    profile.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(profile, content, mode=mode)


def _path_line(directory: Path, shell: str) -> str:
    if shell == "fish":
        quoted = str(directory).replace("\\", "\\\\").replace("'", "\\'")
        return f"set -gx PATH '{quoted}' $PATH"
    return f'export PATH={shlex.quote(str(directory))}:"$PATH"'


def _block_key(directory: Path) -> bytes:
    return json.dumps(os.path.realpath(directory)).encode("ascii")


def _edit_profile(profile: Path, directory: Path, *, shell: str | None = None) -> bool:
    """Add a block for this directory, or remove it when no shell is given."""
    content = _read_profile(profile)
    key = _block_key(directory)
    match = next((m for m in _BLOCK.finditer(content) if m[1] == key), None)
    if shell is not None and match is None:
        line = os.fsencode(_path_line(directory, shell))
        edited = content + b"\n" + _BLOCK_START + key + b"\n" + line + b"\n" + _BLOCK_END
    elif shell is None and match is not None:
        before, after = content[:match.start()], content[match.end():]
        # Keep a line break if the user appended text to an originally
        # unterminated line. Otherwise remove the block's leading separator.
        if (
            before == b"\n" or before.endswith(b"\n\n")
            or not after or after.startswith(b"\n")
        ):
            before = before.removesuffix(b"\n")
        edited = before + after
    else:
        return False
    _write_profile(profile, edited)
    return True


def _target_exists(target: Path) -> bool:
    if not os.path.lexists(target):
        return False
    if not is_wrapper(target):
        raise ConfigError(f"Refusing to change {target}: it is not a claude-swap wrapper.")
    return True


def _install_lock() -> FileLock:
    return FileLock(_cache_dir() / "wrapper-install.lock")


def _remove_blocks(directory: Path) -> bool:
    """Remove this directory's marked PATH block from every known profile."""
    removed = False
    for relative in _PROFILES.values():
        profile = Path.home() / relative
        if profile.is_file() and _edit_profile(profile, directory):
            removed = True
    return removed


def install(directory: str | Path | None = None) -> str:
    """Install the launcher after checking its destination and the real binary.

    Without ``--dir`` the wrapper goes into ``~/.local/bin`` when that
    directory already comes before the real Claude Code on ``PATH``, so it is
    active in the running session and visible to services that never read a
    shell profile. Otherwise the private directory and its marked profile
    block are used, as before. An explicit ``--dir`` is never second-guessed.
    """
    from claude_swap.session import find_claude

    if not supported():
        raise ConfigError(UNSUPPORTED)
    with _install_lock():
        if find_claude() is None:
            raise ConfigError(
                "The real Claude Code binary was not found. Put it on PATH "
                "or set CSWAP_CLAUDE_BIN to its executable."
            )
        smart = directory is None and _preferred_fits()
        target = (
            _preferred_directory() if smart else _directory(directory)
        ) / "claude"
        exists = _target_exists(target)
        if any(char in str(target.parent) for char in (os.pathsep, "\n", "\r")):
            raise ConfigError(
                "The wrapper directory cannot contain a PATH separator or line break."
            )
        if exists and not os.access(target, os.X_OK):
            raise ConfigError(f"The existing wrapper at {target} is not executable.")

        shell = Path(os.environ.get("SHELL", "")).name
        profile = _PROFILES.get(shell)
        canonical = os.path.realpath(target.parent)
        on_path = any(
            os.path.realpath(entry) == canonical or _same_directory(entry, target.parent)
            for entry in _path_dirs()
        )
        # ~/.local/bin needs no banner and no profile line: it is already on
        # PATH and it is what background services see.
        manage_path = not smart and (directory is None or not on_path)
        if not exists and not (WRAPPER_PATH.is_file() and os.access(WRAPPER_PATH, os.X_OK)):
            raise ConfigError(f"The shipped wrapper is not executable at {WRAPPER_PATH}.")
        if directory is not None:
            # A record alone has no effect: status also checks the launcher.
            _record_custom_dir(target.parent, installed=True)
        if not exists:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(WRAPPER_PATH)
        try:
            if manage_path and profile is not None:
                _edit_profile(Path.home() / profile, target.parent, shell=shell)
        except OSError:
            if not exists and is_wrapper(target):
                target.unlink()
            raise

    message = f"Installed at {target}."
    if smart:
        # The shell keeps the path it resolved a command to. A `claude` run
        # before this install is still the real binary until the cache is
        # dropped, even though `claude` now resolves to the wrapper.
        reset = {"bash": "hash -r", "zsh": "rehash"}.get(shell)
        if reset is not None:
            message += f" If you already ran 'claude' in this shell, run '{reset}'."
    if manage_path and profile is None:
        return f"{message} Add this to your shell's PATH setup: {_path_line(target.parent, shell)}"
    if needs_setup():
        if manage_path and profile is not None:
            message += f" Open a new shell or source ~/{profile} to update PATH."
        else:
            message += f" Place {target.parent} before Claude Code in PATH."
    if manage_path and profile is not None:
        message += (
            " Background services and IDEs that do not read your shell profile"
            f" see the wrapper only when {target.parent} is on their PATH."
        )
    return message


def uninstall(directory: str | Path | None = None) -> str:
    """Remove the owned launcher and the PATH blocks the installer added.

    Without ``--dir`` both standard directories are checked, so the wrapper is
    removed wherever ``install`` put it. A real or foreign ``claude`` in the
    other directory is left alone and is not an error: nothing of ours is
    there to remove. An explicit ``--dir`` keeps the strict refusal.
    """
    if not supported():
        raise ConfigError(UNSUPPORTED)
    if directory is not None:
        target = _directory(directory) / "claude"
        with _install_lock():
            exists = _target_exists(target)
            removed_block = _remove_blocks(target.parent)
            if exists:
                target.unlink()
            _record_custom_dir(target.parent, installed=False)
        if exists or removed_block:
            return f"Removed wrapper setup for {target}."
        return f"Wrapper is not installed at {target}."

    directories = _standard_directories()
    with _install_lock():
        removed = []
        for candidate in directories:
            target = candidate / "claude"
            # One standard directory may be a symlink to the other, which
            # makes both paths the same file: check it is still ours right
            # before removing it, so the second pass is a no-op instead of
            # an error that would skip the profile cleanup.
            if is_wrapper(target):
                target.unlink()
                removed.append(target)
        removed_block = False
        for candidate in directories:
            removed_block = _remove_blocks(candidate) or removed_block
    if removed:
        return "Removed wrapper setup for " + ", ".join(str(path) for path in removed) + "."
    if removed_block:
        return f"Removed wrapper setup for {_fallback_directory() / 'claude'}."
    return f"Wrapper is not installed at {_fallback_directory() / 'claude'}."

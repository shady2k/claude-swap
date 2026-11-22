"""Install and run the PATH shim without changing Claude's installation.

Only the synthetic test route has a pinned layer here. No real build is
admitted without the version-specific routing and login evidence from PR3.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
import time
from pathlib import Path

from claude_swap import __version__, claude_forms, fsguard, paths, real_claude, test_mode
from claude_swap.exceptions import ClaudeSwitchError, ConfigError
from claude_swap.fsutil import atomic_write_bytes
from claude_swap.locking import FileLock
from claude_swap.python_chain import LOADER_VARS, check_python_chain
from claude_swap.settings import load_transparent_settings

_BYPASS = "CLAUDE_SWAP_BYPASS"
_OUTSIDE = "launch outside the profile route"
_DAY = 86400


def _launcher(directory: Path) -> Path:
    return directory / ("claude.exe" if sys.platform == "win32" else "claude")


def _invocation_marker(directory: Path, strict: bool) -> str:
    return f"--cswap-shim={int(strict)}:{directory}"


def _script(interpreter: Path, directory: Path, strict: bool) -> bytes:
    check = " || ".join(f'[ "${{{key}+x}}" = x ]' for key in LOADER_VARS)
    refuse = "printf '%s\\n' 'claude-swap: loader environment is forbidden' >&2; exit 4"
    warn = "printf '%s\\n' 'claude-swap: loader environment is set; outside the profile route' >&2"
    response = refuse if strict else f'if [ "${{{test_mode.MODE}:-}}" = 1 ]; then {refuse}; else {warn}; fi'
    invocation = shlex.quote(_invocation_marker(directory, strict))
    return (
        f"#!/bin/sh\n{real_claude.SHIM_MARKER}\n"
        f"if {check}; then {response}; fi\n"
        f'exec {shlex.quote(str(interpreter))} -I -m claude_swap.transparent {invocation} "$@"\n'
    ).encode()

def _metadata(directory: Path) -> dict | None:
    path = directory / real_claude.SHIM_METADATA
    if not os.path.lexists(path):
        return None
    fsguard.check_path(path)
    try:
        data = json.loads(path.read_bytes())
        if not isinstance(data, dict) or not isinstance(data["sha256"], str):
            raise ValueError
        return data
    except (ValueError, KeyError) as exc:
        raise ConfigError("Invalid shim metadata; check the shim directory before enabling") from exc


def _owned(directory: Path, metadata: dict | None) -> bool:
    target = _launcher(directory)
    if not os.path.lexists(target):
        return False
    if not target.is_file() or target.is_symlink() or not metadata:
        raise ConfigError(f"Not a claude-swap installed shim: {target}")
    fsguard.check_path(target)
    if not real_claude.is_shim(target):
        raise ConfigError(f"Not a claude-swap installed shim: {target}")
    if hashlib.sha256(target.read_bytes()).hexdigest() != metadata["sha256"]:
        raise ConfigError(f"Shim contents do not match the installation: {target}")
    return True


def _make_dir(directory: Path) -> None:
    # Check existing ancestors before writing anything beneath them.
    for parent in (directory, *directory.parents):
        if os.path.lexists(parent):
            fsguard.check_path(parent)
            break
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fsguard.check_path(directory)


def enable(backup_root: Path) -> Path:
    if sys.platform == "win32":
        raise ConfigError("No isolated, cancellable Windows shim launcher has been verified (PR1)")
    settings = load_transparent_settings(backup_root)
    interpreter = check_python_chain()
    directory = paths.get_shim_dir(backup_root)
    script = _script(interpreter, directory, settings.require_proxy)
    _make_dir(directory)
    with FileLock(directory / "install.lock"):
        previous = _metadata(directory)
        target = _launcher(directory)
        original = target.read_bytes() if _owned(directory, previous) else None
        metadata = {
            "sha256": hashlib.sha256(script).hexdigest(),
            "interpreter": str(interpreter),
            "version": __version__,
            "requireProxy": settings.require_proxy,
        }
        atomic_write_bytes(target, script, mode=0o700, follow_symlinks=False)
        try:
            atomic_write_bytes(directory / real_claude.SHIM_METADATA, json.dumps(metadata).encode(),
                               follow_symlinks=False)
        except OSError:
            if original is None:
                target.unlink()
            else:
                atomic_write_bytes(target, original, mode=0o700, follow_symlinks=False)
            raise
    return directory


def disable(backup_root: Path) -> None:
    directory = paths.get_shim_dir(backup_root)
    if not os.path.lexists(directory):
        return
    fsguard.check_path(directory)
    with FileLock(directory / "install.lock"):
        metadata = _metadata(directory)
        if _owned(directory, metadata):
            _launcher(directory).unlink()
        if metadata:
            (directory / real_claude.SHIM_METADATA).unlink()


def _installed(directory: Path, strict: bool) -> bool:
    fsguard.check_path(directory)
    metadata = _metadata(directory)
    if not _owned(directory, metadata):
        return False
    interpreter = check_python_chain()
    if (
        metadata.get("version") != __version__ or metadata.get("interpreter") != str(interpreter)
        or metadata.get("requireProxy") is not strict
        or (sys.platform != "win32" and _launcher(directory).read_bytes() != _script(interpreter, directory, strict))
    ):
        raise ConfigError("Shim policy, interpreter or version changed; run cswap transparent enable")
    return True


def _journal(directory: Path, event: str | None = None) -> int:
    fsguard.check_path(directory)
    file = directory / "launches.json"
    now = int(time.time())
    with FileLock(directory / "journal.lock"):
        try:
            if os.path.lexists(file):
                fsguard.check_path(file)
            rows = json.loads(file.read_bytes())
        except FileNotFoundError:
            rows = []
        except (ValueError, UnicodeError) as exc:
            raise ConfigError("Invalid shim launch journal") from exc
        if not isinstance(rows, list) or any(
            not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int
            or row[1] not in ("launch", _OUTSIDE) for row in rows
        ):
            raise ConfigError("Invalid shim launch journal")
        rows = [row for row in rows if now - _DAY <= row[0] <= now]
        if event is not None:
            rows.append([now, event])
            atomic_write_bytes(file, json.dumps(rows).encode(), follow_symlinks=False)
        return len(rows)


def status(backup_root: Path) -> list[str]:
    directory = paths.get_shim_dir(backup_root)
    command = real_claude.path_command()
    lines = [f"Claude for this PATH: {command or '(not found)'}"]
    try:
        policy = load_transparent_settings(backup_root)
        installed = _installed(directory, policy.require_proxy) if os.path.lexists(directory) else False
        active = installed and command is not None and command.resolve() == _launcher(directory).resolve()
        lines.append(f"Shim: {'first on PATH' if active else 'installed, not first on PATH' if installed else 'disabled'}")
    except (ClaudeSwitchError, OSError) as exc:
        lines.append(f"Shim not verified: {exc}; run cswap transparent enable")
    skipped: list[str] = []
    try:
        real = real_claude.resolve(backup_root=backup_root, skipped=skipped)
        lines.append(f"Original Claude (absolute path bypasses shim): {real.path}")
    except ClaudeSwitchError as exc:
        lines.append(str(exc))
    lines.extend(f"Skipped PATH: {entry}" for entry in skipped)
    if sys.platform == "win32":
        lines.append("A client's application directory or working directory may precede PATH.")
    if os.path.lexists(directory):
        try:
            lines.append(f"Shim launches (last 24 hours): {_journal(directory)}")
        except (ClaudeSwitchError, OSError) as exc:
            lines.append(f"Shim launch count unavailable: {exc}")
    else:
        lines.append("Shim launches (last 24 hours): 0")
    return lines


def refresh_install(backup_root: Path) -> None:
    """Rewrite the shell's loader policy when an installed shim changes mode."""
    if os.path.lexists(_launcher(paths.get_shim_dir(backup_root))):
        enable(backup_root)


def _test_layer(directory: Path, args: list[str], env: dict[str, str]):
    pinned, child = test_mode.pinned_launch(args, env)
    content = pinned[1].encode()
    # Keep the file readable for the whole handoff, including later reloads.
    layers = directory / "test-layers"
    _make_dir(layers)
    layer = layers / (hashlib.sha256(content).hexdigest() + ".json")
    atomic_write_bytes(layer, content, follow_symlinks=False)
    return ["--settings", str(layer), *args], child


def _launch(marker: str, args: list[str], root: Path) -> None:
    test = test_mode.active()
    real = test_mode.check_launch(args, backup_root=root) if test else None
    settings = load_transparent_settings(root)
    directory = paths.get_shim_dir(root)
    if (
        marker != _invocation_marker(directory, settings.require_proxy)
        or not sys.flags.isolated or not _installed(directory, settings.require_proxy)
    ):
        raise ConfigError("Shim is not installed, isolated or current; run cswap transparent enable")
    if settings.require_proxy and any(key in os.environ for key in LOADER_VARS):
        raise ConfigError("loader environment is forbidden in strict mode")
    env = os.environ.copy()
    bypass = env.pop(_BYPASS, None)
    if bypass is not None and settings.require_proxy:
        raise ConfigError(f"{_BYPASS}: forbidden in strict mode")
    reason = _BYPASS if bypass == "1" else None
    if reason is None:
        form = claude_forms.classify(args)
        if form.error:
            raise ConfigError(form.error)
        reason = form.bypass_reason
        if reason and settings.require_proxy:
            raise ConfigError(f"{reason}; see cswap transparent status for the absolute path")
    if test:
        args, env = _test_layer(directory, args, env)
        event = "launch"
    else:
        if not reason:
            if settings.require_proxy or not settings.allow_unverified:
                raise ConfigError("No Claude build admitted for profile routing (PR3); see cswap transparent status")
            reason = "unverified Claude build"
        real = real_claude.resolve(backup_root=root)
        print(f"claude-swap: {_OUTSIDE}: {reason}", file=sys.stderr)
        event = _OUTSIDE
    env["CLAUDE_SWAP_LAUNCHED"] = str(os.getpid())
    _journal(directory, event)
    real.handoff(args, env, job=True)


def main() -> None:
    try:
        invocation = sys.argv[1:]
        marker = invocation.pop(0) if invocation else ""
        _launch(marker, invocation, paths.get_backup_root())
    except (ClaudeSwitchError, OSError) as exc:
        print(f"claude-swap: {exc}", file=sys.stderr)
        raise SystemExit(4) from None


if __name__ == "__main__":
    main()

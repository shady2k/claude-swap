"""Install and run the PATH shim without changing Claude's installation.

Only the synthetic test route has a pinned layer here. No real build is
admitted without the version-specific routing and login evidence from PR3.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from claude_swap import __version__, claude_forms, fsguard, launch_policy, paths, profile_ownership, real_claude, spawn, test_mode
from claude_swap.exceptions import ClaudeSwitchError, ConfigError, SessionError
from claude_swap.fsutil import atomic_write_bytes, make_dir_link
from claude_swap.locking import FileLock
from claude_swap.python_chain import LOADER_VARS, check_python_chain
from claude_swap.settings import (
    check_transparent_history, load_transparent_settings, settings_lock,
)

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


def _install(directory: Path, strict: bool) -> None:
    interpreter = check_python_chain()
    script = _script(interpreter, directory, strict)
    _make_dir(directory)
    previous = _metadata(directory)
    target = _launcher(directory)
    original = target.read_bytes() if _owned(directory, previous) else None
    metadata = {
        "sha256": hashlib.sha256(script).hexdigest(),
        "interpreter": str(interpreter),
        "version": __version__,
        "requireProxy": strict,
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


def _safe_label(text: str) -> str:
    label = ""
    for char in text:
        if not char.isprintable():
            code = ord(char)
            if code <= 0xff:
                char = f"\\x{code:02x}"
            elif code <= 0xffff:
                char = f"\\u{code:04x}"
            else:
                char = f"\\U{code:08x}"
        if len(label) + len(char) > 120:
            break
        label += char
    return label


def enable(
    backup_root: Path, *, accept_shared_history: bool = False, pool: list[str] | None = None,
) -> Path:
    if sys.platform == "win32":
        raise ConfigError("No isolated, cancellable Windows shim launcher has been verified (PR1)")
    def pool_members(data: dict) -> tuple[tuple[str, ...], dict[str, list[str]]]:
        selected = launch_policy.slots(data.get("pool", []) if pool is None else pool)
        accounts = launch_policy.accounts(backup_root)
        members = {}
        for slot in selected:
            identity = launch_policy.identity(accounts.get(slot))
            if identity is None or identity[3] != "oauth":
                raise ConfigError(f"Account-{slot} needs a verified OAuth identity before joining the pool")
            members[slot] = list(identity)
        return selected, members

    reviewed = None
    if not accept_shared_history:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ConfigError(f"{launch_policy.CONSENT_TEXT} Use --accept-shared-history to approve without a terminal.")
        with FileLock(paths.account_lock_path(backup_root)):
            reviewed = pool_members(launch_policy.read(backup_root))
        print(launch_policy.CONSENT_TEXT, file=sys.stderr)
        members = reviewed[1]
        label = ", ".join(_safe_label(f"Account-{slot} ({identity[0]}, organization {identity[1]})")
                          for slot, identity in members.items())
        print(f"Approve shared history for {label or 'an empty pool'}? [y/N] ",
              end="", file=sys.stderr, flush=True)
        if sys.stdin.readline().strip().lower() not in {"y", "yes"}:
            raise ConfigError("Shared history was not approved")
    directory = paths.get_shim_dir(backup_root)
    launch_policy.archive()

    def change(data: dict) -> bool:
        selected, members = pool_members(data)
        if reviewed is not None and reviewed != (selected, members):
            raise ConfigError("The recipient identities changed; run cswap transparent enable again")
        with settings_lock(backup_root):
            check_transparent_history(backup_root)
            settings = load_transparent_settings(backup_root, policy=data)
            _install(directory, settings.require_proxy)
        data.update(enabled=True, pool=list(selected), historyZone={
            "scope": launch_policy.HISTORY_SCOPE, "members": members,
        })
        return True

    launch_policy.update(backup_root, change)
    return directory


def set_pool(backup_root: Path, pool: list[str]) -> None:
    """Remove or reorder pool entries without extending history consent."""
    selected = launch_policy.slots(pool)

    def change(data: dict) -> bool:
        if not set(selected).issubset(launch_policy.slots(data.get("pool", []))):
            raise ConfigError("To add accounts, approve shared history again with cswap transparent enable")
        data["pool"] = list(selected)
        zone = data.get("historyZone")
        if isinstance(zone, dict) and isinstance(zone.get("members"), dict):
            zone["members"] = {slot: zone["members"][slot] for slot in selected if slot in zone["members"]}
        return True

    launch_policy.update(backup_root, change)


def revoke_history(backup_root: Path) -> None:
    def change(data: dict) -> bool:
        if "historyZone" not in data:
            return False
        del data["historyZone"]
        return True

    launch_policy.update(backup_root, change)


def disable(backup_root: Path) -> None:
    directory = paths.get_shim_dir(backup_root)

    def change(data: dict) -> bool:
        if not data and not os.path.lexists(directory):
            return False
        data["enabled"] = False
        return True

    # Commit the revocation even if the installed launcher was replaced and
    # cannot safely be removed. In-flight publications already hold consent.
    launch_policy.update(backup_root, change)

    with FileLock(paths.account_lock_path(backup_root)):
        if launch_policy.read(backup_root).get("enabled") is not False or not os.path.lexists(directory):
            return
        fsguard.check_path(directory)
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
        policy = launch_policy.read(backup_root)
        options = load_transparent_settings(backup_root, policy=policy)
        installed = policy.get("enabled") is True and _installed(directory, options.require_proxy)
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
    directory = paths.get_shim_dir(backup_root)
    with FileLock(paths.account_lock_path(backup_root)):
        policy = launch_policy.read(backup_root)
        if policy.get("enabled") is True and os.path.lexists(_launcher(directory)):
            settings = load_transparent_settings(backup_root, policy=policy)
            _install(directory, settings.require_proxy)


def _test_layer(directory: Path, args: list[str], env: dict[str, str]):
    pinned, child = test_mode.pinned_launch(args, env)
    content = pinned[1].encode()
    # Keep the file readable for the whole handoff, including later reloads.
    layers = directory / "test-layers"
    _make_dir(layers)
    layer = layers / (hashlib.sha256(content).hexdigest() + ".json")
    atomic_write_bytes(layer, content, follow_symlinks=False)
    return ["--settings", str(layer), *args], child


class NoAvailableProfile(ClaudeSwitchError):
    """Current policy permits launch, but has no eligible recipient."""


class _UnpreparedProfile(ConfigError):
    """This selected identity has no matching warm profile."""


@dataclass(frozen=True)
class _Recipient:
    slot: str
    identity: launch_policy.Identity


@dataclass(frozen=True)
class _Launch:
    real: real_claude.RealClaude
    args: list[str]
    env: dict[str, str]
    recipient: _Recipient | None = None
    profile: Path | None = None
    outside_reason: str | None = None
    reservation: dict | None = None


def _profile_dir(root: Path, recipient: _Recipient, history: Path) -> Path:
    from claude_swap.session import session_dir_for

    email, org, uuid, _ = recipient.identity
    profile = session_dir_for(root, recipient.slot, email)
    try:
        if not os.path.lexists(profile):
            raise _UnpreparedProfile("profile has not been prepared")
        if fsguard.check_path(profile) != root.resolve() / profile.relative_to(root):
            raise ConfigError("Transparent profile must stay in its own slot")
        info = profile.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ConfigError("Transparent profile must be a directory owned by the current user")
        config = profile / ".claude.json"
        config_info = config.lstat()
        if not stat.S_ISREG(config_info.st_mode) or config_info.st_uid != os.geteuid():
            raise ConfigError("Transparent profile identity file is not safe")
        fsguard.check_leaf(config, config_info)
        oauth = json.loads(config.read_bytes())["oauthAccount"]
        if (oauth.get("emailAddress"), oauth.get("organizationUuid") or "", oauth.get("accountUuid")) != (email, org, uuid):
            raise ValueError
        projects = profile / "projects"
        if os.path.lexists(projects) and (not projects.is_symlink() or projects.resolve() != history):
            raise ConfigError("profile projects/ does not point to the approved shared archive")
    except (FileNotFoundError, ValueError, KeyError, AttributeError, TypeError) as exc:
        raise _UnpreparedProfile("profile is not prepared for the approved identity") from exc
    return profile


def _recipient(slot: str, accounts: dict, members: dict) -> _Recipient:
    record = accounts.get(slot)
    identity = launch_policy.identity(record)
    if identity is None or members.get(slot) != list(identity):
        raise ConfigError("not a member of the current history zone")
    if identity[3] != "oauth" or record.get("disabled"):
        raise ConfigError("profile is disabled or not OAuth")
    return _Recipient(slot, identity)


def _is_default_login(recipient: _Recipient) -> bool:
    from claude_swap.session import SessionManager

    return SessionManager._default_login_identity() == recipient.identity[:2]


def _prepare_launch(
    root: Path, directory: Path, marker: str, args: list[str], policy: dict,
    accounts: dict, *, test: bool,
) -> _Launch:
    options = load_transparent_settings(root, policy=policy)
    if (
        marker != _invocation_marker(directory, options.require_proxy)
        or not sys.flags.isolated or not _installed(directory, options.require_proxy)
    ):
        raise ConfigError("Shim is not installed, isolated or current; run cswap transparent enable")
    if options.require_proxy and any(key in os.environ for key in LOADER_VARS):
        raise ConfigError("loader environment is forbidden in strict mode")
    env = os.environ.copy()
    bypass = env.pop(_BYPASS, None)
    if bypass is not None and options.require_proxy:
        raise ConfigError(f"{_BYPASS}: forbidden in strict mode")
    reason = _BYPASS if bypass == "1" else None
    if reason is None:
        form = claude_forms.classify(args)
        if form.error:
            raise ConfigError(form.error)
        reason = form.bypass_reason
        if reason and options.require_proxy:
            raise ConfigError(f"{reason}; see cswap transparent status for the absolute path")
    env["CLAUDE_SWAP_LAUNCHED"] = str(os.getpid())
    if not test:
        if not reason:
            if options.require_proxy or not options.allow_unverified:
                raise ConfigError("No Claude build admitted for profile routing (PR3); see cswap transparent status")
            reason = "unverified Claude build"
        real = real_claude.resolve(backup_root=root, configured_path=options.claude_path)
        return _Launch(real, args, env, outside_reason=reason)

    if options.require_proxy and test_mode.DIRECT in env:
        raise ConfigError(f"{test_mode.DIRECT}: direct routing is forbidden in strict mode")
    members = launch_policy.consent(policy)
    real = test_mode.check_launch(args, backup_root=root)
    failures = []
    history = None
    for slot in launch_policy.slots(policy.get("pool", [])):
        identity = launch_policy.identity(accounts.get(slot))
        label = _safe_label(f"Account-{slot} ({identity[0]})" if identity else f"Account-{slot}")
        try:
            recipient = _recipient(slot, accounts, members)
        except ConfigError as exc:
            failures.append(f"{label}: {exc}; resets unknown")
            continue
        if history is None:
            history = launch_policy.archive()
        # Unsafe history links are a configuration error, not a reason to
        # continue on a profile whose history would be different.
        from claude_swap.session import session_dir_for
        profile = session_dir_for(root, recipient.slot, recipient.identity[0])
        record = None
        try:
            with profile_ownership.ownership_lock(root), FileLock(paths.account_lock_path(root)):
                current = launch_policy.accounts(root)
                if _recipient(slot, current, members) != recipient:
                    raise ConfigError("Recipient changed before reservation")
                if _is_default_login(recipient):
                    raise _UnpreparedProfile("account is the active default login")
                record = profile_ownership.reserve_locked(root, slot, profile)
            profile = _profile_dir(root, recipient, history)
            test_mode.check_launch(args, profile, backup_root=root, binary=real)
            child_args, child_env = _test_layer(directory, args, env)
            child_env["CLAUDE_CONFIG_DIR"] = child_env["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = str(profile)
            if not history.exists():
                launch_policy.archive(create=True)
            return _Launch(real, child_args, child_env, recipient, profile, reservation=record)
        except (_UnpreparedProfile, SessionError) as exc:
            failures.append(f"{label}: {exc}; resets unknown")
        except BaseException:
            if record is not None:
                with profile_ownership.ownership_lock(root):
                    profile_ownership.release_locked(root, record["launchId"])
            raise
        if record is not None:
            with profile_ownership.ownership_lock(root):
                profile_ownership.release_locked(root, record["launchId"])
    raise NoAvailableProfile("\n".join(failures) if failures else "No accounts in the transparent pool")


def _publish_launch(root: Path, directory: Path, policy: dict, prepared: _Launch) -> bool:
    """Commit the selected launch while consent and the identity still match."""
    with profile_ownership.ownership_lock(root), FileLock(paths.account_lock_path(root)), settings_lock(root):
        if prepared.reservation:
            profile_ownership.verify_reservation_locked(
                root, prepared.reservation["launchId"],
                expected_profile_gen=prepared.reservation["profileGen"],
            )
        current = launch_policy.read(root)
        members = launch_policy.consent(current)
        check_transparent_history(root)
        if current != policy:
            return False
        if recipient := prepared.recipient:
            history = launch_policy.archive()
            if not history.is_dir():
                raise ConfigError("Shared projects/ disappeared before publication; retry the launch")
            accounts = launch_policy.accounts(root)
            try:
                current_recipient = _recipient(recipient.slot, accounts, members)
            except ConfigError:
                return False
            if current_recipient != recipient or _is_default_login(recipient):
                return False
            try:
                profile = _profile_dir(root, recipient, history)
            except _UnpreparedProfile:
                return False
            if profile != prepared.profile:
                return False
            if not os.path.lexists(profile / "projects"):
                make_dir_link(history, profile / "projects")
        _journal(directory, _OUTSIDE if prepared.outside_reason else "launch")
        if prepared.reservation:
            profile_ownership.mark_running_locked(
                root, prepared.reservation["launchId"], os.getpid(),
                expected_profile_gen=prepared.reservation["profileGen"],
            )
        return True


def _launch(marker: str, args: list[str], root: Path) -> None:
    test = test_mode.active()
    if test:
        test_mode.check_launch(args, backup_root=root)
    directory = paths.get_shim_dir(root)
    # A concurrent policy edit restarts selection without giving a stale
    # candidate history or launching it. Bound retries under constant edits.
    for _ in range(3):
        with FileLock(paths.account_lock_path(root)), settings_lock(root):
            policy = launch_policy.read(root)
            launch_policy.consent(policy)
            check_transparent_history(root)
            accounts = launch_policy.accounts(root) if test else {}
        prepared = _prepare_launch(root, directory, marker, args, policy, accounts, test=test)
        if prepared.reservation:
            class PolicyChanged(Exception):
                pass

            def publish():
                if not _publish_launch(root, directory, policy, prepared):
                    raise PolicyChanged

            try:
                result = spawn.owned_launch(
                    lambda: prepared.real.handoff(prepared.args, prepared.env, job=True),
                    publish=publish,
                    release=lambda: profile_ownership.release_completed(root, prepared.reservation["launchId"]),
                    abort=lambda: profile_ownership.release_completed(root, prepared.reservation["launchId"]),
                )
            except PolicyChanged:
                continue
            raise SystemExit(result)
        if _publish_launch(root, directory, policy, prepared):
            break
    else:
        raise ConfigError("Transparent policy kept changing; retry the launch")
    if prepared.outside_reason:
        print(f"claude-swap: {_OUTSIDE}: {prepared.outside_reason}", file=sys.stderr)
    prepared.real.handoff(prepared.args, prepared.env, job=True)


def main() -> None:
    try:
        invocation = sys.argv[1:]
        marker = invocation.pop(0) if invocation else ""
        _launch(marker, invocation, paths.get_backup_root())
    except NoAvailableProfile as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(3) from None
    except (ClaudeSwitchError, OSError) as exc:
        print(f"claude-swap: {exc}", file=sys.stderr)
        raise SystemExit(4) from None


if __name__ == "__main__":
    main()

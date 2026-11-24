"""Check ownership and write access along an executable's entire path.

Walking the input as well as its link targets matters: a trusted destination
is not enough when an untrusted directory can retarget an intermediate link.
These checks protect against other local users, not the owner or an admin.
"""

from __future__ import annotations

import os
import stat
import sys
from collections import deque
from pathlib import Path

from claude_swap.exceptions import ClaudeSwitchError


class GuardError(ClaudeSwitchError):
    """The path's ownership, permissions, or type could not be trusted."""


def check_path(path: Path | str, *, follow_links: bool = True) -> Path:
    """Return the checked canonical path; optionally reject all links and junctions."""
    path = Path(path)
    if not path.is_absolute():
        raise GuardError(f"Not an absolute path: {path}")
    current = Path(path.anchor)
    parts = deque(path.parts[1:])
    links = 0
    try:
        info = current.lstat()
        sticky = _check_component(current, info, bool(parts))
        while parts:
            part = parts.popleft()
            next_path = current / part
            info = next_path.lstat()
            is_link = stat.S_ISLNK(info.st_mode) or next_path.is_junction()
            if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT and not is_link:
                raise GuardError(f"Unsupported reparse point: {next_path}")
            if sticky and (is_link or not stat.S_ISDIR(info.st_mode)
                           or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise GuardError(f"Expected a protected directory inside {current}: {next_path}")
            sticky = _check_component(next_path, info, bool(parts))
            if is_link:
                if not follow_links:
                    raise GuardError(f"Links and junctions are not allowed: {next_path}")
                links += 1
                if links > 40:
                    raise GuardError(f"Too many symlinks: {path}")
                target = next_path.readlink()
                if target.is_absolute():
                    current = Path(target.anchor)
                    parts.extendleft(reversed(target.parts[1:]))
                    sticky = _check_component(current, current.lstat(), bool(parts))
                elif target.anchor:
                    raise GuardError(f"Ambiguous symlink target: {next_path}")
                else:
                    parts.extendleft(reversed(target.parts))
            else:
                current = current.parent if part == ".." else next_path
        return current
    except (OSError, ValueError) as exc:
        raise GuardError(f"Could not inspect executable path {path}: {exc}") from exc


def check_leaf(path: Path, info: os.stat_result) -> None:
    """Check one non-link entry whose parent has already been checked."""
    _check_component(path, info, False)


def _check_component(path: Path, info: os.stat_result, has_children: bool) -> bool:
    """Return True when the next hop needs the sticky-directory exception."""
    if sys.platform == "win32":
        from claude_swap._win_file_security import check_write_access

        check_write_access(path)
        return False
    if not hasattr(os, "geteuid") or info.st_uid not in {0, os.geteuid()}:
        raise GuardError(f"Untrusted owner: {path}")
    # POSIX symlink mode bits do not control access; its parent controls
    # replacement. Ownership matters for the sticky-directory rules.
    if stat.S_ISLNK(info.st_mode):
        return False
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        if (info.st_uid == 0 and has_children and stat.S_ISDIR(info.st_mode)
                and info.st_mode & stat.S_ISVTX):
            return True
        raise GuardError(f"Writable by group or others: {path}")
    return False

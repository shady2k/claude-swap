"""Test shared Claude lookup and the checked object used for launch."""

import hashlib
import os
import sys
import time
from pathlib import Path

import pytest

from claude_swap import _win_file_security, real_claude
from claude_swap.settings import set_setting


def _executable(directory: Path, content: bytes = b"#!/bin/sh\nexit 0\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    name = "claude.exe" if sys.platform == "win32" else "claude"
    target = directory / name
    target.write_bytes(content)
    target.chmod(0o700)
    return target


def _wait_for_new_change_time(probe: Path, previous: int) -> None:
    """Wait until the filesystem reports a change time other than ``previous``.

    A same-size edit with a restored mtime is visible only through
    ``st_ctime_ns``, which the filesystem reports at its clock granularity
    (1 ms on ext4). An edit inside the same tick leaves that field equal.
    """
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        os.utime(probe)
        if probe.stat().st_ctime_ns != previous:
            return
    raise AssertionError("filesystem change time did not advance")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links and permissions")
def test_path_skips_cwd_untrusted_directories_and_all_shims(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    cwd_hit = _executable(tmp_path / "project")
    monkeypatch.chdir(cwd_hit.parent)
    _executable(cwd_hit.parent / "relative")
    unsafe = _executable(tmp_path / "untrusted")
    unsafe.parent.chmod(0o777)
    shim_content = f"#!/bin/sh\n{real_claude.SHIM_MARKER}\n".encode()
    shim = _executable(root / "shim", shim_content)
    copied = _executable(tmp_path / "copied", shim_content)
    real = _executable(tmp_path / "actual")
    (unsafe.parent / "insecure-hop").symlink_to(real.parent, target_is_directory=True)
    alias = tmp_path / "dir-link"
    alias.symlink_to(unsafe.parent / "insecure-hop", target_is_directory=True)
    nice_link = _executable(tmp_path / "safe-link")
    nice_link.unlink()
    nice_link.symlink_to(real)
    alias_shim = tmp_path / "shim-alias"
    alias_shim.mkdir()
    (alias_shim / "claude").symlink_to(shim)
    skipped = []
    entries = ["", ".", "relative", cwd_hit.parent, unsafe.parent, alias,
               shim.parent, shim.parent, copied.parent, alias_shim, nice_link.parent]
    path = os.pathsep.join(map(str, entries))
    assert real_claude.path_command(path) == cwd_hit
    assert real_claude.resolve(backup_root=root, path=path, skipped=skipped).path == real.resolve()
    for message in ("empty or relative", "current directory", "Writable by group", "shim"):
        assert any(message in item for item in skipped)
    with pytest.raises(real_claude.ResolveError, match="shim"):
        real_claude.resolve(backup_root=root, configured_path=alias_shim / "claude")
    with pytest.raises(real_claude.ResolveError, match="current directory"):
        real_claude.resolve(backup_root=root, configured_path=cwd_hit)
    with pytest.raises(real_claude.ResolveError, match="not found on PATH"):
        real_claude.resolve(backup_root=root, path=str(tmp_path / "missing"))
    set_setting(root, "transparent.claudePath", str(nice_link))
    assert real_claude.resolve(backup_root=root, path="").path == real.resolve()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX change time and named probe")
def test_fingerprint_and_probe_use_checked_realpath(tmp_path, monkeypatch):
    target = _executable(tmp_path / "bin")
    alias = tmp_path / "claude"
    alias.symlink_to(target)
    child = real_claude.resolve(backup_root=tmp_path, configured_path=alias)
    captured = []
    monkeypatch.setattr(real_claude.spawn, "run", lambda argv, **kw: captured.append(argv))
    child.run(["auth", "status", "--json"])
    assert captured == [[str(target.resolve()), "auth", "status", "--json"]]
    original = target.stat()
    digest = child.fingerprint()
    assert digest == hashlib.sha256(target.read_bytes()).hexdigest()
    clock = tmp_path / "clock"
    clock.touch()
    _wait_for_new_change_time(clock, original.st_ctime_ns)
    target.write_bytes(b"#!/bin/sh\nexit 1\n")
    os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    with pytest.raises(real_claude.ResolveError, match="changed after resolution"):
        child.run(["auth", "status", "--json"])
    assert len(captured) == 1
    assert real_claude.resolve(backup_root=tmp_path, configured_path=alias).fingerprint() != digest


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows PATH and file APIs")
def test_windows_path_resolves_claude_in_user_profile(tmp_path, monkeypatch):
    target = _executable(Path.home() / ".local" / "bin", b"MZ synthetic executable")
    monkeypatch.setenv("PATH", str(target.parent))
    monkeypatch.setenv("PATHEXT", ".EXE")
    monkeypatch.setenv("NoDefaultCurrentDirectoryInExePath", "1")
    child = real_claude.resolve(backup_root=tmp_path)
    assert child.path == target.resolve()

    # Exercise the probe's open/identity check, without executing the fixture.
    captured = []
    monkeypatch.setattr(real_claude.spawn, "run", lambda argv, **kw: captured.append(argv))
    child.run(["auth", "status", "--json"])
    assert captured == [[str(child.path), "auth", "status", "--json"]]

    # Same lengths and write times still identify two different files.
    initial = target.stat()
    replacement = target.with_name("replacement.exe")
    replacement.write_bytes(b"MZ replaced! executable")
    assert replacement.stat().st_size == initial.st_size
    os.utime(replacement, ns=(initial.st_atime_ns, initial.st_mtime_ns))
    replacement.replace(target)
    monkeypatch.setattr(real_claude.spawn, "handoff", lambda *a, **kw: pytest.fail("unexpected spawn"))
    with pytest.raises(real_claude.ResolveError, match="opened-fd:file_id"):
        child.handoff([], {})


@pytest.fixture
def windows_identity(monkeypatch):
    """Model native snapshots while running the Windows resolver on any OS."""
    initial = _win_file_security.ExecutableIdentity(1, 2, 0, 16, 3, 4, None)
    snapshots = {"path": initial, "fd": initial}
    if sys.platform != "win32":
        monkeypatch.setattr(_win_file_security, "open_executable", lambda path: os.open(path, os.O_RDONLY))
    monkeypatch.setattr(real_claude.sys, "platform", "win32")
    monkeypatch.setattr(_win_file_security, "executable_identity_at_path", lambda path: snapshots["path"])
    monkeypatch.setattr(_win_file_security, "executable_identity_at_fd", lambda fd: snapshots["fd"])
    return snapshots


def test_windows_fingerprint_without_change_time_is_never_cached(
    tmp_path, monkeypatch, windows_identity,
):
    target = _executable(tmp_path / "bin")
    child = real_claude.resolve(backup_root=tmp_path, configured_path=target)
    calls = []
    real_hash = real_claude._hash

    def digest(stream):
        calls.append(1)
        return real_hash(stream)

    monkeypatch.setattr(real_claude, "_hash", digest)
    assert child.fingerprint() == child.fingerprint()
    assert len(calls) == 2
    windows_identity["path"] = windows_identity["fd"] = windows_identity["fd"]._replace(change_time=1)
    other = real_claude.resolve(backup_root=tmp_path, configured_path=target)
    assert other.fingerprint() == other.fingerprint()
    assert len(calls) == 3
    windows_identity["fd"] = windows_identity["fd"]._replace(change_time=2)
    with pytest.raises(real_claude.ResolveError, match="opened-fd:change_time"):
        other.fingerprint()
    assert len(calls) == 3


@pytest.mark.parametrize("launch", ["handoff", "run"])
def test_windows_checks_path_before_spawn_while_handle_is_open(
    tmp_path, monkeypatch, windows_identity, launch,
):
    target = _executable(tmp_path / "bin")
    child = real_claude.resolve(backup_root=tmp_path, configured_path=target)
    fd = None

    def pinned_identity(checked_fd):
        nonlocal fd
        fd = checked_fd
        return windows_identity["fd"]

    def replaced_path(path):
        assert path == child.path
        assert fd is not None
        os.fstat(fd)  # The name is checked while the original is still pinned.
        return windows_identity["path"]._replace(file_id=3, write_time=5)

    monkeypatch.setattr(_win_file_security, "executable_identity_at_fd", pinned_identity)
    monkeypatch.setattr(_win_file_security, "executable_identity_at_path", replaced_path)
    monkeypatch.setattr(real_claude.spawn, launch, lambda *a, **kw: pytest.fail("unexpected spawn"))
    with pytest.raises(real_claude.ResolveError, match=r"\(before-launch-path:file_id\)$"):
        if launch == "handoff":
            child.handoff([], {})
        else:
            child.run([])
    with pytest.raises(OSError):
        os.fstat(fd)

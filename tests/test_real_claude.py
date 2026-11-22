"""Test shared Claude lookup and the checked object used for launch."""

import hashlib
import os
import sys
from pathlib import Path

import pytest

from claude_swap import fsguard, real_claude
from claude_swap.settings import set_setting


def _executable(directory: Path, content: bytes = b"#!/bin/sh\nexit 0\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    name = "claude.exe" if sys.platform == "win32" else "claude"
    target = directory / name
    target.write_bytes(content)
    target.chmod(0o700)
    return target


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
        real_claude.resolve(backup_root=root, path=os.pathsep.join(map(str, entries[:-1])))
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
    target.write_bytes(b"#!/bin/sh\nexit 1\n")
    os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    with pytest.raises(real_claude.ResolveError, match="changed after resolution"):
        child.run(["auth", "status", "--json"])
    assert len(captured) == 1
    assert real_claude.resolve(backup_root=tmp_path, configured_path=alias).fingerprint() != digest


def test_windows_fingerprint_without_change_time_is_never_cached(tmp_path, monkeypatch):
    target = _executable(tmp_path / "bin")
    monkeypatch.setattr(real_claude.sys, "platform", "win32")
    monkeypatch.setattr(fsguard, "check_path", lambda path: path.resolve())
    times = {target.resolve(): None}
    monkeypatch.setattr(real_claude, "_change_time", times.get)
    child = real_claude.resolve(backup_root=tmp_path, configured_path=target)
    calls = []
    real_hash = real_claude._hash

    def digest(stream):
        calls.append(1)
        return real_hash(stream)

    monkeypatch.setattr(real_claude, "_hash", digest)
    assert child.fingerprint() == child.fingerprint()
    assert len(calls) == 2
    times[child.path] = 1
    other = real_claude.resolve(backup_root=tmp_path, configured_path=target)
    assert other.fingerprint() == other.fingerprint()
    assert len(calls) == 3
    times[child.path] = 2
    with pytest.raises(real_claude.ResolveError, match="changed after resolution"):
        other.fingerprint()
    assert len(calls) == 3

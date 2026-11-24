"""Permission checks for the interpreter and package imported by the shim."""

import sys
from pathlib import Path

import pytest

from claude_swap import fsguard, python_chain

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode and symlink checks")


@pytest.fixture
def layout(monkeypatch, tmp_path):
    base = tmp_path / "Versions" / "base"
    base_bin = base / "bin"
    base_bin.mkdir(parents=True)
    binary = base_bin / "python"
    binary.write_bytes(b"isolated interpreter stub")
    binary.chmod(0o755)
    env = tmp_path / "env"
    env_bin = env / "bin"
    env_bin.mkdir(parents=True)
    invocation = env_bin / "python"
    invocation.symlink_to(binary)
    config = env / "pyvenv.cfg"
    config.write_text(f"home = {base_bin}\n")
    site_dir = env / "site-packages"
    package = site_dir / "claude_swap"
    package.mkdir(parents=True)
    module = package / "python_chain.py"
    module.write_text("")
    hook = site_dir / "example.pth"
    hook.write_text("")

    monkeypatch.setattr(sys, "executable", str(invocation))
    monkeypatch.setattr(sys, "prefix", str(env))
    monkeypatch.setattr(sys, "base_prefix", str(base))
    monkeypatch.setattr(sys, "path", [str(site_dir)])
    monkeypatch.setattr(python_chain, "__file__", str(module))
    monkeypatch.setattr(python_chain.site, "getsitepackages", lambda *a, **kw: [str(site_dir)])
    return invocation, (binary, base_bin, config, package, module, hook)


def test_uses_lexical_interpreter_path_after_checking_its_target(layout):
    invocation, (binary, *_) = layout
    assert invocation.resolve() == binary.resolve()
    assert python_chain.check_python_chain() == invocation


@pytest.mark.parametrize("index", range(6), ids=["binary", "bin", "cfg", "pkg", "module", "pth"])
def test_rechecks_permissions_after_success(layout, index):
    invocation, entries = layout
    assert python_chain.check_python_chain() == invocation
    item = entries[index]
    parent = item.parent
    parent_mtime = parent.stat().st_mtime_ns
    item.chmod(item.stat().st_mode | 0o020)
    assert parent.stat().st_mtime_ns == parent_mtime
    with pytest.raises(fsguard.GuardError, match="Writable by group or others"):
        python_chain.check_python_chain()

    if index == 0:
        # Check the interpreter target's ancestor independently of its mode.
        item.chmod(0o755)
        assert python_chain.check_python_chain() == invocation
        versions = item.parents[2]
        versions.chmod(0o775)
        with pytest.raises(fsguard.GuardError, match="Writable by group or others: .*Versions"):
            python_chain.check_python_chain()


def test_import_symlink_from_guarded_site_to_writable_target_is_rejected(layout):
    _, (_, _, _, package, _, _) = layout
    writable = package.parent.parent / "writable"
    writable.mkdir(mode=0o755)
    writable.chmod(0o777)
    (package.parent / "external").symlink_to(writable)
    with pytest.raises(fsguard.GuardError, match="Writable by group or others"):
        python_chain.check_python_chain()


@pytest.mark.parametrize("change", ["rename", "unsafe", "broken-link", "missing-interpreter", "missing-prefix", "unstable"])
def test_entry_disappears_between_listing_and_stat(layout, monkeypatch, change):
    invocation, (_, _, _, package, module, _) = layout
    transient = package / "pending"
    transient.write_bytes(b"safe synthetic file")
    replacement = package / "complete"
    scandir = python_chain.os.scandir
    attempts = []
    roots = []
    failures = []

    class Entry:
        def __init__(self, entry):
            self.entry = entry
            self.path = entry.path

        def stat(self, *, follow_symlinks):
            if self.path == str(transient) and (not failures or change == "unstable"):
                failures.append(self.path)
                if change != "unstable":
                    transient.rename(replacement)
                if change == "unsafe":
                    module.chmod(0o666)
                elif change == "broken-link":
                    replacement.unlink()
                    replacement.symlink_to(package / "absent")
                elif change == "missing-interpreter":
                    (Path(sys.base_prefix) / "bin" / "python").unlink()
                elif change == "missing-prefix":
                    monkeypatch.setattr(sys, "base_prefix", str(package / "absent-prefix"))
                raise FileNotFoundError(2, "entry renamed", self.path)
            return self.entry.stat(follow_symlinks=follow_symlinks)

        def is_symlink(self):
            return self.entry.is_symlink()

    class Scan:
        def __init__(self, directory):
            self.directory = directory
            self.scan = scandir(directory)

        def __enter__(self):
            entries = self.scan.__enter__()
            if Path(self.directory) == package.parent:
                roots.append(self.directory)
            if Path(self.directory) == package:
                attempts.append(self.directory)
            return (Entry(entry) for entry in entries)

        def __exit__(self, *args):
            return self.scan.__exit__(*args)

    monkeypatch.setattr(python_chain.os, "scandir", Scan)
    if change == "rename":
        assert python_chain.check_python_chain() == invocation
        assert len(attempts) == len(roots) == 2
        assert replacement.is_file()
    else:
        expected = {
            "unsafe": "Writable by group or others",
            "broken-link": "Could not inspect executable path",
            "missing-interpreter": "Could not inspect executable path",
            "missing-prefix": "Could not inspect executable path",
            "unstable": "Cannot check the Python executable chain",
        }
        with pytest.raises(fsguard.GuardError, match=expected[change]):
            python_chain.check_python_chain()
        assert len(roots) == (1 if change.startswith("missing-") else 2)
    assert len(failures) == (2 if change == "unstable" else 1)


def test_inaccessible_tree_is_not_retried(layout, monkeypatch):
    calls = []

    def inaccessible(directory):
        calls.append(directory)
        raise PermissionError(13, "synthetic inaccessible tree", str(directory))

    monkeypatch.setattr(python_chain.os, "scandir", inaccessible)
    with pytest.raises(fsguard.GuardError, match="synthetic inaccessible tree"):
        python_chain.check_python_chain()
    assert len(calls) == 1

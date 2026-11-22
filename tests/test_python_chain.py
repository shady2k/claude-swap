"""Permission checks for the interpreter and package imported by the shim."""

import sys

import pytest

from claude_swap import fsguard, python_chain

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode and symlink checks")


@pytest.fixture
def layout(monkeypatch, tmp_path):
    base = tmp_path / "base"
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


def test_import_symlink_from_guarded_site_to_writable_target_is_rejected(layout):
    _, (_, _, _, package, _, _) = layout
    writable = package.parent.parent / "writable"
    writable.mkdir(mode=0o755)
    writable.chmod(0o777)
    (package.parent / "external").symlink_to(writable)
    with pytest.raises(fsguard.GuardError, match="Writable by group or others"):
        python_chain.check_python_chain()

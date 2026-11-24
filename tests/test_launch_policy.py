"""Windows pool data checks, exercised without changing the host platform."""

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import fsguard, launch_policy, paths, settings
from claude_swap.exceptions import ConfigError


@pytest.fixture
def windows_store(monkeypatch, tmp_path):
    root = tmp_path.resolve() / "backup"
    monkeypatch.setattr(launch_policy, "sys", SimpleNamespace(platform="win32"))
    real_lstat = Path.lstat
    reparse_points = set()
    unsafe = set()
    checked = []

    def lstat(path):
        info = real_lstat(path)
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_file_attributes=(getattr(info, "st_file_attributes", 0)
                                | (stat.FILE_ATTRIBUTE_REPARSE_POINT if path in reparse_points else 0)),
        )

    def check_leaf(path, _info):
        checked.append(path)
        if path in unsafe:
            raise fsguard.GuardError(f"Untrusted entry: {path}")

    def check_path(*args, **kwargs):
        pytest.fail("Windows policy data must not use the executable path guard")

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(fsguard, "check_leaf", check_leaf)
    monkeypatch.setattr(fsguard, "check_path", check_path)
    return SimpleNamespace(root=root, reparse_points=reparse_points, unsafe=unsafe, checked=checked)


def test_windows_policy_only_checks_acls_at_store(windows_store):
    root = windows_store.root
    assert launch_policy.read(root) == {}
    lock = paths.account_lock_path(root)
    policy = root / "transparent.json"
    roster = root / "sequence.json"

    def seed(data):
        data["pool"] = ["1"]
        return True

    assert launch_policy.update(root, seed)
    assert launch_policy.read(root) == {"pool": ["1"], "rev": 1}
    roster.write_text(json.dumps({"accounts": {"1": {}}}), encoding="utf-8")
    assert launch_policy.accounts(root) == {"1": {}}
    assert not launch_policy.update(root, lambda _: False)
    assert set(windows_store.checked) == {root, lock, policy, roster}


@pytest.mark.parametrize("root_exists", [False, True], ids=["new-root", "existing-root"])
def test_windows_absent_policy_allows_settings_read_but_not_update_in_unsafe_root(windows_store, root_exists):
    root = windows_store.root
    if root_exists:
        root.mkdir()
    windows_store.unsafe.add(root)
    assert launch_policy.read(root) == {}
    assert not windows_store.checked
    rows = {spec.dotted: (value, is_set) for spec, value, is_set in settings.effective_settings(root)}
    assert rows["transparent.requireProxy"] == (False, False)
    assert not windows_store.checked

    with pytest.raises(fsguard.GuardError):
        launch_policy.update(root, lambda _: pytest.fail("Updated an untrusted root"))
    assert windows_store.checked == [root]
    assert not list(root.iterdir())


@pytest.mark.parametrize("entry", ["root", "policy"])
def test_windows_existing_policy_needs_safe_root_and_file(windows_store, entry, monkeypatch):
    root = windows_store.root
    root.mkdir()
    policy = root / "transparent.json"
    policy.write_text("{}", encoding="utf-8")
    windows_store.unsafe.add(root if entry == "root" else policy)

    def must_not_read(_):
        pytest.fail("Read policy before verifying the ACLs")

    monkeypatch.setattr(Path, "read_bytes", must_not_read)
    with pytest.raises(fsguard.GuardError):
        launch_policy.read(root)
    with pytest.raises(fsguard.GuardError):
        launch_policy.update(root, lambda _: pytest.fail("Updated an untrusted policy"))
    assert policy.read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize("entry", ["root", "policy"])
def test_windows_policy_does_not_treat_access_errors_as_missing(windows_store, entry, monkeypatch):
    root = windows_store.root
    root.mkdir()
    denied = root if entry == "root" else root / "transparent.json"
    lstat = Path.lstat

    def deny(path):
        if path == denied:
            raise PermissionError
        return lstat(path)

    monkeypatch.setattr(Path, "lstat", deny)
    with pytest.raises(ConfigError) as error:
        launch_policy.read(root)
    assert isinstance(error.value.__cause__, PermissionError)


@pytest.mark.parametrize("entry", ["ancestor", "root", "policy", "roster", "lock"])
def test_windows_policy_refuses_reparse_points(windows_store, entry):
    root = windows_store.root
    root.mkdir(parents=True)
    link = {
        "ancestor": root.parent,
        "root": root,
        "policy": root / "transparent.json",
        "roster": root / "sequence.json",
        "lock": paths.account_lock_path(root),
    }[entry]
    if entry in {"policy", "roster", "lock"}:
        link.write_text("{}", encoding="utf-8")
    windows_store.reparse_points.add(link)
    if entry in {"ancestor", "root", "policy"}:
        with pytest.raises(fsguard.GuardError):
            launch_policy.read(root)

    def must_not_change(_):
        pytest.fail("Policy change reached a redirected store entry")

    if entry == "roster":
        with pytest.raises(fsguard.GuardError):
            launch_policy.accounts(root)
    else:
        with pytest.raises(fsguard.GuardError):
            launch_policy.update(root, must_not_change)
    if entry in {"policy", "roster", "lock"}:
        assert link.read_text(encoding="utf-8") == "{}"


def test_windows_policy_refuses_hard_link_substitution(windows_store):
    root = windows_store.root
    root.mkdir(parents=True)
    other = root / "other.json"
    other.write_text('{"pool": ["1"]}', encoding="utf-8")
    os.link(other, root / "transparent.json")
    with pytest.raises(fsguard.GuardError):
        launch_policy.read(root)

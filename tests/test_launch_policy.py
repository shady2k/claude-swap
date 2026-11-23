"""Windows pool data checks, exercised without changing the host platform."""

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import fsguard, launch_policy, paths


@pytest.fixture
def windows_store(monkeypatch, tmp_path):
    root = tmp_path.resolve() / "backup"
    monkeypatch.setattr(launch_policy, "sys", SimpleNamespace(platform="win32"))
    real_lstat = Path.lstat
    reparse_points = set()
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

    def check_path(*args, **kwargs):
        pytest.fail("Windows policy data must not use the executable path guard")

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(fsguard, "check_leaf", check_leaf)
    monkeypatch.setattr(fsguard, "check_path", check_path)
    return root, reparse_points, checked


def test_windows_policy_only_checks_acls_at_store(windows_store):
    root, _, checked = windows_store
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
    assert set(checked) == {root, lock, policy, roster}


@pytest.mark.parametrize("entry", ["ancestor", "root", "policy", "roster", "lock"])
def test_windows_policy_refuses_reparse_points(windows_store, entry):
    root, reparse_points, _ = windows_store
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
    reparse_points.add(link)

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
    root, _, _ = windows_store
    root.mkdir(parents=True)
    other = root / "other.json"
    other.write_text('{"pool": ["1"]}', encoding="utf-8")
    os.link(other, root / "transparent.json")
    with pytest.raises(fsguard.GuardError):
        launch_policy.read(root)

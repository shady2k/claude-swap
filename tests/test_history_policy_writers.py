"""Settings writers preserve unrelated preferences and launch-policy updates."""

import ast
import json
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from claude_swap import cli, fsguard, launch_policy, menubar, paths, settings, transparent
from claude_swap.locking import FileLock


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows profile inheritance")
def test_policy_update_in_inherited_profile_home(monkeypatch):
    import ctypes as c
    from ctypes import wintypes as w

    from claude_swap import _win_file_security as security
    from tests.win_config_diagnostic import _observe_dacl

    # Do not repair the ACL: this controls the product's ordinary mkdir path,
    # not pytest's temp-directory ACL or the private-root fixture.
    # CSIDL_LOCAL_APPDATA resolves the account profile independently of pytest's
    # HOME redirection, including in xdist workers. Its existing directory is
    # outside the guarded real account store; only this fresh child is touched.
    shell = c.WinDLL("shell32", use_last_error=True)
    locate = security._function(shell, "SHGetFolderPathW", c.c_long,
                                w.HWND, c.c_int, w.HANDLE, w.DWORD, w.LPWSTR)
    buffer = c.create_unicode_buffer(32768)
    assert locate(None, 0x1C, None, 0, buffer) == 0
    home = Path(buffer.value) / f"cswap-policy-control-{uuid4().hex}"
    home.mkdir()
    try:
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.setattr(Path, "home", lambda: home)
        root = paths.get_backup_root()
        assert not root.exists()
        check_dacl = security._check_dacl
        rejection = []

        def observe(path, dacl, trusted):
            return _observe_dacl(check_dacl, path, dacl, trusted, rejection)

        monkeypatch.setattr(security, "_check_dacl", observe)
        for revision in (1, 2):
            changed = []

            def change(data):
                changed.append(True)
                assert data == ({} if revision == 1 else {"synthetic": 1, "rev": 1})
                data["synthetic"] = revision
                return True

            try:
                assert launch_policy.update(root, change) is True
                expected = {"synthetic": revision, "rev": revision}
                assert launch_policy.read(root) == expected
            except fsguard.GuardError as exc:
                pytest.fail(f"ordinary profile revision={revision}: {exc}; rejected ACE={rejection}")
            assert changed == [True]
            assert json.loads((root / "transparent.json").read_text(encoding="utf-8")) == expected
    finally:
        shutil.rmtree(home)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows ACL APIs")
@pytest.mark.parametrize("existing_policy", [False, True], ids=["absent-policy", "existing-policy"])
def test_policy_update_refuses_foreign_write_before_mutation(private_backup_root, existing_policy):
    root = private_backup_root
    policy = root / "transparent.json"
    if existing_policy:
        assert launch_policy.update(root, lambda data: (data.update(synthetic=True) or True))
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    # Authenticated Users is outside the guard's current-user/SYSTEM/Admin set.
    result = subprocess.run(
        ["icacls", str(root), "/grant", "*S-1-5-11:(OI)(CI)(M)"],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, "could not install the synthetic foreign write grant"
    changed = []
    with pytest.raises(fsguard.GuardError, match="Writable by another user or group") as error:
        launch_policy.update(root, lambda data: (changed.append(True) or True))
    assert str(root) in str(error.value)
    assert not changed
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
    assert policy.exists() is existing_policy


@pytest.fixture
def root(private_backup_root):
    settings.settings_path(private_backup_root).write_text(json.dumps({
        "schemaVersion": 1, "future": {"keep": True}, "ui": {"orgTag": "off"},
    }), encoding="utf-8")
    return private_backup_root


def test_concurrent_settings_keys_are_read_and_written_under_one_lock(root, monkeypatch):
    first_read = threading.Event()
    second_lock = threading.Event()
    release = threading.Event()
    read = settings._read_raw_for_write
    acquire = FileLock.acquire

    def observe_acquire(lock):
        if threading.current_thread().name.startswith("second"):
            second_lock.set()
        return acquire(lock)

    def paused_read(path):
        raw = read(path)
        if threading.current_thread().name.startswith("first"):
            # The lock covers the read, not merely the atomic replacement.
            probe = FileLock(root / "settings.lock", timeout=0)
            acquired = probe.acquire()
            if acquired:
                probe.release()
            assert not acquired
            first_read.set()
            assert release.wait(5)
        return raw

    monkeypatch.setattr(FileLock, "acquire", observe_acquire)
    monkeypatch.setattr(settings, "_read_raw_for_write", paused_read)
    with ThreadPoolExecutor(1, thread_name_prefix="first") as first, \
            ThreadPoolExecutor(1, thread_name_prefix="second") as second:
        one = first.submit(settings.set_setting, root, "ui.theme", "light")
        try:
            assert first_read.wait(5)
            two = second.submit(settings.set_setting, root, "run.shareHistory", "false")
            assert second_lock.wait(5)
            assert not two.done()
        finally:
            release.set()
        one.result(timeout=5)
        two.result(timeout=5)
    raw = json.loads(settings.settings_path(root).read_text(encoding="utf-8"))
    assert raw == {"schemaVersion": 1, "future": {"keep": True},
                   "ui": {"orgTag": "off", "theme": "light"},
                   "run": {"shareHistory": False}}


def _menu_threshold_writer(root, monkeypatch):
    # Capture the real nested class without starting Cocoa, timers or fetches.
    from claude_swap import app_bundle

    captured = []

    class App:
        def __init_subclass__(cls):
            captured.append(cls)
            cls.__init__ = lambda self: None

        def run(self):
            return None

    monkeypatch.setitem(sys.modules, "rumps", SimpleNamespace(App=App))
    monkeypatch.setitem(sys.modules, "AppKit", SimpleNamespace(
        NSApplication=SimpleNamespace(sharedApplication=lambda: SimpleNamespace(
            setActivationPolicy_=lambda _: None)),
        NSApplicationActivationPolicyAccessory=1,
    ))
    monkeypatch.setattr(app_bundle, "maybe_reexec", lambda _: None)
    monkeypatch.setattr(app_bundle, "in_bundle", lambda: True)
    monkeypatch.setattr(menubar.launch_agent, "write_worker_stamp", lambda _: None)
    monkeypatch.setattr(menubar, "framework_build_warning", lambda: None)
    menubar.run(SimpleNamespace(backup_dir=root))
    app = captured[0]()
    app.switcher = SimpleNamespace(backup_dir=root)
    app._restart_engine = lambda: None
    app.rebuild_menu = lambda: None
    return lambda: app._make_threshold(80)(None)


@pytest.mark.parametrize("surface", ["cli", "tui", "menu"])
@pytest.mark.parametrize("change", ["pool", "disable"])
def test_surface_setting_write_preserves_concurrent_policy_update(root, monkeypatch, surface, change):
    policy = {"enabled": True, "pool": ["1", "2"],
              "historyZone": {"scope": launch_policy.HISTORY_SCOPE,
                              "members": {"1": ["one"], "2": ["two"]}},
              "options": {"requireProxy": False}, "future": {"keep": True}}
    launch_policy.update(root, lambda data: (data.update(policy) or True))
    if surface == "cli":
        writer = lambda: cli._config_command(["set", "ui.theme", "light"])
    elif surface == "tui":
        from claude_swap.tui.app import CswapApp
        from claude_swap.tui.theme import CSWAP_DARK, CSWAP_LIGHT

        app = CswapApp(SimpleNamespace(backup_dir=root))
        app.register_theme(CSWAP_DARK)
        app.register_theme(CSWAP_LIGHT)
        writer = lambda: app.apply_theme("light")
    else:
        writer = _menu_threshold_writer(root, monkeypatch)

    entered = threading.Event()
    release = threading.Event()
    read = settings._read_raw_for_write

    def paused_read(path):
        raw = read(path)
        entered.set()
        assert release.wait(5)
        return raw

    monkeypatch.setattr(settings, "_read_raw_for_write", paused_read)
    def update_policy():
        try:
            assert entered.wait(5)
            if change == "pool":
                transparent.set_pool(root, ["2"])
            else:
                transparent.disable(root)
            return launch_policy.read(root)
        finally:
            release.set()

    with ThreadPoolExecutor(1) as executor:
        pending = executor.submit(update_policy)
        writer()
        updated = pending.result(timeout=5)
    assert updated["rev"] == 2
    assert launch_policy.read(root) == updated
    assert updated["future"] == policy["future"]
    assert updated["options"] == policy["options"]
    if change == "pool":
        assert updated["pool"] == ["2"]
        assert updated["historyZone"]["members"] == {"2": ["two"]}
    else:
        assert updated["enabled"] is False
        assert updated["historyZone"] == policy["historyZone"]
    raw = json.loads(settings.settings_path(root).read_text(encoding="utf-8"))
    assert raw["future"] == {"keep": True}
    assert raw["ui"]["orgTag"] == "off"
    if surface == "menu":
        assert raw["autoswitch"]["threshold"] == 80
    else:
        assert raw["ui"]["theme"] == "light"


def test_only_settings_update_writes_shared_settings_file():
    source = Path(settings.__file__).parent
    writers = []
    references = []
    for path in sorted(source.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        # Claude Code's own settings share this basename. Pin those references
        # too, so a new hardcoded cswap settings path cannot bypass the writer.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or node.value != "settings.json":
                continue
            owner = node
            while not isinstance(owner, (ast.FunctionDef, ast.Module)):
                owner = parents[owner]
            references.append((path.relative_to(source).as_posix(),
                               getattr(owner, "name", "<module>")))
        for owner in ast.walk(tree):
            if not isinstance(owner, ast.FunctionDef):
                continue
            targets = {"settings_path(root)", "settings_path(backup_root)",
                       "settings.settings_path(root)", "settings.settings_path(backup_root)"}
            for node in ast.walk(owner):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    if ast.unparse(node.value.func) in {"settings_path", "settings.settings_path"}:
                        targets.update(ast.unparse(target) for target in node.targets)
            for node in ast.walk(owner):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                name = ast.unparse(node.func)
                if name not in {"atomic_write_json", "settings.atomic_write_json", "atomic_write_text"}:
                    continue
                if ast.unparse(node.args[0]) in targets:
                    writers.append((path.relative_to(source).as_posix(), owner.name, name))
    assert writers == [("settings.py", "_update_settings", "atomic_write_json")]
    assert sorted(references) == [
        ("session.py", "<module>"),
        ("settings.py", "<module>"),
        ("test_mode.py", "_settings_files"),
        ("test_mode.py", "_settings_files"),
        ("test_mode.py", "_settings_files"),
    ]

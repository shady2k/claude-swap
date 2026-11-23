"""F32: consent and selection at the POSIX shim's launch boundary."""

import ast
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import cli, launch_policy, paths, session, test_mode, transparent
from claude_swap.locking import FileLock
from claude_swap.settings import set_setting

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="requires the POSIX PATH shim")

SESSION_ID = "d1f380f0-e77f-4692-981d-c8bcf63a5c92"
PREVIOUS = "synthetic message from the main login"
APPENDED = "synthetic reply from the selected recipient"


@pytest.fixture
def archive():
    projects = Path.home() / ".claude" / "projects"
    project = projects / "project"
    project.mkdir(mode=0o700, parents=True)
    projects.chmod(0o700)
    transcript = project / f"{SESSION_ID}.jsonl"
    transcript.write_text(PREVIOUS + "\n", encoding="utf-8")
    return projects, transcript


@pytest.fixture
def shim(tmp_path, monkeypatch, archive):
    projects, _ = archive
    programs = tmp_path / "bin"
    programs.mkdir()
    monkeypatch.setenv("HISTORY_TEST_HANDOFF", str(tmp_path / "handoff"))
    monkeypatch.setenv("HISTORY_TEST_READ", str(tmp_path / "read"))
    binary = programs / "claude"
    binary.write_text(
        f"#!{sys.executable} -I\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['HISTORY_TEST_HANDOFF']).touch()\n"
        "profile = Path(os.environ.get('CLAUDE_CONFIG_DIR', 'default'))\n"
        "status = {'profile': profile.name}\n"
        "if '--resume' in sys.argv:\n"
        "    sid = sys.argv[sys.argv.index('--resume') + 1]\n"
        "    history = profile / 'projects' / 'project' / (sid + '.jsonl')\n"
        "    Path(os.environ['HISTORY_TEST_READ']).touch()\n"
        "    status['previous'] = history.read_text(encoding='utf-8').splitlines()\n"
        "    with history.open('a', encoding='utf-8') as out:\n"
        f"        out.write({(APPENDED + chr(10))!r})\n"
        "print(json.dumps(status))\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    root = paths.get_backup_root()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    monkeypatch.setenv("PATH", f"{paths.get_shim_dir(root)}{os.pathsep}{programs}")
    for key in tuple(os.environ):
        if key.upper().endswith("_PROXY") or key.startswith("CLAUDE_SWAP_TEST_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv(test_mode.MODE, "1")
    monkeypatch.setenv(test_mode.ENDPOINT, "https://example.test")
    monkeypatch.setenv(test_mode.CLAUDE_BASE, "https://example.test")
    monkeypatch.setenv(test_mode.PROXY, "http://127.0.0.1:18080")
    monkeypatch.setenv(test_mode.ALLOW, str(binary))
    accounts = {}
    profiles = {}
    for slot in ("1", "2"):
        account = {"emailAddress": f"profile{slot}@example.test", "accountUuid": f"id-{slot}",
                   "organizationUuid": "org"}
        accounts[slot] = {"email": account["emailAddress"], "uuid": account["accountUuid"],
                          "organizationUuid": account["organizationUuid"]}
        profile = session.session_dir_for(root, slot, account["emailAddress"])
        profile.mkdir(mode=0o700, parents=True)
        (profile / ".claude.json").write_text(json.dumps({"oauthAccount": account}), encoding="utf-8")
        (profile / "projects").symlink_to(projects, target_is_directory=True)
        profiles[slot] = profile
    (root / "sequence.json").write_text(json.dumps({"accounts": accounts}), encoding="utf-8")
    set_setting(root, "run.shareHistory", "true")
    transparent.enable(root, accept_shared_history=True, pool=["2", "1"])
    return root, profiles


def _invoke(*args):
    return subprocess.run(["claude", *args], capture_output=True, text=True, timeout=10)


def _edit_policy(root, change):
    # Tests inject old/corrupt policy records not creatable through the CLI.
    path = root / "transparent.json"
    with FileLock(root / ".lock"):
        record = json.loads(path.read_text(encoding="utf-8"))
        change(record)
        record["rev"] += 1
        path.write_text(json.dumps(record), encoding="utf-8")


@pytest.mark.parametrize("args", [("-p", "hello"), ("--resume", SESSION_ID)])
@pytest.mark.parametrize("prior_revision", [False, True])
def test_consent_absent_or_unscoped_refuses_new_and_resume(shim, archive, args, prior_revision):
    root, _ = shim
    _edit_policy(root, lambda record: (record["historyZone"].pop("scope") if prior_revision
                                      else record.pop("historyZone")))
    result = _invoke(*args)
    assert result.returncode == 4 and not result.stdout
    assert "--accept-shared-history" in result.stderr
    assert archive[1].read_text(encoding="utf-8") == PREVIOUS + "\n"
    assert not (paths.get_shim_dir(root) / "launches.json").exists()


def test_replaced_slot_does_not_inherit_old_member_consent(shim):
    root, profiles = shim
    sequence = root / "sequence.json"
    data = json.loads(sequence.read_text(encoding="utf-8"))
    data["accounts"]["2"]["uuid"] = "a-different-recipient"
    sequence.write_text(json.dumps(data), encoding="utf-8")
    # Even a warm profile that matches the replacement cannot inherit consent.
    config = profiles["2"] / ".claude.json"
    profile = json.loads(config.read_text(encoding="utf-8"))
    profile["oauthAccount"]["accountUuid"] = "a-different-recipient"
    config.write_text(json.dumps(profile), encoding="utf-8")
    result = _invoke("-p", "hello")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"profile": profiles["1"].name}


def test_resume_shares_full_archive_with_member_but_never_journals_transcript(shim, archive):
    root, profiles = shim
    projects, transcript = archive
    result = _invoke("--resume", SESSION_ID)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"profile": profiles["2"].name, "previous": [PREVIOUS]}
    assert transcript.read_text(encoding="utf-8").splitlines() == [PREVIOUS, APPENDED]
    assert list(projects.rglob("*.jsonl")) == [transcript]
    transparent.set_pool(root, ["1"])
    result = _invoke("--resume", SESSION_ID)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"profile": profiles["1"].name, "previous": [PREVIOUS, APPENDED]}
    assert transcript.read_text(encoding="utf-8").splitlines() == [PREVIOUS, APPENDED, APPENDED]
    assert list(projects.rglob("*.jsonl")) == [transcript]
    journal = (paths.get_shim_dir(root) / "launches.json").read_text(encoding="utf-8")
    assert all(value not in journal for value in (SESSION_ID, PREVIOUS, APPENDED))


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o700])
def test_archive_permissions_checked_before_read_or_handoff(shim, archive, tmp_path, mode):
    root, profiles = shim
    projects, _ = archive
    projects.chmod(mode)
    # Ancestor permissions keep using fsguard's no-foreign-write rule.
    projects.parent.chmod(0o755)
    result = _invoke("--resume", SESSION_ID)
    allowed = mode == 0o700
    assert (tmp_path / "handoff").exists() is allowed
    assert (tmp_path / "read").exists() is allowed
    assert (paths.get_shim_dir(root) / "launches.json").exists() is allowed
    if allowed:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"profile": profiles["2"].name, "previous": [PREVIOUS]}
    else:
        assert result.returncode == 4 and not result.stdout


def test_archive_allows_link_above_home(shim, tmp_path, monkeypatch):
    _, profiles = shim
    home = Path.home()
    link = tmp_path / "linked-parent"
    link.symlink_to(home.parent, target_is_directory=True)
    monkeypatch.setenv("HOME", str(link / home.name))
    enabled = subprocess.run(
        [sys.executable, "-m", "claude_swap", "transparent", "enable", "--accept-shared-history"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
    )
    assert enabled.returncode == 0, enabled.stderr

    result = _invoke("--resume", SESSION_ID)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"profile": profiles["2"].name, "previous": [PREVIOUS]}


def test_launch_outside_route_does_not_require_private_archive(shim, archive, monkeypatch):
    projects, _ = archive
    projects.chmod(0o755)
    monkeypatch.delenv(test_mode.MODE)

    result = _invoke("--version")
    assert result.returncode == 0, result.stderr
    assert "outside the profile route" in result.stderr
    assert json.loads(result.stdout) == {"profile": "default"}


@pytest.mark.parametrize("component", ["projects", ".claude"])
@pytest.mark.parametrize("location", ["inside", "outside"])
def test_archive_path_rejects_links_before_handoff(shim, archive, tmp_path, component, location):
    projects, _ = archive
    directory = projects if component == "projects" else projects.parent
    elsewhere = (Path.home() if location == "inside" else tmp_path) / "linked-archive"
    directory.rename(elsewhere)
    directory.symlink_to(elsewhere, target_is_directory=True)
    result = _invoke("--resume", SESSION_ID)
    assert result.returncode == 4 and not result.stdout
    assert not (tmp_path / "handoff").exists()
    assert not (tmp_path / "read").exists()


def test_routed_launch_creates_missing_archive_privately(shim, archive):
    _, profiles = shim
    projects, _ = archive
    projects.rename(projects.with_name("old-projects"))
    (profiles["2"] / "projects").unlink()
    result = _invoke("-p", "hello")
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(projects.stat().st_mode) == 0o700
    assert (profiles["2"] / "projects").resolve() == projects


def test_launch_does_not_scan_archive_contents(shim, archive, tmp_path, monkeypatch):
    root, _ = shim
    projects, transcript = archive
    transcript.chmod(0o664)
    (projects / "unrelated").symlink_to(tmp_path / "missing")
    result = _invoke("--resume", SESSION_ID)
    assert result.returncode == 0, result.stderr
    monkeypatch.delenv(test_mode.MODE)
    result = _invoke("--version")
    assert result.returncode == 0, result.stderr
    assert "outside the profile route" in result.stderr


def test_foreign_archive_owner_refuses_before_publication(shim, archive, monkeypatch):
    root, _ = shim
    projects, transcript = archive
    original = Path.lstat

    def stat_with_foreign_owner(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == projects:
            fields = list(info)
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", stat_with_foreign_owner)
    with pytest.raises(transparent.ConfigError, match="current user"):
        launch_policy.archive()
    assert transcript.read_text(encoding="utf-8") == PREVIOUS + "\n"
    assert not (paths.get_shim_dir(root) / "launches.json").exists()


@pytest.mark.parametrize("accept", [False, True])
def test_enable_without_a_tty_requires_explicit_archive_consent(shim, accept):
    root, _ = shim
    transparent.disable(root)
    argv = [sys.executable, "-m", "claude_swap", "transparent", "enable"]
    if accept:
        argv.append("--accept-shared-history")
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    assert result.returncode == (0 if accept else 4), result.stderr
    assert (paths.get_shim_dir(root) / "claude").exists() is accept
    output = result.stdout + result.stderr
    assert "projects/" in output
    assert "Disabling transparent mode does not take back anything already sent." in output
    if accept:
        assert launch_policy.read(root)["historyZone"]["scope"] == "all-history-v1"


def _change_policy(root, change):
    if change == "pool":
        transparent.set_pool(root, ["1"])
    elif change == "members":
        _edit_policy(root, lambda record: record["historyZone"]["members"].pop("2"))
    elif change == "scope":
        _edit_policy(root, lambda record: record["historyZone"].update(scope="obsolete"))
    elif change == "revoke":
        transparent.revoke_history(root)
    elif change == "share-history":
        set_setting(root, "run.shareHistory", "false")
    elif change == "account-disabled":
        with FileLock(paths.account_lock_path(root)):
            sequence = root / "sequence.json"
            data = json.loads(sequence.read_text())
            data["accounts"]["2"]["disabled"] = True
            sequence.write_text(json.dumps(data))
    else:
        transparent.disable(root)


def _assert_lock_free(root):
    for path in (paths.account_lock_path(root), root / "settings.lock"):
        lock = FileLock(path, timeout=0)
        assert lock.acquire(), f"launch-boundary action held {path.name}"
        lock.release()


def test_policy_writer_uses_slot_lock_and_advances_revision(shim, monkeypatch):
    root, _ = shim
    original = launch_policy.atomic_write_text
    observed = []

    def observe_write(path, text, **kwargs):
        lock = FileLock(paths.account_lock_path(root), timeout=0)
        assert not lock.acquire()
        observed.append(json.loads(text)["rev"])
        return original(path, text, **kwargs)

    first = launch_policy.read(root)["rev"]
    monkeypatch.setattr(launch_policy, "atomic_write_text", observe_write)
    transparent.set_pool(root, ["1"])
    transparent.revoke_history(root)
    transparent.disable(root)
    transparent.enable(root, accept_shared_history=True)
    monkeypatch.delenv(test_mode.MODE)
    for key, value in [("claudePath", str(Path.home() / "claude")),
                       ("allowUnverified", "true"), ("requireProxy", "false")]:
        cli._config_command(["set", f"transparent.{key}", value])
    assert observed == list(range(first + 1, first + 8))
    assert launch_policy.read(root)["rev"] == observed[-1]


def test_archive_checks_are_outside_locks_except_publication(shim, monkeypatch):
    root, _ = shim
    directory = paths.get_shim_dir(root)
    marker = transparent._invocation_marker(directory, False)
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    monkeypatch.setattr(transparent.spawn, "require_supervision", lambda: None)
    def owned_launch(callback, *, publish, release, abort):
        publish()
        callback()
        release()
        return 0
    monkeypatch.setattr(transparent.spawn, "owned_launch", owned_launch)
    real = test_mode.claude_binary(backup_root=root)
    monkeypatch.setattr(test_mode, "claude_binary", lambda **_: real)
    monkeypatch.setattr(real, "handoff", lambda *args, **kwargs: _assert_lock_free(root))
    original = launch_policy.archive
    checked = []

    def observe_archive(**kwargs):
        if len(checked) < 2:
            _assert_lock_free(root)
        else:
            for path in (paths.account_lock_path(root), root / "settings.lock"):
                assert not FileLock(path, timeout=0).acquire()
        checked.append(None)
        return original(**kwargs)

    monkeypatch.setattr(launch_policy, "archive", observe_archive)
    transparent.enable(root, accept_shared_history=True)
    with pytest.raises(SystemExit) as done:
        transparent._launch(marker, ["-p", "hello"], root)
    assert done.value.code == 0
    assert len(checked) == 3


def test_only_launch_policy_update_writes_policy_file():
    # Pin the only two production references to the filename: the read and
    # the atomic write. A new reference, including an alias, needs review.
    source = Path(launch_policy.__file__).parent
    accesses = []
    for path in sorted(source.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or node.value != "transparent.json":
                continue
            call = parents[node]
            while not isinstance(call, (ast.Call, ast.Module)):
                call = parents[call]
            owner = call
            while not isinstance(owner, (ast.FunctionDef, ast.Module)):
                owner = parents[owner]
            accesses.append((
                path.relative_to(source).as_posix(), getattr(owner, "name", "<module>"),
                ast.unparse(call.func) if isinstance(call, ast.Call) else "<reference>",
            ))
    assert sorted(accesses) == [
        ("launch_policy.py", "read", "_read"),
        ("launch_policy.py", "update", "atomic_write_text"),
    ]


def test_summary_escapes_controls_and_bounds_label(shim):
    root, _ = shim
    sequence = root / "sequence.json"
    data = json.loads(sequence.read_text(encoding="utf-8"))
    data["accounts"]["2"]["email"] = "\x1b[0m\n\x85" + "x" * 200
    sequence.write_text(json.dumps(data), encoding="utf-8")
    transparent.set_pool(root, ["2"])
    result = _invoke("-p", "hello")
    assert result.returncode == 3 and not result.stdout
    label, reason = result.stderr.rstrip("\n").split(": ", 1)
    assert label.startswith(r"Account-2 (\x1b[0m\x0a\x85")
    assert len(label) == 120
    assert reason == "not a member of the current history zone; resets unknown"


@pytest.mark.parametrize("change", ["pool", "members", "scope", "revoke", "share-history", "disable", "account-disabled"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_policy_is_rechecked_at_publication_not_handoff(shim, monkeypatch, change, when):
    root, profiles = shim
    directory = paths.get_shim_dir(root)
    journal = directory / "launches.json"
    marker = transparent._invocation_marker(directory, False)
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    monkeypatch.setattr(transparent.spawn, "require_supervision", lambda: None)
    def owned_launch(callback, *, publish, release, abort):
        try:
            publish()
        except BaseException:
            abort()
            raise
        callback()
        release()
        return 0
    monkeypatch.setattr(transparent.spawn, "owned_launch", owned_launch)
    selected = []
    real = test_mode.claude_binary(backup_root=root)
    monkeypatch.setattr(test_mode, "claude_binary", lambda **_: real)

    def handoff(args, env, **_):
        _assert_lock_free(root)
        assert len(json.loads(journal.read_text(encoding="utf-8"))) == 1
        assert tuple(args[-2:]) == ("--resume", SESSION_ID)
        selected.append(Path(env["CLAUDE_CONFIG_DIR"]))

    monkeypatch.setattr(real, "handoff", handoff)
    if when == "after":
        journal_write = transparent._journal

        def change_after_running(*args):
            records = list((root / "profile-ownership" / "launches").glob("*.json"))
            assert len(records) == 1
            assert json.loads(records[0].read_text())["state"] == "running"
            return journal_write(*args)

        monkeypatch.setattr(transparent, "_journal", change_after_running)
        # Policy writers run outside publication locks, after the saved
        # running record but before handoff.
        def owned_launch(callback, *, publish, release, abort):
            try:
                publish()
            except BaseException:
                abort()
                raise
            _change_policy(root, change)
            callback()
            release()
            return 0
        monkeypatch.setattr(transparent.spawn, "owned_launch", owned_launch)
    if when == "before":
        prepare = transparent._prepare_launch
        changed = False

        def prepare_then_change(*args, **kwargs):
            nonlocal changed
            _assert_lock_free(root)
            prepared = prepare(*args, **kwargs)
            if not changed:
                assert not journal.exists()
                _change_policy(root, change)
                changed = True
            return prepared

        monkeypatch.setattr(transparent, "_prepare_launch", prepare_then_change)
    if when == "before" and change not in {"pool", "members", "account-disabled"}:
        with pytest.raises(transparent.ConfigError):
            transparent._launch(marker, ["--resume", SESSION_ID], root)
        assert not selected and not journal.exists()
    else:
        with pytest.raises(SystemExit) as done:
            transparent._launch(marker, ["--resume", SESSION_ID], root)
        assert done.value.code == 0
        assert selected == [profiles["1" if when == "before" else "2"]]
        assert SESSION_ID not in journal.read_text(encoding="utf-8")
    ownership = [json.loads(path.read_text(encoding="utf-8"))
                 for path in (root / "profile-ownership" / "launches").glob("*.json")]
    assert not ownership, [(record["state"], record.get("pid")) for record in ownership]


@pytest.mark.skipif(sys.platform != "linux", reason="direct routing is Linux-only")
def test_require_proxy_refuses_explicit_direct_before_publication(shim, monkeypatch, tmp_path):
    root, _ = shim
    set_setting(root, "transparent.requireProxy", "true")
    transparent.enable(root, accept_shared_history=True)
    ca = tmp_path / "unused.pem"
    ca.touch()
    monkeypatch.setenv(test_mode.CA, str(ca))
    monkeypatch.setenv(test_mode.ENDPOINT, "https://example.test:19443")
    monkeypatch.setenv(test_mode.CLAUDE_BASE, "https://example.test:19443")
    monkeypatch.setenv(test_mode.DIRECT, "127.0.0.1:19443")
    result = _invoke("-p", "hello")
    assert result.returncode == 4 and not result.stdout
    assert "direct routing is forbidden" in result.stderr
    assert not (paths.get_shim_dir(root) / "launches.json").exists()


def test_share_history_disabled_refuses_without_changing_setting(shim):
    root, _ = shim
    set_setting(root, "run.shareHistory", "false")
    result = _invoke("--resume", SESSION_ID)
    assert result.returncode == 4 and not result.stdout
    assert "run.shareHistory" in result.stderr
    assert json.loads((root / "settings.json").read_text(encoding="utf-8"))["run"]["shareHistory"] is False


@pytest.mark.skipif(sys.platform != "linux", reason="running publication requires Linux supervision")
def test_running_is_committed_before_launch_journal(shim, monkeypatch):
    root, _ = shim
    directory = paths.get_shim_dir(root)
    policy = launch_policy.read(root)
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    prepared = transparent._prepare_launch(
        root, directory, transparent._invocation_marker(directory, False),
        ["-p", "hello"], policy, launch_policy.accounts(root), test=True,
    )
    original = transparent._journal
    observed = []

    def journal_after_running(*args):
        records = list((root / "profile-ownership" / "launches").glob("*.json"))
        assert len(records) == 1
        assert json.loads(records[0].read_text())["state"] == "running"
        observed.append("running")
        return original(*args)

    monkeypatch.setattr(transparent, "_journal", journal_after_running)
    try:
        assert transparent._publish_launch(root, directory, policy, prepared)
        assert observed == ["running"]
    finally:
        with transparent.profile_ownership.ownership_lock(root):
            transparent.profile_ownership.release_locked(root, prepared.reservation["launchId"], confirmed_complete=True)


@pytest.mark.skipif(sys.platform != "linux", reason="running publication requires Linux supervision")
@pytest.mark.parametrize("order", ["running-first", "false-first"])
@pytest.mark.parametrize("key", ["run.shareHistory", "ui.theme"])
def test_f37_settings_write_serializes_with_running(shim, monkeypatch, order, key):
    """Events establish order; timeouts only diagnose a stuck child."""
    import multiprocessing

    root, _ = shim
    ctx = multiprocessing.get_context("fork")
    read_true, allow_read, attempted, written, running_saved = (ctx.Event() for _ in range(5))
    trace = ctx.Queue()
    results = ctx.Queue()
    directory = paths.get_shim_dir(root)
    marker = transparent._invocation_marker(directory, False)
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    original_check = transparent.check_transparent_history
    original_running = transparent.profile_ownership.mark_running_locked
    checks = 0

    def check(root):
        nonlocal checks
        checks += 1
        original_check(root)
        if checks == 2 and order == "running-first":
            read_true.set()
            assert allow_read.wait(10), "publisher was not released"

    def running(*args, **kwargs):
        original_running(*args, **kwargs)
        assert not written.is_set()
        running_saved.set()
        trace.put("running")

    def owned_launch(callback, *, publish, release, abort):
        try:
            publish()
            callback()
            release()
            return 0
        except BaseException:
            abort()
            raise

    def publisher():
        transparent.check_transparent_history = check
        transparent.profile_ownership.mark_running_locked = running
        transparent.spawn.owned_launch = owned_launch
        real = test_mode.claude_binary(backup_root=root)
        test_mode.claude_binary = lambda **_: real
        def handoff(*args, **kwargs):
            _assert_lock_free(root)
            trace.put("handoff")
        real.handoff = handoff
        try:
            transparent._launch(marker, ["-p", "hello"], root)
        except SystemExit as exc:
            results.put(exc.code)
        except transparent.ConfigError:
            results.put(4)

    def writer():
        assert read_true.wait(10), "publisher did not reach settings read"
        lock_path = root / "settings.lock"
        lock = FileLock(lock_path, timeout=0)
        acquired = lock.acquire()
        if acquired:
            lock.release()
        results.put(("probe", acquired))
        attempted.set()
        if key == "ui.theme":
            set_setting(root, key, "light")
        set_setting(root, "run.shareHistory", "false")
        assert running_saved.is_set() is (order == "running-first")
        trace.put("false")
        written.set()

    # In the reverse order the writer must finish outside the publication
    # locks, not from a hook already inside them.
    if order == "false-first":
        original_prepare = transparent._prepare_launch
        def prepare(*args, **kwargs):
            result = original_prepare(*args, **kwargs)
            read_true.set()
            assert written.wait(10), "writer did not finish before publication"
            return result
        monkeypatch.setattr(transparent, "_prepare_launch", prepare)

    children = [ctx.Process(target=publisher), ctx.Process(target=writer)]
    try:
        for child in children:
            child.start()
        assert attempted.wait(10), "writer did not probe the publication lock"
        allow_read.set()
        for child in children:
            child.join(15)
            assert child.exitcode == 0, "child failed or hung"
        outcomes = [results.get(timeout=2) for _ in range(2)]
        assert ("probe", order == "false-first") in outcomes
        expected_code = 0 if order == "running-first" else 4
        assert expected_code in outcomes
        count = 3 if order == "running-first" else 1
        entries = [trace.get(timeout=2) for _ in range(count)]
        setting = "false"
        if order == "running-first":
            assert entries.count("running") == entries.count("handoff") == 1
            assert running_saved.is_set() and written.is_set()
        else:
            assert entries == [setting]
            assert trace.empty()
            assert not (directory / "launches.json").exists()
        assert not list((root / "profile-ownership" / "launches").glob("*.json"))
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
            child.join(5)


@pytest.mark.parametrize("value", ["{", "[]", '{"run": null}', '{"run": {"shareHistory": "true"}}'])
def test_corrupt_settings_at_publication_refuses(shim, monkeypatch, value):
    root, _ = shim
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    prepare = transparent._prepare_launch
    def corrupt_after_prepare(*args, **kwargs):
        result = prepare(*args, **kwargs)
        (root / "settings.json").write_text(value)
        return result
    monkeypatch.setattr(transparent, "_prepare_launch", corrupt_after_prepare)
    # This wrapper keeps the real abort path but never hands off a process.
    def owned_launch(callback, *, publish, release, abort):
        try:
            publish()
            pytest.fail("corrupt settings allowed publication")
        finally:
            abort()
    monkeypatch.setattr(transparent.spawn, "owned_launch", owned_launch)
    with pytest.raises(transparent.ConfigError):
        transparent._launch(transparent._invocation_marker(paths.get_shim_dir(root), False), ["-p", "hello"], root)
    assert not (paths.get_shim_dir(root) / "launches.json").exists()
    assert not list((root / "profile-ownership" / "launches").glob("*.json"))


@pytest.mark.parametrize("value", ["{}", '{"run": {}}'])
def test_absent_share_history_key_uses_default(shim, value):
    root, _ = shim
    (root / "settings.json").write_text(value)
    result = _invoke("-p", "hello")
    assert result.returncode == 0, result.stderr

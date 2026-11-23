"""F32: consent and selection at the POSIX shim's launch boundary."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import launch_policy, paths, session, test_mode, transparent
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
    binary = programs / "claude"
    binary.write_text(
        f"#!{sys.executable} -I\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "profile = Path(os.environ['CLAUDE_CONFIG_DIR'])\n"
        "status = {'profile': profile.name}\n"
        "if '--resume' in sys.argv:\n"
        "    sid = sys.argv[sys.argv.index('--resume') + 1]\n"
        "    history = profile / 'projects' / 'project' / (sid + '.jsonl')\n"
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


@pytest.mark.parametrize("redirect", ["outside-home", "group-writable", "linked-transcript"])
def test_unsafe_archive_refuses_before_handoff(shim, archive, tmp_path, redirect):
    projects, transcript = archive
    if redirect == "outside-home":
        elsewhere = tmp_path / "external-archive"
        projects.rename(elsewhere)
        projects.symlink_to(elsewhere, target_is_directory=True)
    elif redirect == "linked-transcript":
        elsewhere = tmp_path / "external-transcript.jsonl"
        transcript.rename(elsewhere)
        transcript.symlink_to(elsewhere)
    else:
        projects.chmod(0o770)
    result = _invoke("--resume", SESSION_ID)
    assert result.returncode == 4 and not result.stdout
    assert transcript.read_text(encoding="utf-8") == PREVIOUS + "\n"


def test_foreign_archive_owner_refuses_before_publication(shim, archive, monkeypatch):
    root, _ = shim
    projects, transcript = archive
    original = Path.stat

    def stat_with_foreign_owner(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == projects:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
        return info

    monkeypatch.setattr(Path, "stat", stat_with_foreign_owner)
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
    assert "projects/" in result.stdout + result.stderr


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
    assert observed == [first + 1, first + 2]


@pytest.mark.parametrize("change", ["pool", "members", "scope", "revoke", "share-history", "disable"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_policy_is_rechecked_at_publication_not_handoff(shim, monkeypatch, change, when):
    root, profiles = shim
    directory = paths.get_shim_dir(root)
    journal = directory / "launches.json"
    marker = transparent._invocation_marker(directory, False)
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    selected = []
    real = test_mode.claude_binary(backup_root=root)
    monkeypatch.setattr(test_mode, "claude_binary", lambda **_: real)

    def handoff(args, env, **_):
        _assert_lock_free(root)
        assert len(json.loads(journal.read_text(encoding="utf-8"))) == 1
        if when == "after":
            _change_policy(root, change)
        assert tuple(args[-2:]) == ("--resume", SESSION_ID)
        selected.append(Path(env["CLAUDE_CONFIG_DIR"]))

    monkeypatch.setattr(real, "handoff", handoff)
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
    if when == "before" and change not in {"pool", "members"}:
        with pytest.raises(transparent.ConfigError):
            transparent._launch(marker, ["--resume", SESSION_ID], root)
        assert not selected and not journal.exists()
    else:
        transparent._launch(marker, ["--resume", SESSION_ID], root)
        assert selected == [profiles["1" if when == "before" else "2"]]
        assert SESSION_ID not in journal.read_text(encoding="utf-8")


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

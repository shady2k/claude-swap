"""F32: consent and selection at the POSIX shim's launch boundary."""

import ast
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_swap import cli, launch_policy, paths, real_claude, session, test_mode, transparent
from claude_swap.locking import FileLock
from claude_swap.settings import set_setting

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="requires the POSIX PATH shim")

SESSION_ID = "d1f380f0-e77f-4692-981d-c8bcf63a5c92"
PREVIOUS = "synthetic message from the main login"
APPENDED = "synthetic reply from the selected recipient"
RECEIVER_REPLY = "reply returned by independent receiver"
NEW_MESSAGE = "synthetic continuation from the selected recipient"
FOLLOW_UP = "synthetic follow-up from the other participant"
C_SESSION_ID = "0b7c2e5a-1c4d-4f0b-9a67-3e2d8f1c6b54"
C_PREVIOUS = "synthetic message from the excluded account"


@pytest.fixture
def archive():
    projects = Path.home() / ".claude" / "projects"
    project = projects / "project"
    project.mkdir(mode=0o700, parents=True)
    projects.chmod(0o700)
    transcript = project / f"{SESSION_ID}.jsonl"
    transcript.write_text(PREVIOUS + "\n", encoding="utf-8")
    return projects, transcript


def _add_profile(root, projects, slot, *, link_history=True):
    account = {"emailAddress": f"profile{slot}@example.test", "accountUuid": f"id-{slot}",
               "organizationUuid": "org"}
    profile = session.session_dir_for(root, slot, account["emailAddress"])
    profile.mkdir(mode=0o700, parents=True)
    (profile / ".claude.json").write_text(json.dumps({"oauthAccount": account}), encoding="utf-8")
    if link_history:
        (profile / "projects").symlink_to(projects, target_is_directory=True)
    sequence = root / "sequence.json"
    data = json.loads(sequence.read_text(encoding="utf-8")) if sequence.exists() else {"accounts": {}}
    data["accounts"][slot] = {"email": account["emailAddress"], "uuid": account["accountUuid"],
                              "organizationUuid": account["organizationUuid"]}
    sequence.write_text(json.dumps(data), encoding="utf-8")
    return profile


@pytest.fixture
def shim(tmp_path, monkeypatch, archive):
    projects, _ = archive
    programs = tmp_path / "bin"
    programs.mkdir()
    monkeypatch.setenv("HISTORY_TEST_HANDOFF", str(tmp_path / "handoff"))
    monkeypatch.setenv("HISTORY_TEST_READ", str(tmp_path / "read"))
    monkeypatch.setenv("HISTORY_TEST_REQUEST", str(tmp_path / "request"))
    monkeypatch.setenv("HISTORY_TEST_SESSION_ID", SESSION_ID)
    monkeypatch.setenv("HISTORY_TEST_EXPECTED_EMAIL", "profile2@example.test")
    binary = programs / "claude"
    binary.write_text(
        f"#!{sys.executable} -I\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['HISTORY_TEST_HANDOFF']).touch()\n"
        "profile = Path(os.environ.get('CLAUDE_CONFIG_DIR', 'default'))\n"
        "status = {'profile': profile.name}\n"
        "request = {'profile': profile.name, 'argv': sys.argv[1:], 'history': []}\n"
        "if sys.argv[-3:] == ['auth', 'status', '--json']:\n"
        "    print(json.dumps({'loggedIn': True, 'authMethod': 'claude.ai', 'email': os.environ.get('HISTORY_TEST_EXPECTED_EMAIL', 'profile2@example.test'), 'orgId': 'org'}))\n"
        "    raise SystemExit(0)\n"
        "if '--resume' in sys.argv:\n"
        "    sid = sys.argv[sys.argv.index('--resume') + 1]\n"
        "    history = profile / 'projects' / 'project' / (sid + '.jsonl')\n"
        "    Path(os.environ['HISTORY_TEST_READ']).touch()\n"
        "    lines = history.read_text(encoding='utf-8').splitlines()\n"
        "    status['previous'] = request['history'] = lines\n"
        "    appended = []\n"
        "    if '-p' in sys.argv or '--print' in sys.argv:\n"
        "        appended.append(sys.argv[-1])\n"
        "        request['prompt'] = sys.argv[-1]\n"
        "    receiver = os.environ.get('HISTORY_TEST_RECEIVER')\n"
        "    if receiver:\n"
        "        import subprocess\n"
        "        payload = json.dumps({'history': lines, 'prompt': request.get('prompt')})\n"
        "        response = subprocess.run([sys.executable, '-I', receiver], input=payload, capture_output=True, text=True, check=True)\n"
        "        reply = json.loads(response.stdout)['reply']\n"
        "    else:\n"
        f"        reply = {APPENDED!r}\n"
        "    appended.append(reply)\n"
        "    with history.open('a', encoding='utf-8') as out:\n"
        "        out.writelines(line + '\\n' for line in appended)\n"
        "elif os.environ.get('HISTORY_TEST_START') == '1':\n"
        "    project = profile / 'projects' / 'project'\n"
        "    project.mkdir(mode=0o700, parents=True, exist_ok=True)\n"
        "    prompt = sys.argv[-1] if '-p' in sys.argv or '--print' in sys.argv else 'start'\n"
        "    sid = os.environ['HISTORY_TEST_SESSION_ID']\n"
        "    (project / (sid + '.jsonl')).write_text(\n"
        f"        prompt + '\\n' + {APPENDED!r} + '\\n', encoding='utf-8',\n"
        "    )\n"
        "    request['prompt'] = prompt\n"
        "    status['session'] = sid\n"
        "    if os.environ.get('HISTORY_TEST_START_RESULT'):\n"
        "        Path(os.environ['HISTORY_TEST_START_RESULT']).write_text(json.dumps(status), encoding='utf-8')\n"
        "Path(os.environ['HISTORY_TEST_REQUEST']).write_text(json.dumps(request), encoding='utf-8')\n"
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
    profiles = {slot: _add_profile(root, projects, slot, link_history=slot != "1")
                for slot in ("1", "2")}
    set_setting(root, "run.shareHistory", "true")
    transparent.enable(root, accept_shared_history=True, pool=["2", "1"])
    return root, profiles


def _invoke(*args):
    return subprocess.run(["claude", *args], capture_output=True, text=True, timeout=10)


def _transcript_files(projects):
    return sorted(path.relative_to(projects).as_posix() for path in projects.rglob("*.jsonl"))


def _request(tmp_path):
    return json.loads((tmp_path / "request").read_text(encoding="utf-8"))


@pytest.fixture
def history_receiver(shim, tmp_path, monkeypatch):
    """Independent child receives JSON over stdin; no HTTP listener is needed."""
    def no_socket(*_args, **_kwargs):
        pytest.fail("ordinary history receiver must not open sockets")

    monkeypatch.setattr(socket, "socket", no_socket)
    receiver = tmp_path / "receiver.py"
    accepted = tmp_path / "accepted.jsonl"
    receiver.write_text(
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "request = json.load(sys.stdin)\n"
        f"with Path({str(accepted)!r}).open('a', encoding='utf-8') as out:\n"
        "    out.write(json.dumps(request) + '\\n')\n"
        "if os.environ.get('HISTORY_TEST_REJECT') == '1':\n"
        "    raise SystemExit(17)\n"
        f"print(json.dumps({{'reply': {RECEIVER_REPLY!r}}}))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HISTORY_TEST_RECEIVER", str(receiver))
    return accepted


def _accepted(receiver):
    return [json.loads(line) for line in receiver.read_text(encoding="utf-8").splitlines()]


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

    def remove_consent(record):
        if prior_revision:
            record["historyZone"].pop("scope")
            record["rev"] = 6
        else:
            record.pop("historyZone")

    _edit_policy(root, remove_consent)
    if prior_revision:
        assert json.loads((root / "transparent.json").read_text(encoding="utf-8"))["rev"] == 7
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


def test_resume_shares_full_archive_with_member_but_never_journals_transcript(
    shim, archive, tmp_path, monkeypatch, history_receiver,
):
    root, profiles = shim
    projects, transcript = archive
    transcript.unlink()
    monkeypatch.setenv("HISTORY_TEST_START", "1")
    transparent.enable(root, accept_shared_history=True, pool=["1"])
    started = json.loads(_invoke("-p", PREVIOUS).stdout)
    assert started == {"profile": profiles["1"].name, "session": SESSION_ID}
    assert transcript.read_text(encoding="utf-8").splitlines() == [PREVIOUS, APPENDED]
    ids_before = _transcript_files(projects)
    assert ids_before == [f"project/{SESSION_ID}.jsonl"]
    assert launch_policy.read(root)["historyZone"]["scope"] == launch_policy.HISTORY_SCOPE
    transparent.enable(root, accept_shared_history=True, pool=["2", "1"])
    assert set(launch_policy.read(root)["historyZone"]["members"]) == {"1", "2"}

    result = _invoke("--resume", SESSION_ID, "-p", NEW_MESSAGE)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "profile": profiles["2"].name, "previous": [PREVIOUS, APPENDED],
    }
    # The recipient's local mock accepted A's earlier reply and the new turn.
    request = _request(tmp_path)
    assert _accepted(history_receiver) == [{"history": [PREVIOUS, APPENDED], "prompt": NEW_MESSAGE}]
    assert request["profile"] == profiles["2"].name
    assert request["history"] == [PREVIOUS, APPENDED]
    assert request["prompt"] == NEW_MESSAGE
    assert request["argv"][-2:] == ["-p", NEW_MESSAGE]
    assert transcript.read_text(encoding="utf-8").splitlines() == [
        PREVIOUS, APPENDED, NEW_MESSAGE, RECEIVER_REPLY,
    ]
    assert _transcript_files(projects) == ids_before

    transparent.set_pool(root, ["1"])
    result = _invoke("--resume", SESSION_ID, "-p", FOLLOW_UP)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "profile": profiles["1"].name,
        "previous": [PREVIOUS, APPENDED, NEW_MESSAGE, RECEIVER_REPLY],
    }
    request = _request(tmp_path)
    assert request["profile"] == profiles["1"].name
    assert request["history"] == [PREVIOUS, APPENDED, NEW_MESSAGE, RECEIVER_REPLY]
    assert request["prompt"] == FOLLOW_UP
    assert transcript.read_text(encoding="utf-8").splitlines() == [
        PREVIOUS, APPENDED, NEW_MESSAGE, RECEIVER_REPLY, FOLLOW_UP, RECEIVER_REPLY,
    ]
    assert _transcript_files(projects) == ids_before
    journal = (paths.get_shim_dir(root) / "launches.json").read_text(encoding="utf-8")
    assert all(value not in journal for value in (
        SESSION_ID, PREVIOUS, NEW_MESSAGE, FOLLOW_UP, APPENDED, RECEIVER_REPLY,
    ))


def test_resume_receiver_rejection_fails_before_transcript_update(shim, history_receiver, archive, monkeypatch):
    monkeypatch.setenv("HISTORY_TEST_REJECT", "1")
    result = _invoke("--resume", SESSION_ID, "-p", NEW_MESSAGE)
    assert result.returncode != 0
    assert _accepted(history_receiver) == [{"history": [PREVIOUS], "prompt": NEW_MESSAGE}]
    assert archive[1].read_text(encoding="utf-8") == PREVIOUS + "\n"


def test_excluded_member_history_continues_with_remaining_participant(shim, archive, tmp_path):
    root, profiles = shim
    projects, _ = archive
    profile_c = _add_profile(root, projects, "3")
    transparent.enable(root, accept_shared_history=True, pool=["3", "2", "1"])
    assert set(launch_policy.read(root)["historyZone"]["members"]) == {"1", "2", "3"}
    c_transcript = projects / "project" / f"{C_SESSION_ID}.jsonl"
    c_transcript.write_text(C_PREVIOUS + "\n", encoding="utf-8")
    ids_before = _transcript_files(projects)

    transparent.set_pool(root, ["2", "1"])
    policy = launch_policy.read(root)
    assert policy["pool"] == ["2", "1"]
    assert "3" not in policy["historyZone"]["members"]
    assert profile_c.exists()

    result = _invoke("--resume", C_SESSION_ID, "-p", NEW_MESSAGE)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"profile": profiles["2"].name, "previous": [C_PREVIOUS]}
    request = _request(tmp_path)
    assert request["profile"] == profiles["2"].name
    assert request["history"] == [C_PREVIOUS]
    assert request["prompt"] == NEW_MESSAGE
    assert c_transcript.read_text(encoding="utf-8").splitlines() == [C_PREVIOUS, NEW_MESSAGE, APPENDED]
    assert _transcript_files(projects) == ids_before

    transparent.set_pool(root, ["1"])
    assert launch_policy.read(root)["pool"] == ["1"]
    result = _invoke("--resume", C_SESSION_ID, "-p", FOLLOW_UP)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "profile": profiles["1"].name, "previous": [C_PREVIOUS, NEW_MESSAGE, APPENDED],
    }
    request = _request(tmp_path)
    assert request["profile"] == profiles["1"].name
    assert request["history"] == [C_PREVIOUS, NEW_MESSAGE, APPENDED]
    assert request["prompt"] == FOLLOW_UP
    assert c_transcript.read_text(encoding="utf-8").splitlines() == [
        C_PREVIOUS, NEW_MESSAGE, APPENDED, FOLLOW_UP, APPENDED,
    ]
    assert _transcript_files(projects) == ids_before
    journal = (paths.get_shim_dir(root) / "launches.json").read_text(encoding="utf-8")
    assert all(value not in journal for value in (
        C_SESSION_ID, C_PREVIOUS, NEW_MESSAGE, FOLLOW_UP, APPENDED,
    ))


def test_run_created_outside_zone_history_resumes_under_b(shim, archive, monkeypatch):
    root, profiles = shim
    projects, transcript = archive
    transcript.unlink()
    assert not (profiles["1"] / "projects").is_symlink()
    assert not (profiles["1"] / "projects").exists()
    start_result = Path(os.environ["HISTORY_TEST_HANDOFF"]).with_name("start-result")
    monkeypatch.setenv("HISTORY_TEST_START", "1")
    monkeypatch.setenv("HISTORY_TEST_START_RESULT", str(start_result))
    transparent.enable(root, accept_shared_history=True, pool=["2"])

    from claude_swap.switcher import ClaudeAccountSwitcher
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._write_account_credentials("1", "profile1@example.test", json.dumps({
        "claudeAiOauth": {"accessToken": "synthetic", "refreshToken": "", "expiresAt": 0},
    }))
    switcher._write_account_config("1", "profile1@example.test", json.dumps({
        "oauthAccount": {"emailAddress": "profile1@example.test", "accountUuid": "id-1", "organizationUuid": "org"},
    }))
    monkeypatch.setenv("HISTORY_TEST_EXPECTED_EMAIL", "profile1@example.test")
    # Exercise cli.py's cswap run dispatch and let the synthetic Claude child
    # create the transcript; only terminal handoff is intercepted.
    def handoff(self, args, env, *, job=False):
        assert args[0] == "--settings"
        layer = json.loads(args[1])["env"]
        assert layer[test_mode.CLAUDE_BASE] == "https://example.test"
        assert env[test_mode.CLAUDE_BASE] == layer[test_mode.CLAUDE_BASE]
        result = subprocess.run([str(self.path), *args], env=env, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        raise SystemExit(0)

    monkeypatch.setattr(real_claude.RealClaude, "handoff", handoff)
    monkeypatch.setenv("CONTAINER", "1")
    args = SimpleNamespace(account="1", debug=False, no_share=False, share_history=None, require_session=False)
    with pytest.raises(SystemExit):
        cli._run_launch(args, ["-p", PREVIOUS])
    sid = json.loads(start_result.read_text(encoding="utf-8"))["session"]
    assert transcript.read_text(encoding="utf-8").splitlines() == [PREVIOUS, APPENDED]
    ids_before = _transcript_files(projects)

    monkeypatch.setenv("HISTORY_TEST_EXPECTED_EMAIL", "profile2@example.test")
    result = _invoke("--resume", sid, "-p", NEW_MESSAGE)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["profile"] == profiles["2"].name
    assert _request(Path(os.environ["HISTORY_TEST_REQUEST"]).parent)["history"] == [PREVIOUS, APPENDED]
    assert transcript.read_text(encoding="utf-8").splitlines() == [PREVIOUS, APPENDED, NEW_MESSAGE, APPENDED]
    assert _transcript_files(projects) == ids_before
    journal = (paths.get_shim_dir(root) / "launches.json").read_text(encoding="utf-8")
    assert all(value not in journal for value in (sid, PREVIOUS, NEW_MESSAGE, APPENDED))


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


def test_archive_rejects_reparse_directory_before_read_or_handoff(shim, archive, tmp_path, monkeypatch):
    root, _ = shim
    projects, transcript = archive
    original = Path.lstat

    class ReparseInfo:
        def __init__(self, info):
            self._info = info
            self.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT

        def __getattr__(self, name):
            return getattr(self._info, name)

    def stat_as_junction(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        return ReparseInfo(info) if path == projects else info

    monkeypatch.setattr(Path, "lstat", stat_as_junction)
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    def fail_if_handed_off(self, args, env, *, job=False):
        (tmp_path / "handoff=token").touch()
        pytest.fail("handoff reached")

    monkeypatch.setattr(real_claude.RealClaude, "handoff", fail_if_handed_off)
    marker = transparent._invocation_marker(paths.get_shim_dir(root), False)
    with pytest.raises(transparent.ConfigError, match="not a link or junction"):
        transparent._launch(marker, ["--resume", SESSION_ID], root)
    assert not (tmp_path / "read").exists()
    assert not (tmp_path / "handoff").exists()
    assert not (tmp_path / "handoff=token").exists()
    assert transcript.read_text(encoding="utf-8") == PREVIOUS + "\n"
    assert not (paths.get_shim_dir(root) / "launches.json").exists()


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


def test_foreign_archive_owner_refuses_before_read_or_handoff(shim, archive, tmp_path, monkeypatch):
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
    monkeypatch.setattr(transparent, "sys", SimpleNamespace(
        platform=sys.platform, flags=SimpleNamespace(isolated=True), stderr=sys.stderr,
    ))
    marker = transparent._invocation_marker(paths.get_shim_dir(root), False)
    with pytest.raises(transparent.ConfigError, match="current user"):
        transparent._launch(marker, ["--resume", SESSION_ID], root)
    assert not (tmp_path / "read").exists()
    assert not (tmp_path / "handoff").exists()
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
    assert "entire projects/ archive" in output
    assert "default login and cswap run" in output
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
    monkeypatch.setattr(transparent.spawn, "require_supervision", lambda: None)
    def owned_launch(callback, *, publish, release, abort):
        publish()
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
        with pytest.raises(SystemExit) as done:
            transparent._launch(marker, ["--resume", SESSION_ID], root)
        assert done.value.code == 0
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


def test_share_history_disabled_refuses_without_reading_or_changing_setting(shim, archive, tmp_path):
    root, _ = shim
    _, transcript = archive
    set_setting(root, "run.shareHistory", "false")
    result = _invoke("--resume", SESSION_ID, "-p", NEW_MESSAGE)
    assert result.returncode == 4 and not result.stdout
    assert "run.shareHistory" in result.stderr
    assert not (tmp_path / "read").exists()
    assert not (tmp_path / "handoff").exists()
    assert transcript.read_text(encoding="utf-8") == PREVIOUS + "\n"
    assert json.loads((root / "settings.json").read_text(encoding="utf-8"))["run"]["shareHistory"] is False

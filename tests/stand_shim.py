"""Exercise the installed POSIX shim under the stand's process-tree audit."""

from __future__ import annotations

import http.client
import io
import json
import os
import runpy
import ssl
import subprocess
import sys
from contextlib import closing, redirect_stdout
from pathlib import Path
from urllib.parse import urlsplit

from tests import stand_mock as mock

PRINT_ARGS = ["--model", "auth", "-p", "--", 'a "quoted" prompt', "--settings=prompt-data"]
ESCAPE = ("192.0.2.1", 443)  # TEST-NET-1, exercised only in a fresh net namespace.
SESSION_ID = "8c7e5a38-8e86-4c95-a5d7-cebddd898e9a"
PRIOR = "prior synthetic reply"
THREAD = Path("stand-project") / f"{SESSION_ID}.jsonl"


def command(scenario: str) -> list[str]:
    from tests.stand_linux import DIRECT_SCENARIOS

    if scenario in DIRECT_SCENARIOS:
        return ["claude", "--resume", SESSION_ID, *PRINT_ARGS]
    return ["claude", *{
        "client_settings": ["--settings={}"],
        "auth": ["auth", "status", "--json"],
        "update": ["update"],
        "unknown": ["future-subcommand"],
    }.get(scenario, PRINT_ARGS)]


def shim_path(root: Path) -> Path:
    from claude_swap.paths import get_shim_dir

    return get_shim_dir(root / "data" / "claude-swap") / "claude"


def fake_path(root: Path) -> Path:
    return root / "bin" / "claude"


def is_layer_path(root: Path, argument: str) -> bool:
    path = Path(argument)
    return path.is_absolute() and path.resolve().is_relative_to(root / "data" / "claude-swap")


def _resume_direct(layer: dict, *, refused: bool) -> None:
    from claude_swap import paths, session, test_mode

    assert not {key.upper() for key in os.environ.keys() | layer.keys()} & {
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    }
    assert layer[test_mode.CLAUDE_BASE] == mock.DIRECT_BASE
    assert layer[test_mode.DIRECT] == os.environ[test_mode.DIRECT]
    assert layer["NODE_EXTRA_CA_CERTS"] == os.environ[test_mode.CA]
    profile = Path(os.environ["CLAUDE_CONFIG_DIR"])
    email = _email("2")
    assert profile == session.session_dir_for(paths.get_backup_root(), "2", email)
    identity = json.loads((profile / ".claude.json").read_text())["oauthAccount"]
    assert identity["emailAddress"] == email
    thread = profile / "projects" / THREAD
    messages = [json.loads(line) for line in thread.read_text().splitlines()]
    body = json.dumps({"profile": "2", "session": SESSION_ID, "messages": messages}).encode()

    # Independent fake-Claude client: consume the pinned layer and retain the
    # named TLS authority without allowing the resolver to choose a target.
    address = mock.require_direct_target()

    def restrict_route(event, values):
        if event == "socket.connect" and values[1] != address:
            raise AssertionError("fake Claude attempted an unapproved connection")
        if event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}:
            raise AssertionError("fake Claude attempted DNS")

    sys.addaudithook(restrict_route)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=layer["NODE_EXTRA_CA_CERTS"])
    base = urlsplit(layer[test_mode.CLAUDE_BASE])
    with closing(http.client.HTTPSConnection(base.hostname, base.port, context=context)) as conn:
        conn._create_connection = lambda *_: mock._dial(address)
        try:
            conn.request("POST", mock.MESSAGES, body, {"Content-Type": "application/json"})
        except ConnectionRefusedError:
            assert refused
            print("null")
            raise SystemExit(17) from None
        assert not refused
        with conn.getresponse() as response:
            assert response.status == 200
            reply = json.load(response)["reply"]
    with thread.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"role": "assistant", "content": reply}) + "\n")
    print(json.dumps({"profile": "2", "session": SESSION_ID, "reply": reply}))


def _fake_main(scenario: str) -> None:
    from tests.stand_linux import DIRECT_SCENARIOS, require_isolation

    require_isolation()
    from claude_swap import test_mode

    assert sys.flags.isolated
    assert sys.argv[1] == "--settings"
    path = Path(sys.argv[2])
    assert is_layer_path(Path(os.environ["CSWAP_STAND_ROOT"]), str(path))
    assert path.stat().st_mode & 0o077 == 0
    assert sys.argv[3:] == command(scenario)[1:]
    layer = json.loads(path.read_text(encoding="utf-8"))["env"]
    assert "NO_PROXY" not in os.environ and "ANTHROPIC_API_KEY" not in os.environ
    if scenario in DIRECT_SCENARIOS:
        _resume_direct(layer, refused=scenario == "direct_refused")
        return
    assert layer[test_mode.CLAUDE_BASE] == mock.BASE
    assert layer[test_mode.PROXY] == f"http://{mock.PROXY[0]}:{mock.PROXY[1]}"
    if scenario == "shim_positive":
        assert layer["NODE_EXTRA_CA_CERTS"] == os.environ[test_mode.CA]
        print(json.dumps(mock._https_probe()))
    elif scenario == "shim_direct":
        mock._attempt_direct(Path(layer["NODE_EXTRA_CA_CERTS"]))
        print("null")
    elif scenario == "escape":
        import errno
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect(ESCAPE)
            except OSError as exc:
                assert exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH)
            else:
                raise AssertionError("stand has an external route")
    else:
        raise AssertionError("a rejected form reached Claude")


def _entry(*args: str) -> None:
    saved = sys.argv
    sys.argv = ["cswap", *args]
    try:
        runpy.run_module("claude_swap", run_name="__main__", alter_sys=True)
    finally:
        sys.argv = saved


def _email(slot: str) -> str:
    return f"stand-{slot}@example.test"


def seed_profiles(pool: tuple[str, ...]) -> Path:
    from claude_swap import paths, session

    root = paths.get_backup_root()
    assert root.is_relative_to(Path(os.environ["CSWAP_STAND_ROOT"]))
    archive = paths.get_default_claude_config_home() / "projects"
    archive.parent.mkdir(mode=0o700, exist_ok=True)
    archive.mkdir(mode=0o700)
    (archive / THREAD.parent).mkdir(mode=0o700)
    (archive / THREAD).write_text(json.dumps({"role": "assistant", "content": PRIOR}) + "\n")
    accounts = {}
    for slot in pool:
        email = _email(slot)
        account_id = f"c5579c9f-0495-4ba8-bfbe-{int(slot):012d}"
        profile = session.session_dir_for(root, slot, email)
        profile.mkdir(parents=True, mode=0o700)
        accounts[slot] = {"email": email, "organizationUuid": "", "uuid": account_id}
        (profile / ".claude.json").write_text(json.dumps({"oauthAccount": {
            "emailAddress": email, "organizationUuid": "", "accountUuid": account_id,
        }}))
        (profile / "projects").symlink_to(archive, target_is_directory=True)
    (root / "sequence.json").write_text(json.dumps({"accounts": accounts}))
    return archive


def install(fallback: Path, pool: tuple[str, ...] = ()) -> None:
    from claude_swap import paths

    # Exercise the cswap admin entry point before adding anything to PATH.
    options = [option for slot in pool for option in ("--account", slot)]
    with redirect_stdout(io.StringIO()):
        _entry("transparent", "enable", "--accept-shared-history", *options)
    shim = paths.get_shim_dir() / "claude"
    assert shim == shim_path(Path(os.environ["CSWAP_STAND_ROOT"])) and shim.is_file()
    os.environ["PATH"] = f"{shim.parent}{os.pathsep}{fallback.parent}"


def launch(scenario: str, ca: Path | None = None) -> subprocess.CompletedProcess[str]:
    from claude_swap import paths, test_mode
    from tests.stand_linux import DIRECT_SCENARIOS

    mock._check_stand()
    root = Path(os.environ["CSWAP_STAND_ROOT"])
    fake = fake_path(root)
    fake.write_text(
        f"#!{sys.executable} -I\n"
        "import sys\n"
        f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})\n"
        "from tests.stand_shim import _fake_main\n"
        f"_fake_main({scenario!r})\n",
        encoding="utf-8",
    )
    fake.chmod(0o700)
    direct = scenario in DIRECT_SCENARIOS
    if direct:
        mock.require_direct_target()
    else:
        mock._configure_route(ca)
    os.environ[test_mode.ALLOW] = str(fake)
    pool = ("2", "1") if direct else ("1",)
    archive = seed_profiles(pool)
    install(fake, pool)
    os.environ["NO_PROXY"] = "localhost" if direct else "*"
    os.environ["ANTHROPIC_API_KEY"] = "synthetic-override"

    if scenario == "missing_endpoint":
        del os.environ[test_mode.ENDPOINT]
    elif scenario == "loopback_endpoint":
        os.environ[test_mode.ENDPOINT] = "https://127.0.0.1"
    elif scenario == "public_endpoint":
        os.environ[test_mode.ENDPOINT] = "https://not-reserved.com"
    elif scenario == "public_base":
        os.environ[test_mode.CLAUDE_BASE] = "https://not-reserved.com"
    elif scenario == "public_proxy":
        os.environ[test_mode.PROXY] = "http://192.0.2.1:8080"
    elif scenario == "unlisted_claude":
        os.environ[test_mode.ALLOW] = str(fake.with_name("not-claude"))
    elif scenario == "bypass":
        os.environ["CLAUDE_SWAP_BYPASS"] = "1"

    cwd = root / "project"
    cwd.mkdir()
    if scenario in {"user_env", "project_env"}:
        config = paths.get_claude_config_home() if scenario == "user_env" else cwd / ".claude"
        config.mkdir(exist_ok=True)
        (config / "settings.json").write_text(json.dumps({"env": {
            test_mode.CLAUDE_BASE: "https://override.invalid",
        }}), encoding="utf-8")
    result = subprocess.run(command(scenario), cwd=cwd, capture_output=True, text=True, check=False)
    if direct:
        assert list(archive.glob("*/*.jsonl")) == [archive / THREAD]
        lines = (archive / THREAD).read_text().splitlines()
        assert [json.loads(line)["content"] for line in lines] == (
            [PRIOR, "synthetic reply"] if scenario == "direct_success" else [PRIOR]
        ), result.stderr
    return result


def main(scenario: str) -> int:
    try:
        result = launch(scenario)
    except mock.HostsPreflightError as exc:
        print(exc, file=sys.stderr)
        return 4
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))

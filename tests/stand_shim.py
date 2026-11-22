"""Exercise the installed POSIX shim under the stand's process-tree audit."""

from __future__ import annotations

import io
import json
import os
import runpy
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

from tests import stand_mock as mock

PRINT_ARGS = ["--model", "auth", "-p", "--", 'a "quoted" prompt', "--settings=prompt-data"]
ESCAPE = ("192.0.2.1", 443)  # TEST-NET-1, exercised only in a fresh net namespace.


def command(scenario: str) -> list[str]:
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


def _fake_main(scenario: str) -> None:
    from tests.stand_linux import require_isolation

    require_isolation()
    from claude_swap import test_mode

    assert sys.flags.isolated
    assert sys.argv[1] == "--settings"
    path = Path(sys.argv[2])
    assert is_layer_path(Path(os.environ["CSWAP_STAND_ROOT"]), str(path))
    assert path.stat().st_mode & 0o077 == 0
    assert sys.argv[3:] == command(scenario)[1:]
    layer = json.loads(path.read_text(encoding="utf-8"))["env"]
    assert layer[test_mode.CLAUDE_BASE] == mock.BASE
    assert layer[test_mode.PROXY] == f"http://{mock.PROXY[0]}:{mock.PROXY[1]}"
    assert "NO_PROXY" not in os.environ and "ANTHROPIC_API_KEY" not in os.environ
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


def install(fallback: Path) -> None:
    from claude_swap import paths

    # Exercise the cswap admin entry point before adding anything to PATH.
    with redirect_stdout(io.StringIO()):
        _entry("transparent", "enable")
    shim = paths.get_shim_dir() / "claude"
    assert shim == shim_path(Path(os.environ["CSWAP_STAND_ROOT"])) and shim.is_file()
    os.environ["PATH"] = f"{shim.parent}{os.pathsep}{fallback.parent}"


def launch(scenario: str, ca: Path | None = None) -> subprocess.CompletedProcess[str]:
    from claude_swap import paths, test_mode

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
    mock._configure_route(ca)
    os.environ[test_mode.ALLOW] = str(fake)
    install(fake)
    os.environ["NO_PROXY"] = "*"
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
        config.mkdir()
        (config / "settings.json").write_text(json.dumps({"env": {
            test_mode.CLAUDE_BASE: "https://override.invalid",
        }}), encoding="utf-8")
    return subprocess.run(command(scenario), cwd=cwd, capture_output=True, text=True, check=False)


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

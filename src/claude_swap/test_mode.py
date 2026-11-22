"""Fail-closed routing for the synthetic test mode, not a network sandbox.

The stand must enforce isolation independently. This module rejects unsafe
configuration before dispatch and supplies an explicit CONNECT route for cswap
and the same pinned settings for Claude launches and internal auth probes.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import Request

from claude_swap.exceptions import ClaudeSwitchError

MODE = "CLAUDE_SWAP_TEST_MODE"
ENDPOINT = "CLAUDE_SWAP_TEST_ENDPOINT"
CLAUDE_BASE = "ANTHROPIC_BASE_URL"
ALLOW = "CLAUDE_SWAP_TEST_CLAUDE_ALLOW"
CA = "CLAUDE_SWAP_TEST_CA"
PROXY = "HTTPS_PROXY"
_PROXY_KEYS = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
_ROUTE_KEYS = _PROXY_KEYS | {
    CLAUDE_BASE, "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


class TestModeConfigError(ClaudeSwitchError):
    """A test invocation cannot pin its synthetic route."""


def active() -> bool:
    return os.environ.get(MODE) == "1"


def _base(key: str) -> str:
    value = os.environ.get(key, "")
    try:
        if not value or any(ord(char) <= 32 for char in value):
            raise ValueError
        url = urlsplit(value)
        host = url.hostname or ""
        if (
            url.scheme != "https" or url.username is not None
            or url.path not in {"", "/"} or "?" in value or "#" in value
            or url.port == 0 or not host.endswith((".example", ".test", ".invalid"))
            or not all(_LABEL.fullmatch(label) for label in host.split("."))
            or url.netloc.lower() not in {host, f"{host}:{url.port}"}
        ):
            raise ValueError
    except ValueError:
        raise TestModeConfigError(f"{key}: expected an HTTPS origin in a reserved test zone") from None
    return value.rstrip("/")


def _proxy(key: str, value: str) -> None:
    try:
        if any(ord(char) <= 32 for char in value):
            raise ValueError
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http" or not parsed.port
            or not ipaddress.ip_address(parsed.hostname or "").is_loopback
            or "%" in (parsed.hostname or "")
            or parsed.path not in {"", "/"} or "?" in value or "#" in value
        ):
            raise ValueError
    except ValueError:
        raise TestModeConfigError(f"{key}: expected a loopback-literal HTTP CONNECT proxy") from None


def _route() -> None:
    if "CLAUDE_SWAP_BYPASS" in os.environ:
        raise TestModeConfigError("CLAUDE_SWAP_BYPASS: forbidden in test mode")
    _base(ENDPOINT)
    _base(CLAUDE_BASE)
    for key, value in os.environ.items():
        if value and key.upper() in _PROXY_KEYS - {"NO_PROXY"}:
            _proxy(key, value)
    _proxy(PROXY, os.environ.get(PROXY, ""))
    if CA in os.environ:
        _ca_file()


def claude_binary() -> str:
    """Resolve PATH, then compare with a stand-supplied absolute allowlist."""
    candidate = shutil.which("claude")
    if candidate:
        for entry in os.environ.get(ALLOW, "").split(os.pathsep):
            if Path(entry).is_absolute():
                try:
                    if os.path.samefile(entry, candidate):
                        return os.path.abspath(candidate)
                except OSError:
                    continue
    raise TestModeConfigError(f"{ALLOW}: PATH-selected claude is not allowed")


def _managed_settings() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    if sys.platform == "win32":
        return Path(r"C:\Program Files\ClaudeCode\managed-settings.json")
    return Path("/etc/claude-code/managed-settings.json")


def _settings_files(profile: Path | None):
    from claude_swap import paths

    cwd = Path.cwd()
    yield _managed_settings()
    yield paths.get_claude_config_home() / "settings.json"
    if profile is not None:
        yield profile / "settings.json"
    for directory in (cwd, *cwd.parents):
        for name in ("settings.json", "settings.local.json"):
            yield directory / ".claude" / name


def _check_layers(profile: Path | None = None) -> None:
    for file in dict.fromkeys(_settings_files(profile)):
        try:
            settings = json.loads(file.read_text(encoding="utf-8"))
            env = settings.get("env", {})
            if not isinstance(env, dict):
                raise ValueError
        except FileNotFoundError:
            continue
        except (OSError, AttributeError, ValueError):
            raise TestModeConfigError(f"{file}: cannot check env settings") from None
        for key in env:
            if key.upper() in _ROUTE_KEYS:
                raise TestModeConfigError(f"{file}: env.{key} is forbidden in test mode")


def _client_form(args: list[str]) -> None:
    if any(arg.split("=", 1)[0] in {"--settings", "--setting-sources"} for arg in args):
        raise TestModeConfigError("--settings / --setting-sources: client layer is forbidden")
    # Only the stand's interactive, print and resume arguments are admitted.
    # Require a multi-word print prompt so a bare CLI verb is never admitted
    # as a prompt, even if it is not one of the commands we name in errors.
    print_mode = False
    seen_prompt = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-p", "--print"}:
            print_mode = True
            index += 1
            continue
        if arg == "--resume":
            index += 1
            if index < len(args) and not args[index].startswith("-"):
                index += 1
            continue
        if arg == "--output-format" and args[index + 1:index + 2] in (
            ["text"], ["json"], ["stream-json"]
        ):
            index += 2
            continue
        if print_mode and not seen_prompt and not arg.startswith("-") and len(arg.split()) > 1:
            seen_prompt = True
            index += 1
            continue
        verb = arg if arg in {"auth", "update", "install", "mcp"} else "unknown"
        raise TestModeConfigError(f"Claude invocation form: {verb} command or option is forbidden")


def check_launch(args: list[str], profile: Path | None = None) -> str:
    _route()
    binary = claude_binary()
    _client_form(args)
    _check_layers(profile)
    return binary


def preflight(argv: list[str]) -> None:
    """Check the existing cswap entry point before parsing or dispatch."""
    if not active():
        return
    _route()
    claude_binary()
    _check_layers()
    if argv[:1] == ["run"]:
        args = argv[1:]
        index = args.index("--") if "--" in args else len(args)
        head, tail = args[:index], args[index + 1:]
        if not head or not head[0] or head[0].startswith("-"):
            raise TestModeConfigError("cswap run invocation form: explicit account required")
        _client_form(tail)
    elif argv not in (["help"], ["--help"], ["-h"], ["--version"]):
        # Do not dispatch unrelated surfaces (update, service helpers, etc.).
        verb = argv[0] if argv and argv[0] in {"auth", "update", "upgrade", "install", "mcp"} else "unsupported"
        raise TestModeConfigError(f"cswap invocation form: {verb}")


def _ca_file() -> str:
    value = os.environ.get(CA, "")
    if not Path(value).is_absolute() or not Path(value).is_file():
        raise TestModeConfigError(f"{CA}: expected an explicit test CA file")
    return value


def pinned_launch(args: list[str], env: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    """Supply one settings layer, without inherited auth or proxy overrides."""
    child = {key: value for key, value in env.items() if key.upper() not in _ROUTE_KEYS}
    pinned = {CLAUDE_BASE: _base(CLAUDE_BASE), PROXY: os.environ[PROXY]}
    if os.environ.get(CA):
        pinned["NODE_EXTRA_CA_CERTS"] = _ca_file()
    child.update(pinned)
    return ["--settings", json.dumps({"env": pinned}), *args], child


def service_url(url: str) -> str:
    return _base(ENDPOINT) + urlsplit(url).path if active() else url


class _Tunnel(http.client.HTTPSConnection):
    """Dial only the proxy literal; do not ask the system resolver."""

    @staticmethod
    def _dial(address, timeout, source_address):
        ip = ipaddress.ip_address(address[0])
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
        except BaseException:
            sock.close()
            raise
        return sock

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # HTTPConnection assigns its own connector on initialisation.
        self._create_connection = self._dial


def open_service(request: Request, *, timeout: float):
    """Open an API request through the explicit tunnel, with no redirects."""
    if not active():
        from urllib.request import urlopen

        return urlopen(request, timeout=timeout)
    from urllib.error import HTTPError, URLError

    _route()
    origin = urlsplit(request.full_url)
    base = urlsplit(_base(ENDPOINT))
    if origin.scheme != base.scheme or origin.netloc != base.netloc:
        raise TestModeConfigError(f"{ENDPOINT}: unexpected request origin")
    proxy = urlsplit(os.environ[PROXY])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cafile=_ca_file())
    except OSError:
        raise TestModeConfigError(f"{CA}: cannot load the explicit test CA") from None
    conn = _Tunnel(proxy.hostname, proxy.port, timeout=timeout, context=context)
    headers = {}
    if proxy.username is not None:
        userinfo = f"{unquote(proxy.username)}:{unquote(proxy.password or '')}"
        headers["Proxy-Authorization"] = "Basic " + base64.b64encode(userinfo.encode()).decode("ascii")
    conn.set_tunnel(origin.hostname, origin.port or 443, headers=headers)
    request_headers = dict(request.header_items())
    request_headers.setdefault("Connection", "close")
    try:
        conn.request(request.get_method(), request.selector, request.data, request_headers)
        response = conn.getresponse()
        # Do not reuse the connection. getresponse() leaves the response's
        # socket file usable independently of the connection's socket.
        if conn.sock is not None:
            conn.sock.close()
            conn.sock = None
    except OSError as exc:
        conn.close()
        raise URLError(exc) from exc
    except BaseException:
        conn.close()
        raise
    if not 200 <= response.status < 300:
        raise HTTPError(request.full_url, response.status, response.reason, response.headers, response)
    return response

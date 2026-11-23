"""Fail-closed routing for the synthetic test mode, not a network sandbox.

The stand must enforce isolation independently. This module rejects unsafe
configuration before dispatch and pins either loopback CONNECT or an explicit
direct TLS route for cswap, Claude launches and internal auth probes.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit
from urllib.request import Request

from claude_swap import claude_forms
from claude_swap.exceptions import ClaudeSwitchError

if TYPE_CHECKING:
    from claude_swap.real_claude import RealClaude

MODE = "CLAUDE_SWAP_TEST_MODE"
ENDPOINT = "CLAUDE_SWAP_TEST_ENDPOINT"
CLAUDE_BASE = "ANTHROPIC_BASE_URL"
ALLOW = "CLAUDE_SWAP_TEST_CLAUDE_ALLOW"
CA = "CLAUDE_SWAP_TEST_CA"
PROXY = "HTTPS_PROXY"
DIRECT = "CLAUDE_SWAP_TEST_DIRECT"
_PROXY_KEYS = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
_ROUTE_KEYS = _PROXY_KEYS | {
    CLAUDE_BASE, DIRECT, "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
}
_LAYER_KEYS = _ROUTE_KEYS | {"CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR"}
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


def _direct_address(endpoint: str, claude_base: str) -> tuple[str, int]:
    if sys.platform != "linux":
        raise TestModeConfigError(f"{DIRECT}: direct test routing requires the isolated Linux stand")
    # Keep the HTTPS authority for Host/SNI separate from the numeric dial
    # address. All three settings must designate the same synthetic service.
    try:
        address = urlsplit(f"http://{os.environ[DIRECT]}")
        ip = ipaddress.ip_address(address.hostname or "")
        port = address.port
        canonical = f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"
        base = urlsplit(endpoint)
        claude = urlsplit(claude_base)
        if (
            not ip.is_loopback or not port or os.environ[DIRECT] != canonical
            or base.port != port or claude.port != port or base.hostname != claude.hostname
        ):
            raise ValueError
    except ValueError:
        raise TestModeConfigError(
            f"{DIRECT}: expected a loopback literal and port matching both test HTTPS origins"
        ) from None
    return str(ip), port


def _route() -> tuple[str, int] | None:
    if "CLAUDE_SWAP_BYPASS" in os.environ:
        raise TestModeConfigError("CLAUDE_SWAP_BYPASS: forbidden in test mode")
    endpoint = _base(ENDPOINT)
    claude_base = _base(CLAUDE_BASE)
    if DIRECT in os.environ:
        address = _direct_address(endpoint, claude_base)
        _ca_file()
        return address
    for key, value in os.environ.items():
        if value and key.upper() in _PROXY_KEYS - {"NO_PROXY"}:
            _proxy(key, value)
    _proxy(PROXY, os.environ.get(PROXY, ""))
    if CA in os.environ:
        _ca_file()


def claude_binary(*, backup_root: Path | None = None) -> RealClaude:
    """Resolve once and require the result to be in the stand's allowlist."""
    from claude_swap import real_claude

    try:
        candidate = real_claude.resolve(backup_root=backup_root)
    except ClaudeSwitchError:
        raise TestModeConfigError(f"{ALLOW}: no allowed claude resolved") from None
    _check_allowed(candidate)
    return candidate


def _check_allowed(candidate: RealClaude) -> None:
    for entry in os.environ.get(ALLOW, "").split(os.pathsep):
        if Path(entry).is_absolute():
            try:
                if os.path.samefile(entry, candidate.path):
                    return
            except OSError:
                continue
    raise TestModeConfigError(f"{ALLOW}: resolved claude is not allowed")


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
            if key.upper() in _LAYER_KEYS:
                raise TestModeConfigError(f"{file}: env.{key} is forbidden in test mode")


def _check_form(args: list[str]) -> None:
    form = claude_forms.classify(args)
    if form.error:
        raise TestModeConfigError(form.error)
    if form.settings is not None:
        raise TestModeConfigError("--settings: client layer is forbidden")
    if form.setting_sources:
        raise TestModeConfigError("--setting-sources: client layer is forbidden")
    if form.bypass_reason:
        raise TestModeConfigError(f"Claude invocation form: {form.bypass_reason}")


def check_launch(
    args: list[str], profile: Path | None = None, *, backup_root: Path | None = None,
    binary: RealClaude | None = None,
) -> RealClaude:
    _route()
    _check_form(args)
    _check_layers(profile)
    if binary is None:
        return claude_binary(backup_root=backup_root)
    _check_allowed(binary)
    return binary


def preflight(argv: list[str]) -> RealClaude | None:
    """Check the cswap entry point; return the checked executable for `run`."""
    if not active():
        return None
    _route()
    _check_layers()
    if argv[:1] == ["run"]:
        args = argv[1:]
        index = args.index("--") if "--" in args else len(args)
        head, tail = args[:index], args[index + 1:]
        if not head or not head[0] or head[0].startswith("-"):
            raise TestModeConfigError("cswap run invocation form: explicit account required")
        _check_form(tail)
        return claude_binary()
    if argv[:2] == ["transparent", "enable"]:
        options = iter(argv[2:])
        accepted = False
        for option in options:
            if option == "--accept-shared-history" and not accepted:
                accepted = True
            elif option != "--account" or not re.fullmatch(r"[1-9][0-9]*", next(options, "")):
                break
        else:
            return None
    if argv not in (
        ["help"], ["--help"], ["-h"], ["--version"],
        ["transparent", "status"], ["transparent", "disable"],
    ):
        # Do not dispatch unrelated surfaces (update, service helpers, etc.).
        verb = argv[0] if argv and argv[0] in {"auth", "update", "upgrade", "install", "mcp"} else "unsupported"
        raise TestModeConfigError(f"cswap invocation form: {verb}")
    return None


def _ca_file() -> str:
    value = os.environ.get(CA, "")
    if not Path(value).is_absolute() or not Path(value).is_file():
        raise TestModeConfigError(f"{CA}: expected an explicit test CA file")
    return value


def pinned_launch(args: list[str], env: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    """Supply one settings layer, without inherited auth or proxy overrides."""
    child = {key: value for key, value in env.items() if key.upper() not in _ROUTE_KEYS}
    pinned = {CLAUDE_BASE: _base(CLAUDE_BASE)}
    if DIRECT in os.environ:
        _direct_address(_base(ENDPOINT), pinned[CLAUDE_BASE])
        pinned[DIRECT] = os.environ[DIRECT]
        pinned["NODE_EXTRA_CA_CERTS"] = _ca_file()
    else:
        proxy = os.environ[PROXY]
        # Preflight forbids lower proxy settings. An authenticated test proxy
        # can use the child environment without exposing userinfo in argv.
        if urlsplit(proxy).username is None:
            pinned[PROXY] = proxy
        else:
            child[PROXY] = proxy
        if os.environ.get(CA):
            pinned["NODE_EXTRA_CA_CERTS"] = _ca_file()
    child.update(pinned)
    return ["--settings", json.dumps({"env": pinned}), *args], child


def service_url(url: str) -> str:
    return _base(ENDPOINT) + urlsplit(url).path if active() else url


class _LiteralHTTPSConnection(http.client.HTTPSConnection):
    """Use a fixed numeric address without changing the TLS authority."""

    @staticmethod
    def _dial(address, timeout):
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

    def __init__(self, host, port, *, address, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._create_connection = lambda _host, timeout, _source: self._dial(address, timeout)


def open_service(request: Request, *, timeout: float):
    """Open a pinned API request, with no proxy discovery or redirects."""
    if not active():
        from urllib.request import urlopen

        return urlopen(request, timeout=timeout)
    from urllib.error import HTTPError, URLError

    direct = _route()
    origin = urlsplit(request.full_url)
    base = urlsplit(_base(ENDPOINT))
    if origin.scheme != base.scheme or origin.netloc != base.netloc:
        raise TestModeConfigError(f"{ENDPOINT}: unexpected request origin")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cafile=_ca_file())
    except OSError:
        raise TestModeConfigError(f"{CA}: cannot load the explicit test CA") from None
    if direct is not None:
        conn = _LiteralHTTPSConnection(
            origin.hostname, origin.port, address=direct, timeout=timeout, context=context,
        )
    else:
        proxy = urlsplit(os.environ[PROXY])
        conn = _LiteralHTTPSConnection(
            proxy.hostname, proxy.port, address=(proxy.hostname, proxy.port),
            timeout=timeout, context=context,
        )
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

"""Synthetic HTTPS origin, reachable only through this stand's CONNECT proxy.

The authority is never resolved. The proxy maps it to one numeric loopback
listener and sends a run-specific preamble before relaying any TLS bytes.
The HTTPS listener records and closes connections without the preamble.
"""

from __future__ import annotations

import base64
from contextlib import chdir, contextmanager
import http.client
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import runpy
import secrets
import select
import socket
from socketserver import TCPServer
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
from urllib.request import Request

HOST = "api.mock.example"
BASE = f"https://{HOST}"
AUTHORITY = f"{HOST}:443"
LOOPBACK = "127.0.0.1"
PROXY = (LOOPBACK, 18080)
ORIGIN = (LOOPBACK, 18443)
TIMEOUT = 5
PROBE = "/stand-probe"


class HostsPreflightError(RuntimeError):
    """The stand cannot safely assume its service authority is unmapped."""


def preflight_hosts(path: Path = Path("/etc/hosts")) -> None:
    """Reject service aliases in the hosts file without asking a resolver."""
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise HostsPreflightError(f"Cannot read hosts file: {path}") from exc
    for line in lines:
        aliases = line.partition(b"#")[0].split()[1:]
        if any(alias.lower().rstrip(b".") == HOST.encode("ascii") for alias in aliases):
            raise HostsPreflightError(f"hosts file contains a mapping for {HOST}")


def _test_certificates(directory: Path, openssl: str) -> tuple[Path, Path, Path]:
    def run(*args):
        subprocess.run([openssl, *args], cwd=directory, check=True, capture_output=True)

    run(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
        "-subj", "/CN=claude-swap synthetic stand CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign",
        "-keyout", "ca.key", "-out", "ca.pem",
    )
    run(
        "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-subj", f"/CN={HOST}", "-keyout", "origin.key", "-out", "origin.csr",
    )
    (directory / "origin.ext").write_text(
        f"subjectAltName=DNS:{HOST}\nbasicConstraints=critical,CA:FALSE\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )
    run(
        "x509", "-req", "-days", "1", "-sha256", "-in", "origin.csr",
        "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-extfile", "origin.ext", "-out", "origin.pem",
    )
    return directory / "ca.pem", directory / "origin.pem", directory / "origin.key"


def _dial(address: tuple[str, int]) -> socket.socket:
    # Both caller-supplied targets are stand constants, not proxy input.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect(address)
    except OSError:
        sock.close()
        raise
    return sock


def _relay(client: socket.socket, origin: socket.socket) -> None:
    peers = {client: origin, origin: client}
    while readable := select.select(list(peers), [], [], TIMEOUT)[0]:
        for sock in readable:
            data = sock.recv(16384)
            if not data:
                return
            peers[sock].sendall(data)


def _send_json(handler: BaseHTTPRequestHandler) -> None:
    body = b'{"stand": "synthetic"}'
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # Do not log headers, query strings or malformed request lines.
        return


@contextmanager
def _running(server: TCPServer):
    with server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield
        finally:
            server.shutdown()
            worker.join()


def _check_stand() -> None:
    from tests.stand_linux import require_isolation

    preflight_hosts()
    require_isolation()


@contextmanager
def _serve():
    from tests.stand_linux import openssl_path

    _check_stand()
    records = {"connect": [], "https": [], "direct": 0, "denied_connect": 0}
    preamble = secrets.token_bytes(32)

    class OriginHandler(_QuietHandler):
        def do_GET(self):
            path = self.path.partition("?")[0]
            records["https"].append([self.command, path])
            _send_json(self)

    class OriginServer(TCPServer):
        def get_request(self):
            sock, address = super().get_request()
            sock.settimeout(TIMEOUT)
            try:
                observed = b""
                while len(observed) < len(preamble):
                    chunk = sock.recv(len(preamble) - len(observed))
                    observed += chunk
                    if not chunk or not preamble.startswith(observed):
                        break
            except OSError:
                observed = b""
            if observed != preamble:
                records["direct"] += 1
                sock.close()
                raise OSError("Origin connection lacked the stand preamble")
            try:
                return tls.wrap_socket(sock, server_side=True), address
            except OSError:
                sock.close()
                raise

    class ProxyHandler(_QuietHandler):
        def setup(self):
            self.request.settimeout(TIMEOUT)
            super().setup()

        def do_CONNECT(self):
            if self.path != AUTHORITY:
                records["denied_connect"] += 1
                self.send_error(403)
                return
            records["connect"].append(AUTHORITY)
            try:
                with _dial(ORIGIN) as origin:
                    origin.sendall(preamble)
                    self.send_response_only(200, "Connection Established")
                    self.end_headers()
                    _relay(self.connection, origin)
            except OSError:
                # Closing the handler ends the tunnel; either peer can hang up.
                return

    with tempfile.TemporaryDirectory(prefix="stand-ca-") as directory:
        ca, cert, key = _test_certificates(Path(directory), openssl_path())
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        with (
            _running(OriginServer(ORIGIN, OriginHandler)),
            _running(TCPServer(PROXY, ProxyHandler)),
        ):
            yield ca, records


def _https_probe() -> dict:
    from claude_swap import test_mode

    request = Request(test_mode.service_url(f"https://unused.invalid{PROBE}"))
    with test_mode.open_service(request, timeout=TIMEOUT) as response:
        return json.load(response)


def _configure_route(ca: Path | None = None) -> None:
    from claude_swap import test_mode

    os.environ.update({
        test_mode.ENDPOINT: BASE,
        test_mode.CLAUDE_BASE: BASE,
        test_mode.PROXY: f"http://{PROXY[0]}:{PROXY[1]}",
    })
    if ca is not None:
        os.environ[test_mode.CA] = str(ca)


def _fake_claude_path() -> str:
    from claude_swap import test_mode

    claude = Path(os.environ["PATH"]) / "claude"
    claude.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
    claude.chmod(0o700)
    os.environ[test_mode.ALLOW] = str(claude)
    return str(claude)


PRINT_ARGS = ["-p", "synthetic prompt"]


def _run_cli(*options: str) -> None:
    with tempfile.TemporaryDirectory(prefix="stand-cli-") as directory, chdir(directory):
        sys.argv = ["cswap", "run", "1", *options, "--", *PRINT_ARGS]
        runpy.run_module("claude_swap", run_name="__main__", alter_sys=True)


def _cli_endpoint_control(scenario: str) -> None:
    from claude_swap import test_mode

    _check_stand()
    _configure_route()
    _fake_claude_path()
    if scenario == "malformed_endpoint":
        os.environ[test_mode.ENDPOINT] = f"http://{HOST}"
    else:
        del os.environ[test_mode.ENDPOINT]
    _run_cli()


def _cli_positive(ca: Path) -> dict:
    from claude_swap import paths, session, spawn, test_mode

    _configure_route(ca)
    claude = _fake_claude_path()
    # This privileged worker already passed the network and mount namespace checks.
    os.environ["CONTAINER"] = "cswap-test-stand"
    os.environ["NO_PROXY"] = "*"
    os.environ["ANTHROPIC_API_KEY"] = "unused-synthetic-override"

    email = "account@example.test"
    backup = paths.get_backup_root()
    assert backup.is_relative_to(Path(os.environ["CSWAP_STAND_ROOT"]))
    (backup / "configs").mkdir(parents=True)
    (backup / "credentials").mkdir()
    credentials = json.dumps({"claudeAiOauth": {
        "accessToken": "synthetic-access-token",
        "expiresAt": int((time.time() + 3600) * 1000),
    }})
    (backup / "credentials" / f".creds-1-{email}.enc").write_bytes(
        base64.b64encode(credentials.encode("utf-8"))
    )
    identity = {"emailAddress": email, "organizationUuid": ""}
    (backup / "configs" / f".claude-config-1-{email}.json").write_text(
        json.dumps({"oauthAccount": identity}), encoding="utf-8",
    )
    (backup / "sequence.json").write_text(json.dumps({"accounts": {
        "1": {"email": email, "organizationUuid": ""},
    }}), encoding="utf-8")
    profile = session.session_dir_for(backup, "1", email)
    assert not profile.exists()

    pinned = {
        test_mode.CLAUDE_BASE: BASE,
        test_mode.PROXY: f"http://{PROXY[0]}:{PROXY[1]}",
        "NODE_EXTRA_CA_CERTS": str(ca),
    }
    auth_checked = False
    response = None

    def check_launch(argv, env, args):
        assert argv[:2] == [claude, "--settings"]
        assert json.loads(argv[2]) == {"env": pinned}
        assert argv[3:] == args
        assert all(env[key] == value for key, value in pinned.items())
        assert "NO_PROXY" not in env and "ANTHROPIC_API_KEY" not in env
        assert env["CLAUDE_CONFIG_DIR"] == str(profile)
        assert (profile / ".credentials.json").read_text(encoding="utf-8") == credentials
        assert json.loads((profile / ".claude.json").read_text(encoding="utf-8"))[
            "oauthAccount"
        ] == identity

    def auth_status(argv, *, env, **kwargs):
        nonlocal auth_checked
        check_launch(argv, env, ["auth", "status", "--json"])
        auth_checked = True
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({
            "loggedIn": True, "authMethod": "claude.ai", "email": email,
        }))

    def final_exec(binary, argv, env):
        nonlocal response
        assert binary == claude and auth_checked
        check_launch(argv, env, PRINT_ARGS)
        # Exercise the synthetic HTTPS path under the environment that the
        # real CLI prepared, without relaxing the native exec allowlist.
        with patch.dict(os.environ, env, clear=True):
            response = _https_probe()
        raise SystemExit(0)

    with patch.object(spawn, "run", auth_status), patch.object(os, "execvpe", final_exec):
        try:
            _run_cli("--no-share", "--no-share-history", "--require-session")
        except SystemExit as exc:
            if exc.code != 0:
                raise
    assert response is not None, "CLI did not reach the fake Claude launch"
    return response


def _attempt_direct(ca: Path) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=ca)
    with _dial(ORIGIN) as sock:
        try:
            with context.wrap_socket(sock, server_hostname=HOST):
                raise AssertionError("Origin accepted direct TLS")
        except (ssl.SSLError, ConnectionResetError):
            pass


def _attempt_denied_connect() -> None:
    with _dial(PROXY) as sock:
        sock.sendall(b"CONNECT unlisted.mock.example:443 HTTP/1.0\r\n\r\n")
        with http.client.HTTPResponse(sock) as response:
            response.begin()
            if response.status != 403:
                raise AssertionError("Proxy did not reject an unlisted CONNECT authority")


def _serve_worker() -> int:
    with _serve() as (ca, records):
        print(ca, flush=True)
        sys.stdin.readline()
    print(json.dumps(records))
    return int(bool(records["direct"] or records["denied_connect"]))


def _client_worker(scenario: str) -> int:
    _check_stand()
    ca = Path(sys.stdin.readline().strip())
    response = None
    if scenario == "positive":
        _configure_route(ca)
        response = _https_probe()
    elif scenario == "cli_positive":
        response = _cli_positive(ca)
    elif scenario == "direct":
        _attempt_direct(ca)
    elif scenario == "denied_connect":
        _attempt_denied_connect()
    else:
        raise ValueError("Unknown mock scenario")
    print(json.dumps(response))
    return 0


def main(scenario: str) -> int:
    # Check before either the mock or the client is launched. Each child
    # also checks the same mounted hosts file and the namespace on entry.
    _check_stand()
    from tests.stand_linux import worker_argv

    with subprocess.Popen(
        worker_argv("stand_mock", "serve"),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    ) as server:
        try:
            ca_line = server.stdout.readline()
            if not ca_line:
                raise RuntimeError("HTTPS stand failed to start")
            client = subprocess.run(
                worker_argv("stand_mock", "client", scenario),
                input=ca_line, stdout=subprocess.PIPE, text=True, check=True,
            )
        finally:
            # Close the server's input to signal shutdown and read its journal.
            journal, _ = server.communicate()
    print(json.dumps({"records": json.loads(journal), "response": json.loads(client.stdout)}))
    return server.returncode


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["serve"]:
            sys.exit(_serve_worker())
        if sys.argv[1:2] == ["client"]:
            sys.exit(_client_worker(sys.argv[2]))
        from tests.stand_linux import MOCK_CLI_CONTROLS

        if sys.argv[1] in MOCK_CLI_CONTROLS:
            _cli_endpoint_control(sys.argv[1])
        else:
            sys.exit(main(sys.argv[1]))
    except HostsPreflightError as exc:
        print(exc, file=sys.stderr)
        sys.exit(4)

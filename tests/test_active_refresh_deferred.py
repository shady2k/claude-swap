"""Unsafe active recovery refuses writes; authorized refresh leaves state unlocked."""

from __future__ import annotations

import ast
import inspect
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

import pytest

from claude_swap import oauth, profile_ownership
from claude_swap import switcher as switcher_module
from claude_swap.switcher import ClaudeAccountSwitcher


EMAIL = "deferred@example.com"


def credential(refresh="synthetic-current", *, expired=True):
    return json.dumps({"claudeAiOauth": {
        "accessToken": "synthetic-access", "refreshToken": refresh,
        "expiresAt": 1000 if expired else 9999999999000,
    }})


@pytest.fixture
def active_store(temp_home, monkeypatch):
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._write_json(switcher.sequence_file, {
        "activeAccountNumber": "1",
        "accounts": {"1": {"email": EMAIL}},
    })
    monkeypatch.setattr(switcher, "_live_identity_matches", lambda *args: True)
    return switcher


@pytest.fixture
def local_token_server(monkeypatch):
    """Only this explicit loopback origin can receive synthetic requests."""
    posts = []
    entered = threading.Event()
    release = threading.Event()
    release.set()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            posts.append(self.path)
            entered.set()
            release.wait(10)
            body = json.dumps({
                "access_token": "synthetic-successor-access",
                "refresh_token": "synthetic-successor-refresh", "expires_in": 3600,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    origin = f"http://127.0.0.1:{server.server_port}"
    opener = build_opener(ProxyHandler({}))

    def open_local(request, *, timeout):
        parsed = urlsplit(request.full_url)
        assert f"{parsed.scheme}://{parsed.netloc}" == origin
        return opener.open(request, timeout=timeout)

    monkeypatch.setattr(oauth.test_mode, "service_url", lambda url: origin + urlsplit(url).path)
    monkeypatch.setattr(oauth.test_mode, "open_service", open_local)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield posts, entered, release
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(10)
        assert not thread.is_alive()


def snapshot(switcher):
    """Compare all durable bytes, including ownership generations and stashes."""
    return {
        "live": switcher._read_credentials(),
        "files": {
            str(path.relative_to(Path.home())): path.read_bytes()
            for path in Path.home().rglob("*")
            if path.is_file() and not path.name.endswith(".lock")
        },
    }


@pytest.mark.parametrize("shape", ["identity-moved", "unreadable", "foreign-live"])
def test_unsafe_recovery_does_not_post_or_write(
    active_store, local_token_server, monkeypatch, shape,
):
    switcher = active_store
    collected = credential()
    switcher._write_account_credentials("1", EMAIL, collected)
    switcher._write_credentials(
        credential("synthetic-foreign") if shape == "foreign-live" else collected
    )
    if shape == "identity-moved":
        monkeypatch.setattr(switcher, "_live_identity_matches", lambda *a: False)
    if shape == "unreadable":
        monkeypatch.setattr(switcher, "_read_account_credentials_ex", lambda *a: ("", True))
    before = snapshot(switcher)

    from claude_swap.refresh_authority import CredentialSnapshot
    collected = CredentialSnapshot(collected, {"email": EMAIL, "organizationUuid": "", "uuid": ""}, 0)
    result = switcher._fetch_active_usage("1", EMAIL, collected)

    assert local_token_server[0] == []
    assert snapshot(switcher) == before
    assert result.error == ("unreadable" if shape == "unreadable" else "credential-unproven" if shape == "foreign-live" else "ownership-lost")
    assert result.sentinel is None


def test_independent_profile_reservation_completes_while_recovery_is_paused(
    active_store, local_token_server, monkeypatch,
):
    switcher = active_store
    from claude_swap.refresh_authority import CredentialSnapshot
    creds = CredentialSnapshot(credential(), {"email": EMAIL, "organizationUuid": "", "uuid": ""}, 0)
    switcher._write_credentials(creds)
    switcher._write_account_credentials("1", EMAIL, creds)
    posts, entered, release = local_token_server
    release.clear()
    def paused_refresh(*args, **kwargs):
        entered.set()
        assert release.wait(10), "active refresh was never released"
        return oauth.RefreshOutcome(credential("synthetic-successor", expired=False), None)

    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", paused_refresh)
    monkeypatch.setattr(
        oauth, "try_fetch_usage_for_account",
        lambda *a, **k: oauth.UsageOutcome(None, error="http-401"),
    )
    completed = threading.Event()
    reserved = threading.Event()
    failures = []

    def recover():
        try:
            switcher._fetch_active_usage("1", EMAIL, creds)
        except BaseException as exc:
            failures.append(exc)
        finally:
            completed.set()

    def reserve():
        try:
            with profile_ownership.ownership_lock(switcher.backup_dir):
                lease = profile_ownership.reserve_locked(
                    switcher.backup_dir, "2", switcher.backup_dir / "sessions" / "independent",
                )
                reserved.set()
                profile_ownership.release_locked(switcher.backup_dir, lease["launchId"])
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=recover)
    contender = threading.Thread(target=reserve)
    worker.start()
    try:
        assert entered.wait(5), "recovery never reached the controlled pause"
        assert not completed.is_set(), "recovery finished before the reservation attempt"
        contender.start()
        progressed = reserved.wait(2)
        still_paused = not completed.is_set()
    finally:
        release.set()
        worker.join(10)
        if contender.ident is not None:
            contender.join(10)
    assert not worker.is_alive() and not contender.is_alive()
    assert not failures
    assert progressed, "active recovery blocked an independent ownership reservation"
    assert still_paused, "recovery was not paused while the reservation completed"
    assert completed.is_set()
    assert posts == []


def test_no_refresh_network_call_is_nested_under_ownership_lock():
    tree = ast.parse(inspect.getsource(inspect.getmodule(ClaudeAccountSwitcher)))
    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        owns_state = any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "ownership_lock"
            for item in node.items for call in ast.walk(item.context_expr)
        )
        if not owns_state:
            continue
        for statement in node.body:
            for call in ast.walk(statement):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
                    if call.func.attr in {"try_refresh_oauth_credentials", "refresh_oauth_credentials"}:
                        violations.append(call.lineno)
    assert not violations, f"refresh network call under ownership lock at lines {violations}"

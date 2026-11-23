"""The usage layer cannot spend a refresh grant without an explicit gate."""

import ast
import inspect
import json
import urllib.error
from pathlib import Path
from unittest.mock import Mock

import pytest

from claude_swap import oauth


def test_usage_requires_explicit_refresh_authority():
    for function in (oauth.try_fetch_usage_for_account, oauth.fetch_usage_for_account):
        parameter = inspect.signature(function).parameters["refresh_via"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty


@pytest.mark.parametrize("expired", [False, True])
def test_explicit_none_never_posts_refresh(monkeypatch, expired):
    credentials = json.dumps({"claudeAiOauth": {
        "accessToken": "access", "refreshToken": "grant",
        "expiresAt": 1 if expired else 9999999999999,
    }})
    post = Mock(side_effect=AssertionError("read-only usage must not refresh"))
    monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", post)
    request = Mock(side_effect=urllib.error.HTTPError("url", 401, "no", {}, None))
    monkeypatch.setattr(oauth, "request_usage_data", request)
    result = oauth.try_fetch_usage_for_account(
        "1", "a@b.c", credentials, False, refresh_via=None,
    )
    assert result.error == "http-401"
    request.assert_called_once_with("access")
    post.assert_not_called()


def test_usage_layer_has_no_raw_refresh_calls_or_compatibility_wrapper():
    tree = ast.parse(inspect.getsource(oauth))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert not any(
        isinstance(call.func, ast.Name)
        and call.func.id == "try_refresh_oauth_credentials"
        for call in calls
    )
    assert not hasattr(oauth, "refresh_oauth_credentials")


def test_production_usage_callers_supply_refresh_authority():
    root = Path(inspect.getfile(oauth)).parent
    missing = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = function.attr if isinstance(function, ast.Attribute) else (
                function.id if isinstance(function, ast.Name) else None
            )
            if name in ("try_fetch_usage_for_account", "fetch_usage_for_account"):
                if not any(keyword.arg == "refresh_via" for keyword in node.keywords):
                    missing.append(f"{path.name}:{node.lineno}")
    assert missing == []


def test_raw_refresh_calls_are_confined_to_authority_gates():
    root = Path(inspect.getfile(oauth)).parent
    calls = []

    class RefreshCalls(ast.NodeVisitor):
        def __init__(self, path):
            self.path = path
            self.function = None

        def visit_FunctionDef(self, node):
            previous = self.function
            self.function = node.name
            self.generic_visit(node)
            self.function = previous

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            function = node.func
            name = function.attr if isinstance(function, ast.Attribute) else (
                function.id if isinstance(function, ast.Name) else None
            )
            if name == "try_refresh_oauth_credentials":
                calls.append((self.path.name, self.function))
            self.generic_visit(node)

    for path in root.rglob("*.py"):
        RefreshCalls(path).visit(ast.parse(path.read_text(encoding="utf-8")))
    assert sorted(calls) == [
        ("switcher.py", "_consume_backup_grant_locked"),
        ("switcher.py", "_fetch_active_usage"),
    ]

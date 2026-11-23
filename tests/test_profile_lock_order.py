"""Cross-module profile mutation lock order and publication boundaries."""

import ast
from contextlib import contextmanager
from pathlib import Path

from claude_swap import profile_ownership, switcher


ROOT = Path(__file__).resolve().parents[1] / "src" / "claude_swap"


def _call_name(node):
    if isinstance(node, ast.Call):
        return ast.unparse(node.func)
    return ""


def test_switcher_lock_requires_outer_ownership_lock():
    violations = []
    for filename in ("switcher.py", "transfer.py", "session.py", "transparent.py"):
        tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))

        def visit(node, owned=False, account=False, function=None):
            if isinstance(node, ast.FunctionDef):
                function = node.name
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    expr = item.context_expr
                    if _call_name(expr).endswith("ownership_lock"):
                        owned = True
                    is_account_lock = _call_name(expr) == "FileLock" and any(
                        (isinstance(arg, ast.Attribute) and arg.attr == "lock_file")
                        or _call_name(arg).endswith("account_lock_path")
                        for arg in expr.args
                    )
                    if is_account_lock:
                        account = True
                        # Shim installation/policy reads never inspect or mutate
                        # profile ownership. Publication is checked separately.
                        policy_only = filename == "transparent.py" and function in {
                            "enable", "disable", "refresh_install", "_launch",
                        }
                        if not owned and not policy_only:
                            violations.append((filename, node.lineno))
            if isinstance(node, ast.Call) and _call_name(node).endswith("mark_running_locked"):
                if not (owned and account):
                    violations.append((filename, node.lineno, "publication"))
            if isinstance(node, ast.FunctionDef) and node.name == "backfill_account_uuid":
                return
            for child in ast.iter_child_nodes(node):
                visit(child, owned, account, function)

        visit(tree)
    assert not violations, violations


def test_running_transition_has_one_publication_point_per_surface():
    calls = {}
    for filename in ("session.py", "transparent.py"):
        tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
        calls[filename] = [
            node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _call_name(node).endswith("mark_running_locked")
        ]
    assert all(len(lines) == 1 for lines in calls.values()), calls


def test_backup_persist_holds_state_before_account_lock(temp_home, monkeypatch):
    manager = switcher.ClaudeAccountSwitcher()
    events = []

    @contextmanager
    def state_lock(*args):
        events.append("state-enter")
        yield
        events.append("state-exit")

    @contextmanager
    def account_lock(*args):
        assert events[-1] == "state-enter"
        events.append("account-enter")
        yield
        events.append("account-exit")

    monkeypatch.setattr(profile_ownership, "ownership_lock", state_lock)
    monkeypatch.setattr(switcher, "FileLock", account_lock)
    monkeypatch.setattr(manager, "_write_account_credentials", lambda *args: events.append("write"))
    manager.persist_backup_credentials("1", "synthetic@example.com", "synthetic")
    assert events == ["state-enter", "account-enter", "write", "account-exit", "state-exit"]


def test_running_state_assignments_stay_in_ownership_module():
    violations = []
    for source in ROOT.glob("*.py"):
        if source.name == "profile_ownership.py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if isinstance(value, ast.Constant) and value.value == "running":
                    for target in targets:
                        if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and target.slice.value == "state":
                            violations.append((source.name, node.lineno))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "update":
                if any(keyword.arg == "state" and isinstance(keyword.value, ast.Constant) and keyword.value.value == "running" for keyword in node.keywords):
                    violations.append((source.name, node.lineno))
    assert not violations, violations


def test_actual_backup_write_holds_state_and_account_lock(temp_home, monkeypatch):
    manager = switcher.ClaudeAccountSwitcher()
    manager._setup_directories()
    original_state = profile_ownership.ownership_lock
    original_account = switcher.FileLock
    original_write = manager._store._write_account_credentials
    held = []
    writes = []

    @contextmanager
    def state_lock(*args):
        with original_state(*args):
            held.append("state")
            try:
                yield
            finally:
                held.pop()

    @contextmanager
    def account_lock(*args, **kwargs):
        assert held == ["state"]
        with original_account(*args, **kwargs):
            held.append("account")
            try:
                yield
            finally:
                held.pop()

    def write(*args):
        assert held[:2] == ["state", "account"]
        writes.append(args[:2])
        original_write(*args)

    monkeypatch.setattr(profile_ownership, "ownership_lock", state_lock)
    monkeypatch.setattr(switcher, "FileLock", account_lock)
    monkeypatch.setattr(manager._store, "_write_account_credentials", write)
    manager.persist_backup_credentials("1", "synthetic@example.com", "synthetic")
    assert writes == [("1", "synthetic@example.com")]

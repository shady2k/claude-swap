"""Check the interpreter and import paths used by isolated package launches."""

from __future__ import annotations

import os
import site
import stat
import sys
from pathlib import Path

from claude_swap import fsguard

LOADER_VARS = (
    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
)


def _check_tree(path: Path, checked: set[Path]) -> None:
    pending = [fsguard.check_path(path)]
    while pending:
        directory = pending.pop()
        if directory in checked:
            continue
        checked.add(directory)
        with os.scandir(directory) as children:
            for child in children:
                target = Path(child.path)
                info = child.stat(follow_symlinks=False)
                if child.is_symlink() or target.is_junction():
                    target = fsguard.check_path(target)
                    info = target.stat()
                else:
                    fsguard.check_leaf(target, info)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(target)
                elif not stat.S_ISREG(info.st_mode):
                    raise fsguard.GuardError(f"Unexpected import-path entry: {target}")


def _check_python_chain() -> Path:
    """Run one complete check with fresh traversal state."""
    interpreter = Path(sys.executable)
    original = fsguard.check_path(interpreter)
    if not original.is_file() or not os.access(original, os.X_OK):
        raise fsguard.GuardError(f"Interpreter is not executable: {interpreter}")
    for prefix in {Path(sys.prefix), Path(sys.base_prefix)}:
        fsguard.check_path(prefix)
    for directory in {Path(sys.prefix), interpreter.parent, interpreter.parent.parent}:
        cfg = directory / "pyvenv.cfg"
        if os.path.lexists(cfg) and not fsguard.check_path(cfg).is_file():
            raise fsguard.GuardError(f"Not a regular interpreter configuration: {cfg}")
    checked: set[Path] = set()
    for directory in [*site.getsitepackages(), Path(__file__).absolute().parent]:
        if os.path.lexists(directory):
            _check_tree(Path(directory), checked)
    # Include extra import roots installed via a trusted .pth file, e.g.
    # the source directory of an editable install. Never include cwd.
    for entry in sys.path:
        if entry and Path(entry).is_absolute() and os.path.lexists(entry):
            fsguard.check_path(entry)
    return interpreter


def check_python_chain() -> Path:
    """Return the checked lexical interpreter, preserving venv discovery.

    CPython 3.14.9 imports atomically rename temporary bytecode files. If an entry
    disappears during traversal, restart the entire check once with fresh
    state. Repeated instability fails closed, as do permission and link errors.
    """
    for attempt in range(2):
        try:
            return _check_python_chain()
        except OSError as exc:
            if isinstance(exc, FileNotFoundError) and not attempt:
                continue
            raise fsguard.GuardError(f"Cannot check the Python executable chain: {exc}") from exc

"""The thin ``claude`` wrapper: launch on the best account without switching.

``cswap wrapper`` prints the path of the shipped script (``scripts/claude``).
A symlink to it in a directory ahead of the real Claude Code in ``PATH`` makes
every ``claude``, ``claude --resume`` included, run

    cswap run --auto -- "$@"

so one account is chosen by the ``best`` headroom comparison
(``ClaudeAccountSwitcher.auto_run_target``) and started as its own session
profile with its own proxy — the default login is read, never switched. What
a user sees is in ``docs/auto-launch.md``.

Three rules keep the wrapper and cswap from handing the terminal to each
other in a loop, and keep the account cswap chose:

- The wrapper resolves the real Claude Code itself — the first ``claude`` on
  ``PATH`` that is not this file, symlinks resolved, macOS's ``readlink``
  without ``-f`` — and exports its path as ``CSWAP_REAL_CLAUDE``.
  ``session.find_claude`` prefers that over ``shutil.which``.
- ``session.find_claude`` never returns this file. Started as ``cswap run 3``
  with the wrapper on ``PATH``, it walks ``PATH`` past the wrapper to the real
  binary, so an explicit account is not replaced by an automatic choice, and
  the ``claude auth status`` probe does not become a second cswap.
  :func:`is_wrapper` recognises the shipped file whether it is symlinked or
  copied.
- ``CSWAP_REAL_CLAUDE`` is cswap's own plumbing: ``session._exec`` drops it
  before Claude Code starts, so a ``claude`` a session starts later goes
  through the wrapper and its account choice again.

A copy of the script that is edited (or from another version) is not
recognised as the wrapper: it still reaches the real binary through the
export, but as an ordinary ``claude`` on ``PATH`` whose launch would choose
again. Install it as a symlink.
"""

from __future__ import annotations

import os
from pathlib import Path

#: The variable the wrapper uses to hand the real binary's path down to cswap.
REAL_CLAUDE_ENV = "CSWAP_REAL_CLAUDE"

#: The shipped script. ``cswap wrapper`` prints this; the wheel carries it.
WRAPPER_PATH = Path(__file__).with_name("scripts") / "claude"


def is_wrapper(path: str | os.PathLike[str]) -> bool:
    """Whether ``path`` is this shipped wrapper, symlinked or copied.

    The symlink is the documented install, so its resolved path is compared
    first; a copy has other bytes or the same ones, which the second test
    catches. Anything unreadable is not the wrapper: a broken path must not
    be skipped as if it were cswap's own script.
    """
    try:
        if os.path.realpath(path) == os.path.realpath(WRAPPER_PATH):
            return True
        return Path(path).read_bytes() == WRAPPER_PATH.read_bytes()
    except OSError:
        return False

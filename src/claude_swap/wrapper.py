"""The thin ``claude`` wrapper: launch the recorded active account.

``cswap wrapper`` prints the path of the shipped script (``scripts/claude``).
A symlink to it in a directory ahead of the real Claude Code in ``PATH`` makes
every ``claude``, ``claude --resume`` included, run

    cswap run --active -- "$@"

so the slot recorded in ``sequence.json`` (``cswap switch``) is started in its
own session profile with its own proxy, and the global ``~/.claude`` login is
never read, written or switched. What a user sees is in
``docs/auto-launch.md``.

The script resolves nothing and searches nothing: it checks that ``cswap`` is
on ``PATH`` and replaces itself with ``cswap run --active -- "$@"``. Finding
the real Claude Code is ``session.find_claude``'s single job, so there is one
answer to "which binary is Claude Code" and it cannot disagree with itself.
Its ``--version``/``-v``/``--help``/``-h`` passthrough uses the same rule, so
a caller asking which version is installed gets an answer without an account.

One rule keeps the two from handing the terminal to each other in a loop:
``find_claude`` never returns this file. Started as ``cswap run 3`` with the
wrapper on ``PATH``, it walks ``PATH`` past the wrapper to the real binary, so
an explicit account is not replaced by the wrapper's own launch, and the
``claude auth status`` probe does not become a second cswap. :func:`is_wrapper`
recognises the script by a marker line in its first kilobytes — cheap on a
377 MB binary, and still true of an edited copy or another version.
"""

from __future__ import annotations

import os
from pathlib import Path

#: The shipped script. ``cswap wrapper`` prints this; the wheel carries it.
WRAPPER_PATH = Path(__file__).with_name("scripts") / "claude"

#: The line that makes a file this wrapper, scanned for in its head only.
MARKER = b"# claude-swap thin wrapper"

#: How much of a candidate is read: the marker is in the first line, and a
#: binary the size of Claude Code must never be read whole (measured: 0.21 s
#: and 391 MiB for 377 MB, per check).
HEAD_BYTES = 4096


def is_wrapper(path: str | os.PathLike[str]) -> bool:
    """Whether ``path`` is this shipped wrapper, symlinked, copied or edited.

    The marker line is what it is recognised by, not the bytes of the shipped
    file, so a copy someone adjusted (a different install directory in its
    comment, a newer version of the script) is still known to be a wrapper and
    is still never launched as Claude Code. Anything unreadable is not the
    wrapper: a broken path must not be walked past as if it were our own
    script.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError:
        return False
    return MARKER in head

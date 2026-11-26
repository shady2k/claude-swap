"""Tests for the thin ``claude`` wrapper and what cswap does with it.

The wrapper is a shell script, so most of these run it as a child process with
a PATH built for the case: a fake real ``claude``, a fake ``cswap`` that records
its arguments, and the shipped script itself, installed as the symlink a user
is told to make. Nothing here reaches a real Claude Code, a real account or the
network.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from claude_swap import wrapper

_SRC_DIR = str(Path(__file__).resolve().parent.parent / "src")

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the wrapper is a POSIX shell script; Windows is not a target",
)

# The arguments a shell must hand through untouched: spaces and quotes stay in
# one argument, an empty argument stays an argument, and nothing is expanded.
TRICKY_ARGS = [
    "--resume",
    "-p",
    "two words",
    "",
    "quote\"and'apostrophe",
    "$HOME and `backticks`",
    "*",
    "юникод",
]


FAKE_CLAUDE = '''\
#!{python}
import json, os, sys
record = os.environ.get("WRAPPER_TEST_REAL_RECORD")
if record:
    with open(record, "w", encoding="utf-8") as f:
        json.dump({{"argv": sys.argv[1:]}}, f)
sys.exit(int(os.environ.get("WRAPPER_TEST_REAL_EXIT", "0")))
'''

FAKE_CSWAP = '''\
#!{python}
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["WRAPPER_TEST_CSWAP_RECORD"], "w", encoding="utf-8") as f:
    json.dump({{"argv": argv}}, f)
if os.environ.get("WRAPPER_TEST_HANDOVER"):
    # What the real `cswap run` does on POSIX: replace itself with claude.
    real = os.environ["WRAPPER_TEST_REAL"]
    os.execv(real, [real, *argv[argv.index("--") + 1:]])
sys.exit(int(os.environ.get("WRAPPER_TEST_CSWAP_EXIT", "0")))
'''


def _script(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        body.format(python=sys.executable), encoding="utf-8"
    )
    path.chmod(0o755)
    return path


class TestTheWrapper:
    """`claude ...` becomes `cswap run --active -- ...` and nothing else."""

    @pytest.fixture
    def layout(self, tmp_path: Path) -> dict[str, Path]:
        """The symlinked install, a real claude, and a cswap that records."""
        real = _script(tmp_path / "real" / "claude", FAKE_CLAUDE)
        cswap = _script(tmp_path / "swapper" / "cswap", FAKE_CSWAP)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        link = bin_dir / "claude"
        link.symlink_to(wrapper.WRAPPER_PATH)
        return {
            "tmp": tmp_path,
            "real": real,
            "cswap": cswap,
            "link": link,
            "wrapper_dir": link.parent,
            "real_dir": real.parent,
            "cswap_dir": cswap.parent,
        }

    def _env(self, layout: dict[str, Path], **extra: str) -> dict[str, str]:
        env = {
            "PATH": os.pathsep.join(
                str(layout[name])
                for name in ("wrapper_dir", "real_dir", "cswap_dir")
            ),
            "HOME": str(layout["tmp"] / "home"),
            "WRAPPER_TEST_CSWAP_RECORD": str(layout["tmp"] / "cswap.json"),
            "WRAPPER_TEST_REAL_RECORD": str(layout["tmp"] / "real.json"),
            "WRAPPER_TEST_REAL": str(layout["real"]),
        }
        env.update(extra)
        return env

    @staticmethod
    def _run(cmd: list[str], env: dict[str, str], **kwargs):
        import subprocess

        return subprocess.run(cmd, env=env, capture_output=True, text=True, **kwargs)

    def test_arguments_are_forwarded_verbatim(self, layout):
        result = self._run(
            [str(layout["link"]), *TRICKY_ARGS], self._env(layout)
        )

        assert result.returncode == 0, result.stderr
        recorded = json.loads((layout["tmp"] / "cswap.json").read_text())
        assert recorded["argv"] == ["run", "--active", "--", *TRICKY_ARGS]

    def test_a_plain_claude_forwards_no_arguments(self, layout):
        result = self._run([str(layout["link"])], self._env(layout))

        assert result.returncode == 0, result.stderr
        recorded = json.loads((layout["tmp"] / "cswap.json").read_text())
        assert recorded["argv"] == ["run", "--active", "--"]

    def test_the_real_claude_gets_the_arguments_and_the_exit_code(self, layout):
        """The whole chain: wrapper → cswap → real claude, exit code intact."""
        result = self._run(
            [str(layout["link"]), *TRICKY_ARGS],
            self._env(
                layout, WRAPPER_TEST_HANDOVER="1", WRAPPER_TEST_REAL_EXIT="7"
            ),
        )

        assert result.returncode == 7
        recorded = json.loads((layout["tmp"] / "real.json").read_text())
        assert recorded["argv"] == TRICKY_ARGS

    def test_a_cswap_refusal_is_its_exit_code(self, layout):
        result = self._run(
            [str(layout["link"]), "-p", "hi"],
            self._env(layout, WRAPPER_TEST_CSWAP_EXIT="1"),
        )

        assert result.returncode == 1

    def test_a_second_symlink_hop_still_finds_the_real_claude(self, layout):
        """Installed through another symlink (`~/bin/claude` → a link to the
        script): the script must resolve itself, or it skips the wrong file."""
        hop_dir = layout["tmp"] / "hop"
        hop_dir.mkdir()
        (hop_dir / "claude").symlink_to(layout["link"])

        result = self._run(
            [str(hop_dir / "claude"), "--continue"], self._env(layout)
        )

        assert result.returncode == 0, result.stderr
        recorded = json.loads((layout["tmp"] / "cswap.json").read_text())
        assert recorded["argv"] == ["run", "--active", "--", "--continue"]

    def test_the_wrapper_looks_for_no_binary_of_its_own(self, layout):
        """Finding Claude Code is cswap's single job for a launch: with no
        real binary on PATH the wrapper still hands over, and `cswap run` is
        what reports it."""
        env = self._env(layout)
        env["PATH"] = os.pathsep.join(
            str(layout[name]) for name in ("wrapper_dir", "cswap_dir")
        )

        result = self._run([str(layout["link"]), "--resume"], env)

        assert result.returncode == 0, result.stderr
        recorded = json.loads((layout["tmp"] / "cswap.json").read_text())
        assert recorded["argv"] == ["run", "--active", "--", "--resume"]

    def test_no_cswap_is_a_clear_refusal(self, layout):
        env = self._env(layout)
        env["PATH"] = os.pathsep.join(
            str(layout[name]) for name in ("wrapper_dir", "real_dir")
        )

        result = self._run([str(layout["link"])], env)

        assert result.returncode == 127
        assert "cswap is not on PATH" in result.stderr

    def test_a_quoted_install_path_still_hands_over(self, layout):
        """A directory with a space in it (a common macOS home) stays one PATH
        entry and one argument, not two."""
        spaced = layout["tmp"] / "with space"
        spaced.mkdir()
        link = spaced / "claude"
        link.symlink_to(wrapper.WRAPPER_PATH)

        result = self._run([str(link), "-p", "hi"], self._env(layout))

        assert result.returncode == 0, result.stderr
        recorded = json.loads((layout["tmp"] / "cswap.json").read_text())
        assert recorded["argv"] == ["run", "--active", "--", "-p", "hi"]


class TestIsWrapper:
    """How cswap recognises its own script, so it never launches it."""

    def test_the_shipped_path_is_the_wrapper(self):
        assert wrapper.is_wrapper(wrapper.WRAPPER_PATH)

    def test_a_symlink_to_it_is_the_wrapper(self, tmp_path: Path):
        link = tmp_path / "claude"
        link.symlink_to(wrapper.WRAPPER_PATH)
        assert wrapper.is_wrapper(link)

    def test_a_copy_of_it_is_the_wrapper(self, tmp_path: Path):
        copied = tmp_path / "claude"
        copied.write_bytes(wrapper.WRAPPER_PATH.read_bytes())
        assert wrapper.is_wrapper(copied)

    def test_an_edited_copy_is_still_the_wrapper(self, tmp_path: Path):
        """The marker, not the shipped bytes: a copy whose comments or
        install directory were changed is still a wrapper, and still must
        never be launched as Claude Code."""
        edited = tmp_path / "claude"
        edited.write_text(
            wrapper.WRAPPER_PATH.read_text().replace(
                "~/.local/claude-swap/bin", "~/.local/bin"
            ) + "\n# local tweak\n"
        )
        assert wrapper.is_wrapper(edited)

    def test_another_binary_is_not(self, tmp_path: Path):
        other = tmp_path / "claude"
        other.write_text("#!/bin/sh\nexit 0\n")
        assert not wrapper.is_wrapper(other)

    def test_a_large_binary_is_not_read_whole(self, tmp_path: Path, monkeypatch):
        """A `claude` can be 377 MB (measured: 0.21 s and 391 MiB to compare
        whole); a check on every launch reads only the head."""
        big = tmp_path / "claude"
        with open(big, "wb") as fh:
            fh.write(b"\x7fELF" + b"\0" * (8 * 1024 * 1024))
        read_bytes = 0
        real_open = open

        class Counting:
            def __init__(self, fh):
                self._fh = fh

            def read(self, size=-1):
                nonlocal read_bytes
                read_bytes += size if size and size > 0 else 0
                return self._fh.read(size)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._fh.close()

        monkeypatch.setattr(
            "builtins.open",
            lambda path, *a, **k: (
                Counting(real_open(path, *a, **k))
                if str(path) == str(big)
                else real_open(path, *a, **k)
            ),
        )

        assert not wrapper.is_wrapper(big)
        assert read_bytes <= wrapper.HEAD_BYTES

    def test_a_missing_path_is_not(self, tmp_path: Path):
        assert not wrapper.is_wrapper(tmp_path / "nope")


class TestTheRealCliAcceptsIt:
    """The wrapper's one command line is a real `cswap run --active`, so the
    real parser takes it (and refuses for a reason, not for a usage error)."""

    def test_a_refusal_is_a_reason_not_a_usage_error(self, tmp_path: Path):
        import subprocess

        home = tmp_path / "home"
        home.mkdir()
        shim_dir = tmp_path / "shim"
        _script(
            shim_dir / "cswap",
            "#!{python}\nimport sys\nfrom claude_swap.cli import main\n"
            "sys.argv[0] = 'cswap'\nmain()\n",
        )
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        link = bin_dir / "claude"
        link.symlink_to(wrapper.WRAPPER_PATH)
        _script(tmp_path / "real" / "claude", FAKE_CLAUDE)

        env = {
            "PATH": os.pathsep.join(
                [
                    str(bin_dir),
                    str(shim_dir),
                    str(tmp_path / "real"),
                    os.environ.get("PATH", ""),
                ]
            ),
            "HOME": str(home),
            "PYTHONPATH": _SRC_DIR,
            "WRAPPER_TEST_REAL_RECORD": str(tmp_path / "real.json"),
        }
        result = subprocess.run(
            [str(link), "--resume"], env=env, capture_output=True, text=True
        )

        assert result.returncode == 1, result.stderr
        assert "No active account is recorded" in result.stderr
        assert "unrecognized arguments" not in result.stderr
        assert not (tmp_path / "real.json").exists()

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
import shutil
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


class TestWrapperCommands:
    @pytest.fixture(autouse=True)
    def set_up(self, temp_home, tmp_path, monkeypatch):
        self.bin = temp_home / ".local" / "claude-swap" / "bin"
        self.real = _script(tmp_path / "real" / "claude", FAKE_CLAUDE)
        self.profile = temp_home / ".bashrc"
        monkeypatch.setenv("SHELL", "/bin/bash")
        monkeypatch.setenv("PATH", str(self.real.parent))
        monkeypatch.delenv("CSWAP_CLAUDE_BIN", raising=False)

    def run_command(self, monkeypatch, *args):
        from claude_swap.cli import main

        monkeypatch.setattr(sys, "argv", ["cswap", "wrapper", *args])
        main()

    def test_print_shipped_script(self, monkeypatch, capsys):
        self.run_command(monkeypatch)
        assert capsys.readouterr().out == f"{wrapper.WRAPPER_PATH}\n"

    @pytest.mark.parametrize(
        ("shell", "profile", "command"),
        [
            ("bash", ".bashrc", b"export PATH="),
            ("zsh", ".zshrc", b"export PATH="),
            ("fish", ".config/fish/config.fish", b"set -gx PATH "),
        ],
    )
    def test_install_repeat_and_clean_uninstall(
        self, shell, profile, command, temp_home, monkeypatch, capsys
    ):
        monkeypatch.setenv("SHELL", f"/bin/{shell}")
        profile = temp_home / profile
        profile.parent.mkdir(parents=True, exist_ok=True)
        original = b"# keep this comment\r\n# keep bytes and absent final newline: \xff"
        profile.write_bytes(original)
        profile.chmod(0o640)

        self.run_command(monkeypatch, "install")
        link = self.bin / "claude"
        assert link.is_symlink() and link.resolve() == wrapper.WRAPPER_PATH.resolve()
        edited = profile.read_bytes()
        assert edited.startswith(original) and command in edited
        assert b"claude-swap" in edited
        assert profile.stat().st_mode & 0o777 == 0o640
        self.run_command(monkeypatch, "install")
        assert profile.read_bytes() == edited

        self.run_command(monkeypatch, "uninstall")
        assert not os.path.lexists(link)
        assert profile.read_bytes() == original
        self.run_command(monkeypatch, "uninstall")
        assert profile.read_bytes() == original
        assert "Wrapper is not installed" in capsys.readouterr().out

    @pytest.mark.parametrize("on_path", [False, True])
    def test_custom_install_dir(self, on_path, temp_home, monkeypatch, capsys):
        custom = temp_home / "custom bin"
        if on_path:
            alias = temp_home / "path-alias"
            alias.symlink_to(custom, target_is_directory=True)
            monkeypatch.setenv("PATH", f"~/path-alias/:{self.real.parent}")
        self.run_command(monkeypatch, "install", "--dir", "~/custom bin")
        assert (custom / "claude").is_symlink()
        assert self.profile.exists() is not on_path
        capsys.readouterr()
        if on_path:
            monkeypatch.setenv("PATH", f"{custom}:{self.real.parent}")
        self.run_command(monkeypatch, "status")
        output = capsys.readouterr().out
        installed_dir = custom if on_path else custom.resolve()
        assert f"Installed at {installed_dir / 'claude'}" in output
        assert str(self.real) in output
        assert ("Active in PATH" in output) is on_path
        self.run_command(monkeypatch, "uninstall", "--dir", str(custom))
        assert not (custom / "claude").exists()
        if not on_path:
            assert self.profile.read_bytes() == b""

    def test_custom_dir_ignores_a_path_entry_it_cannot_stat(
        self, temp_home, tmp_path, monkeypatch, capsys
    ):
        """A PATH entry below a plain file raises ENOTDIR, not ENOENT; it is
        not the directory being installed into, so the profile gets the block."""
        plain_file = tmp_path / "plain-file"
        plain_file.write_text("a file, not a directory")
        monkeypatch.setenv(
            "PATH", os.pathsep.join([f"{plain_file}/bin", str(self.real.parent)])
        )
        custom = temp_home / "custom"

        self.run_command(monkeypatch, "install", "--dir", str(custom))

        assert (custom / "claude").is_symlink()
        assert b"export PATH=" in self.profile.read_bytes()

    def test_an_empty_path_does_not_mean_the_current_directory(
        self, temp_home, tmp_path, monkeypatch, capsys
    ):
        """PATH="" searches nothing; the directory cswap runs in is not on it."""
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        monkeypatch.setenv("PATH", "")
        monkeypatch.setenv("CSWAP_CLAUDE_BIN", str(self.real))

        self.run_command(monkeypatch, "install", "--dir", ".")

        assert b"export PATH=" in self.profile.read_bytes()

    @pytest.mark.parametrize("action", ["install", "uninstall"])
    @pytest.mark.parametrize("kind", ["file", "binary", "dangling", "fifo"])
    def test_refuses_to_touch_foreign_target(self, action, kind, monkeypatch, capsys):
        self.bin.mkdir(parents=True)
        target = self.bin / "claude"
        if kind == "file":
            target.write_text("user data")
        elif kind == "binary":
            target.symlink_to(self.real)
        elif kind == "dangling":
            target.symlink_to(self.bin / "missing")
        else:
            os.mkfifo(target)
        before = target.lstat()
        self.profile.write_text("# keep me\n")

        # A named directory keeps the strict refusal; without --dir the
        # harmless no-op is below.
        args = ["--dir", str(self.bin)] if action == "uninstall" else []
        with pytest.raises(SystemExit) as exc:
            self.run_command(monkeypatch, action, *args)
        assert exc.value.code == 1
        assert "Refusing" in capsys.readouterr().err
        assert target.lstat().st_ino == before.st_ino
        assert self.profile.read_text() == "# keep me\n"

    @pytest.mark.parametrize("kind", ["file", "binary", "dangling", "fifo"])
    def test_uninstall_without_dir_leaves_a_foreign_target_alone(
        self, kind, monkeypatch, capsys
    ):
        """A real or foreign `claude` in a standard directory is not ours to
        remove, and its presence is not an error when no wrapper is installed."""
        self.bin.mkdir(parents=True)
        target = self.bin / "claude"
        if kind == "file":
            target.write_text("user data")
        elif kind == "binary":
            target.symlink_to(self.real)
        elif kind == "dangling":
            target.symlink_to(self.bin / "missing")
        else:
            os.mkfifo(target)
        before = target.lstat()
        self.profile.write_text("# keep me\n")

        self.run_command(monkeypatch, "uninstall")

        assert target.lstat().st_ino == before.st_ino
        assert self.profile.read_text() == "# keep me\n"
        assert "Wrapper is not installed" in capsys.readouterr().out

    def test_requires_real_claude(self, monkeypatch, capsys):
        monkeypatch.setenv("PATH", "")
        with pytest.raises(SystemExit) as exc:
            self.run_command(monkeypatch, "install")
        assert exc.value.code == 1
        assert "real Claude Code" in capsys.readouterr().err
        assert not self.bin.exists() and not self.profile.exists()

    def test_unknown_shell_gives_manual_path(self, temp_home, monkeypatch, capsys):
        monkeypatch.setenv("SHELL", "/bin/unknown")
        self.run_command(monkeypatch, "install")
        assert f'export PATH={self.bin}:"$PATH"' in capsys.readouterr().out
        assert (self.bin / "claude").is_symlink()
        assert not self.profile.exists()
        assert not (temp_home / ".zshrc").exists()
        assert not (temp_home / ".config").exists()

    def test_status_finds_custom_install_without_a_profile(self, temp_home, monkeypatch, capsys):
        monkeypatch.setenv("SHELL", "/bin/unknown")
        custom = temp_home / "custom"
        self.run_command(monkeypatch, "install", "--dir", str(custom))
        capsys.readouterr()
        self.run_command(monkeypatch, "status")
        assert f"Installed at {custom.resolve() / 'claude'}" in capsys.readouterr().out
        self.run_command(monkeypatch, "uninstall", "--dir", str(custom))
        capsys.readouterr()
        self.run_command(monkeypatch, "status")
        assert "Wrapper is not installed" in capsys.readouterr().out

    def test_profile_edit_follows_symlink_and_quotes_path(
        self, temp_home, tmp_path, monkeypatch
    ):
        import subprocess

        profile = tmp_path / "dotfiles-bash"
        profile.write_bytes(b"# my profile\n")
        self.profile.symlink_to(profile)
        custom = temp_home / "my bin' \\$HOME"

        self.run_command(monkeypatch, "install", "--dir", str(custom))
        result = subprocess.run(
            ["/bin/sh", "-c", '. "$1"; command -v claude', "sh", str(self.profile)],
            check=True, capture_output=True, text=True,
        )
        assert Path(result.stdout.strip()) == custom / "claude"
        self.run_command(monkeypatch, "uninstall", "--dir", str(custom))
        assert self.profile.is_symlink()
        assert profile.read_bytes() == b"# my profile\n"

    def test_profile_error_rolls_back_new_symlink(self, monkeypatch, capsys):
        self.profile.mkdir()
        with pytest.raises(SystemExit) as exc:
            self.run_command(monkeypatch, "install")
        assert exc.value.code == 1
        assert "Shell profile" in capsys.readouterr().err
        assert not os.path.lexists(self.bin / "claude")
        assert self.profile.is_dir()

    def test_uninstall_after_shell_change_only_removes_its_own_block(
        self, temp_home, monkeypatch
    ):
        self.profile.write_bytes(b"# user line")
        self.run_command(monkeypatch, "install")
        other = temp_home / "other"
        self.run_command(monkeypatch, "install", "--dir", str(other))
        with self.profile.open("ab") as fh:
            fh.write(b"# another user line\n")
        monkeypatch.setenv("SHELL", "/bin/zsh")

        self.run_command(monkeypatch, "uninstall")
        assert (other / "claude").is_symlink()
        self.run_command(monkeypatch, "uninstall", "--dir", str(other))
        assert self.profile.read_bytes() == b"# user line\n# another user line\n"


class TestSmartInstallDirectory:
    """`install` without --dir prefers a `~/.local/bin` already on PATH.

    The directory is the one user-local place that is normally ahead of the
    real Claude Code in `PATH`, so a symlink there needs no profile edit and
    is seen by background services and IDEs at once. Every other case keeps
    the private directory and its marked profile block.
    """

    @pytest.fixture(autouse=True)
    def set_up(self, temp_home, tmp_path, monkeypatch):
        self.home = temp_home
        self.local_bin = temp_home / ".local" / "bin"
        self.fallback = temp_home / ".local" / "claude-swap" / "bin"
        self.real = _script(tmp_path / "real" / "claude", FAKE_CLAUDE)
        self.profile = temp_home / ".bashrc"
        monkeypatch.setenv("SHELL", "/bin/bash")
        monkeypatch.delenv("CSWAP_CLAUDE_BIN", raising=False)

    def set_path(self, monkeypatch, *entries: Path) -> None:
        monkeypatch.setenv("PATH", os.pathsep.join(str(entry) for entry in entries))

    @staticmethod
    def profiles(home: Path) -> list[Path]:
        return [
            home / ".bashrc",
            home / ".zshrc",
            home / ".config" / "fish" / "config.fish",
        ]

    def test_a_local_bin_ahead_of_the_real_claude_hosts_the_wrapper(
        self, monkeypatch
    ):
        """`~/.local/bin` is created when needed, stays out of the profiles,
        and the wrapper is active the moment it lands."""
        self.set_path(monkeypatch, self.local_bin, self.real.parent)

        message = wrapper.install()

        link = self.local_bin / "claude"
        assert link.is_symlink() and link.resolve() == wrapper.WRAPPER_PATH.resolve()
        assert message == (
            f"Installed at {link}."
            " If you already ran 'claude' in this shell, run 'hash -r' (Bash)"
            " or 'rehash' (Zsh)."
        )
        assert all(not profile.exists() for profile in self.profiles(self.home))
        assert wrapper.is_wrapper(shutil.which("claude"))
        assert not wrapper.needs_setup(for_add=True)
        assert not wrapper.needs_setup()

        # Repeat install: same symlink, same answer, no second block anywhere.
        before = link.lstat().st_ino
        assert wrapper.install() == message
        assert link.lstat().st_ino == before
        assert all(not profile.exists() for profile in self.profiles(self.home))

    def test_a_real_claude_in_local_bin_keeps_the_wrapper_out_of_it(
        self, monkeypatch
    ):
        """A `claude` that is not ours is never replaced, and the private
        directory plus the profile line is used instead."""
        self.local_bin.mkdir(parents=True)
        occupant = self.local_bin / "claude"
        occupant.symlink_to(self.real)
        self.set_path(monkeypatch, self.local_bin, self.real.parent)

        message = wrapper.install()

        assert occupant.is_symlink() and occupant.resolve() == self.real.resolve()
        assert (self.fallback / "claude").is_symlink()
        assert b"export PATH=" in self.profile.read_bytes()
        assert "Open a new shell" in message
        assert "do not read your shell profile" in message

    @pytest.mark.parametrize("placement", ["after", "absent"])
    def test_other_path_shapes_fall_back_to_the_private_directory(
        self, placement, monkeypatch
    ):
        if placement == "after":
            self.set_path(monkeypatch, self.real.parent, self.local_bin)
        else:
            self.set_path(monkeypatch, self.real.parent)

        message = wrapper.install()

        assert (self.fallback / "claude").is_symlink()
        assert not os.path.lexists(self.local_bin / "claude")
        assert b"export PATH=" in self.profile.read_bytes()
        assert "Open a new shell" in message
        assert "do not read your shell profile" in message
        # The standard install is done, so `cswap add` stops asking for it
        # even though `claude` still resolves to the real binary here.
        assert not wrapper.needs_setup(for_add=True)
        assert wrapper.needs_setup()

    def test_a_dangling_local_bin_falls_back(self, monkeypatch):
        """A `~/.local/bin` symlink to a removed directory is named on PATH but
        cannot hold anything, so the private directory is used."""
        self.local_bin.parent.mkdir(parents=True)
        self.local_bin.symlink_to(self.local_bin.parent / "gone")
        self.set_path(monkeypatch, self.local_bin, self.real.parent)

        message = wrapper.install()

        assert (self.fallback / "claude").is_symlink()
        assert b"export PATH=" in self.profile.read_bytes()
        assert "Open a new shell" in message

    @pytest.mark.parametrize("exists", [True, False])
    def test_a_local_bin_behind_a_missing_directory_falls_back(
        self, exists, monkeypatch
    ):
        """`$HOME/.local/gone/../bin` collapses to `~/.local/bin` lexically,
        but a lookup through it answers ENOENT while `gone` is missing, so
        the OS never resolves `claude` there and the private directory is
        used, whether `~/.local/bin` exists yet or not."""
        self.local_bin.parent.mkdir(parents=True)
        if exists:
            self.local_bin.mkdir()
        broken = self.local_bin.parent / "gone" / ".." / "bin"
        self.set_path(monkeypatch, broken, self.real.parent)

        message = wrapper.install()

        assert (self.fallback / "claude").is_symlink()
        assert not os.path.lexists(self.local_bin / "claude")
        assert b"export PATH=" in self.profile.read_bytes()
        assert "Open a new shell" in message
        assert "do not read your shell profile" in message

    def test_the_shell_cache_advice_names_both_shells(self, monkeypatch):
        """The hint follows the shell that will run it, not `$SHELL`: a Bash
        started from Zsh still needs `hash -r`."""
        monkeypatch.setenv("SHELL", "/usr/bin/zsh")
        self.set_path(monkeypatch, self.local_bin, self.real.parent)

        message = wrapper.install()

        assert message == (
            f"Installed at {self.local_bin / 'claude'}."
            " If you already ran 'claude' in this shell, run 'hash -r' (Bash)"
            " or 'rehash' (Zsh)."
        )
        assert not (self.home / ".zshrc").exists()

    def test_cswap_claude_bin_outside_path_still_takes_local_bin(self, monkeypatch):
        """The real binary may be named by CSWAP_CLAUDE_BIN only; the wrapper
        still belongs where `claude` is resolved from."""
        monkeypatch.setenv("CSWAP_CLAUDE_BIN", str(self.real))
        self.set_path(monkeypatch, self.local_bin)

        message = wrapper.install()

        assert (self.local_bin / "claude").is_symlink()
        assert all(not profile.exists() for profile in self.profiles(self.home))
        assert "do not read your shell profile" not in message

    def test_status_and_uninstall_find_the_wrapper_in_local_bin(self, monkeypatch):
        self.set_path(monkeypatch, self.local_bin, self.real.parent)
        wrapper.install()
        link = self.local_bin / "claude"

        found = wrapper.status()
        assert found.installed is not None and found.installed.samefile(link)
        assert found.active
        assert wrapper.uninstall() == f"Removed wrapper setup for {link}."
        assert not os.path.lexists(link)
        assert wrapper.status().installed is None

    def test_uninstall_leaves_a_real_claude_in_local_bin_alone(self, monkeypatch):
        self.local_bin.mkdir(parents=True)
        occupant = self.local_bin / "claude"
        occupant.symlink_to(self.real)
        self.set_path(monkeypatch, self.real.parent)
        wrapper.install()
        link = self.fallback / "claude"
        assert link.is_symlink()

        message = wrapper.uninstall()

        assert not os.path.lexists(link)
        assert occupant.is_symlink() and occupant.resolve() == self.real.resolve()
        assert message.startswith("Removed wrapper setup")
        assert self.profile.read_bytes() == b""

    def test_uninstall_when_local_bin_links_to_the_private_directory(
        self, monkeypatch
    ):
        """`~/.local/bin` may be a symlink to the private directory, so both
        standard paths are one file: it is removed once and the profile block
        still goes."""
        self.local_bin.parent.mkdir(parents=True)
        self.fallback.mkdir(parents=True)
        self.local_bin.symlink_to(self.fallback)
        self.set_path(monkeypatch, self.real.parent)
        wrapper.install()
        link = self.fallback / "claude"
        assert link.is_symlink()
        assert b"export PATH=" in self.profile.read_bytes()

        message = wrapper.uninstall()

        assert not os.path.lexists(link)
        assert "Removed wrapper setup" in message
        assert self.profile.read_bytes() == b""

    def test_needs_setup_ignores_a_wrapper_outside_path(self, monkeypatch, tmp_path):
        """A hand-installed wrapper in a custom directory that PATH does not
        reach leaves `cswap add` asking for the standard setup."""
        custom = tmp_path / "custom"
        self.set_path(monkeypatch, self.real.parent)
        wrapper.install(custom)
        assert wrapper.is_wrapper(custom / "claude")

        assert wrapper.needs_setup(for_add=True)

    def test_only_the_standard_directories_are_standard(self, monkeypatch, tmp_path):
        """The TUI asks this before choosing an uninstall target, so a custom
        `--dir` must not be mistaken for one of the two standard places."""
        self.set_path(monkeypatch, self.real.parent)
        wrapper.install(tmp_path / "custom")

        assert wrapper.is_standard_directory(self.local_bin)
        assert wrapper.is_standard_directory(self.fallback)
        assert not wrapper.is_standard_directory(tmp_path / "custom")

"""Portable no-network stand for trusted Python scripts, not a native sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import venv
from collections import Counter
from importlib.metadata import version
from pathlib import Path


_SOURCE = Path(__file__).resolve().parents[1] / "src"
_STARTUP = Path(__file__).with_name("fixtures") / "stand_sitecustomize.py"


class StandAudit:
    """Run real isolated Python processes with an audit hook before user code.

    Only explicitly registered scripts or the installed test shim may start,
    using this stand's interpreter and ``-I``. Do not register untrusted code:
    CPython audit hooks detect accidental egress, not hostile native code.
    The separate Linux stand checks native network syscalls independently.
    """

    def __init__(self, tmp_path: Path, *, probe_socket_operations: bool = False) -> None:
        self.root = tmp_path.resolve() / "audit-stand"
        self.root.mkdir()
        dirs = {}
        for name in ("home", "config", "data", "cache", "state", "tmp", "bin", "work"):
            dirs[name] = self.root / name
            dirs[name].mkdir()
        self.cwd = dirs["work"]
        self._env = {
            "HOME": str(dirs["home"]),
            "USERPROFILE": str(dirs["home"]),
            "APPDATA": str(dirs["config"]),
            "LOCALAPPDATA": str(dirs["data"]),
            "CLAUDE_CONFIG_DIR": str(dirs["config"] / "claude"),
            "XDG_CONFIG_HOME": str(dirs["config"]),
            "XDG_DATA_HOME": str(dirs["data"]),
            "XDG_CACHE_HOME": str(dirs["cache"]),
            "XDG_STATE_HOME": str(dirs["state"]),
            "TMP": str(dirs["tmp"]),
            "TEMP": str(dirs["tmp"]),
            "TMPDIR": str(dirs["tmp"]),
            "PATH": str(dirs["bin"]),
            "NO_PROXY": "*",
            "LC_ALL": "C",
            "CLAUDE_SWAP_TEST_MODE": "1",
        }
        if os.name == "nt" and "SystemRoot" in os.environ:
            self._env["SYSTEMROOT"] = os.environ["SystemRoot"]

        class Builder(venv.EnvBuilder):
            def post_setup(self, context):
                self.context = context

        builder = Builder(with_pip=False, symlinks=os.name != "nt")
        builder.create(self.root / "venv")
        self.python = Path(builder.context.env_exe)
        site = Path(builder.context.lib_path)
        shutil.copyfile(_STARTUP, site / "sitecustomize.py")
        # Allow importing the checked-out source without adding the ambient
        # environment's site-packages or executing any of its .pth files.
        metadata = site / "claude_swap.dist-info"
        metadata.mkdir()
        (metadata / "METADATA").write_text(
            f"Name: claude-swap\nVersion: {version('claude-swap')}\n", encoding="utf-8",
        )
        self._policy = site / "stand-policy.json"
        self.journal = self.root / "audit.jsonl"
        self.journal.touch()
        self._probe_socket_operations = probe_socket_operations
        self._allowed: dict[str, tuple[int, str]] = {}
        self._roots: Counter[int] = Counter()
        self._shim = None

    @property
    def env(self) -> dict[str, str]:
        return self._env.copy()

    def allow(self, script: Path) -> Path:
        """Register a trusted script and pin its contents; return its absolute path."""
        script = script.resolve(strict=True)
        key = os.path.normcase(str(script))
        digest = hashlib.sha256(script.read_bytes()).hexdigest()
        if key not in self._allowed:
            self._allowed[key] = (len(self._allowed) + 1, digest)
        elif self._allowed[key][1] != digest:
            raise ValueError("registered stand script changed")
        self._write_policy()
        return script

    def _write_policy(self) -> None:
        self._policy.write_text(json.dumps({
            "python": str(self.python),
            "root": str(self.root),
            "launch_journal_start": self.journal.stat().st_size,
            "source": str(_SOURCE),
            "journal": str(self.journal),
            "env": self._env,
            "probe_socket_operations": self._probe_socket_operations,
            "scripts": self._allowed,
            "shim": self._shim,
        }), encoding="utf-8")

    def run(self, script: Path, *args: str, check_audit: bool = True) -> subprocess.CompletedProcess[str]:
        script = self.allow(script)
        script_id, _ = self._allowed[os.path.normcase(str(script))]
        self._roots[script_id] += 1
        result = subprocess.run(
            [str(self.python), "-I", str(script), *args],
            cwd=self.cwd, env=self.env, close_fds=True,
            stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8", timeout=30,
        )
        if check_audit:
            self.assert_clean()
        return result

    def run_shim(
        self, installer: Path, source: str, *args: str,
    ) -> subprocess.CompletedProcess[str]:
        """Install and run a trusted synthetic Claude under the audit hook."""
        from claude_swap import paths, test_mode
        from claude_swap.session import session_dir_for

        # The fixture sets CLAUDE_CONFIG_DIR and isolates all homes. Compute
        # the shim directory with that fixture's XDG data/home, not pytest's.
        if sys.platform == "linux":
            backup = Path(self._env["XDG_DATA_HOME"]) / "claude-swap"
        else:
            backup = Path(self._env["HOME"]) / paths.LEGACY_BACKUP_DIRNAME
        shim_dir = paths.get_shim_dir(backup)
        email, uuid = "audit@example.test", "audit-profile"
        profile = session_dir_for(backup, "1", email)
        profile.mkdir(mode=0o700, parents=True)
        (backup / "sequence.json").write_text(json.dumps({"accounts": {"1": {"email": email, "uuid": uuid}}}))
        (profile / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": email, "accountUuid": uuid}}))
        fake = self.root / "bin" / "claude"
        # No interpreter path-length or quoting assumptions: the kernel runs
        # /bin/sh, which immediately execs the designated isolated Python.
        program = fake.with_suffix(".py")
        program.write_text(source, encoding="utf-8")
        fake.write_text(
            f"#!/bin/sh\nexec {shlex.quote(str(self.python))} -I {shlex.quote(str(program))} \"$@\"\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        self._env.update({
            test_mode.ENDPOINT: "https://api.portable.test",
            test_mode.CLAUDE_BASE: "https://api.portable.test",
            test_mode.PROXY: "http://127.0.0.1:18080",
            test_mode.ALLOW: str(fake),
            "PATH": f"{shim_dir}{os.pathsep}{fake.parent}",
            # Normalize variables added by /bin/sh (bash on macOS).
            "PWD": str(self.cwd),
            "SHLVL": "0",
        })
        self.allow(program)
        # The route strips this key before handoff. No socket is permitted,
        # including to the designated synthetic proxy.
        child_env = self.env
        del child_env["NO_PROXY"]
        child_env.update(CLAUDE_CONFIG_DIR=str(profile), CLAUDE_SECURESTORAGE_CONFIG_DIR=str(profile))
        self._shim = {
            "argv": list(args),
            "dir": str(shim_dir),
            "fake": str(fake),
            "fake_digest": hashlib.sha256(fake.read_bytes()).hexdigest(),
            "script": os.path.normcase(str(program)),
            "child_env": child_env,
        }
        installed = self.run(installer)
        if installed.returncode or not (shim_dir / "claude").is_file():
            raise AssertionError(f"shim install failed: {installed.stderr}")
        self._roots[0] += 1  # Audited startup of the installed shim, not a .py script.
        self._write_policy()
        return subprocess.run(
            ["claude", *args], cwd=self.cwd, env=self.env, close_fds=True,
            stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8", timeout=30,
        )

    def records(self) -> list[dict]:
        """Read the sanitized observations, including deliberately blocked events."""
        return [json.loads(line) for line in self.journal.read_text(encoding="utf-8").splitlines()]

    def assert_clean(self) -> None:
        records = self.records()
        blocked = next((r for r in records if r["kind"] == "blocked"), None)
        if blocked is not None:
            event = blocked["event"]
            if event == "startup":
                details = {key: blocked[key] for key in ("stage", "environment") if key in blocked}
                raise AssertionError(f"stand blocked startup: {blocked['reason']} {json.dumps(details)}")
            raise AssertionError(f"stand blocked an operation: {event}")
        expected = self._roots + Counter(r["script"] for r in records if r["kind"] in {"spawn", "exec"})
        started = Counter(r["script"] for r in records if r["kind"] == "startup")
        if not expected or started != expected:
            raise AssertionError("missing or unexpected isolated audit startup marker")

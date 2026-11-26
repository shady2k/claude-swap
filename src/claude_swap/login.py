"""The isolated profile behind ``cswap add --login``.

``cswap add`` captures the login of the profile the user is already in. When
that is not the account being added — a second account, or any account on a
machine whose live login must stay put — cswap runs Claude Code's own
``claude auth login`` in a throwaway ``CLAUDE_CONFIG_DIR`` instead of writing
an OAuth client of its own. Claude Code owns the registration, the PKCE
exchange and the credential format; cswap only reads what it leaves behind.

The directory is created 0700 and removed in ``finally`` on every path: a
completed login, a refused one and Ctrl+C. On macOS Claude Code stores the
credential in a Keychain item whose service name is hashed from that
directory, so the item is deleted in the same ``finally``; an absent item is
success.

The child gets the environment a launch gets (``session._claude_env``): the
auth-override variables and ``CLAUDE_SECURESTORAGE_CONFIG_DIR`` are dropped,
the account's proxy is written in both spellings when one was given, and
``CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`` follows
``run.disableNonessentialTraffic``. Nothing here prints a credential, a proxy
URL or its password.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from claude_swap import oauth, spawn
from claude_swap.account_proxy import ProxyRoute
from claude_swap.exceptions import CredentialReadError, LoginError
from claude_swap.session import (
    AUTH_OVERRIDE_ENV_VARS,
    _claude_env,
    delete_macos_keychain_entry,
    read_config_dir_credentials,
)
from claude_swap.settings import DEFAULT_NO_PROXY, load_run_settings


@dataclass(frozen=True)
class LoginResult:
    """What Claude Code left in the isolated profile after a completed login."""

    credentials: str
    config: str
    email: str
    account_uuid: str
    organization_uuid: str
    organization_name: str


@contextmanager
def isolated_profile() -> Iterator[Path]:
    """A private ``CLAUDE_CONFIG_DIR`` that holds nothing once the block ends.

    ``tempfile.mkdtemp`` already creates a 0700 directory on POSIX; the
    explicit ``chmod`` states the requirement rather than relying on it.
    Windows has no POSIX mode bits, so the call is POSIX-only.
    """
    config_dir = Path(tempfile.mkdtemp(prefix="cswap-login-"))
    try:
        if os.name != "nt":
            os.chmod(config_dir, 0o700)
        yield config_dir
    finally:
        delete_macos_keychain_entry(config_dir)
        shutil.rmtree(config_dir, ignore_errors=True)


def login_environment(
    config_dir: Path, route: ProxyRoute | None, backup_dir: Path
) -> dict[str, str]:
    """The environment ``claude auth login`` runs with in the isolated profile.

    Built from the same pieces a ``cswap run`` launch uses, so the login
    exchange follows the account's proxy and the ``run`` settings instead of a
    second copy of those rules.
    """
    run = load_run_settings(backup_dir)
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in AUTH_OVERRIDE_ENV_VARS
    }
    env.pop("CLAUDE_SECURESTORAGE_CONFIG_DIR", None)
    env["CLAUDE_CONFIG_DIR"] = str(config_dir)
    no_proxy = DEFAULT_NO_PROXY if route is None else run.no_proxy
    return _claude_env(env, route, no_proxy, run.disable_nonessential_traffic)


def run_login(
    claude_bin: str,
    config_dir: Path,
    route: ProxyRoute | None,
    backup_dir: Path,
    email: str | None = None,
) -> LoginResult:
    """Run the official login command and read what it left behind.

    The child keeps the terminal: the browser flow needs it, and cswap has
    nothing to add to that exchange. A non-zero exit, or a profile without a
    usable credential or identity, is :class:`LoginError`; the caller has not
    touched a slot at that point.
    """
    argv = [claude_bin, "auth", "login", "--claudeai"]
    if email is not None:
        argv += ["--email", email]
    env = login_environment(config_dir, route, backup_dir)
    try:
        completed = spawn.run(argv, env=env)
    except OSError as e:
        raise LoginError(
            f"Could not run Claude Code's login: {e.strerror or e}"
        ) from None
    if completed.returncode != 0:
        raise LoginError(
            "`claude auth login` exited with status "
            f"{completed.returncode}; no account was added."
        )
    return read_login_result(config_dir)


def read_login_result(config_dir: Path) -> LoginResult:
    """Read the credential and ``oauthAccount`` metadata from the profile.

    The credential read is strict about the Keychain: falling back to a
    plaintext seed the login itself did not write would file an old token
    under the new identity. The metadata is the profile's ``.claude.json``,
    the same file ``add_account`` reads for the live login.
    """
    try:
        credentials = read_config_dir_credentials(
            str(config_dir), strict_keychain=True
        )
    except CredentialReadError as e:
        raise LoginError(
            "Claude Code's login left no readable credential: "
            f"{e}; no account was added."
        ) from None
    oauth_data = oauth.extract_oauth_data(credentials or "")
    token = (oauth_data or {}).get("accessToken")
    if not isinstance(token, str) or not token:
        raise LoginError(
            "Claude Code's login did not leave an OAuth credential; "
            "no account was added."
        )

    config_path = config_dir / ".claude.json"
    try:
        config = config_path.read_text(encoding="utf-8")
        data = json.loads(config)
    except (OSError, ValueError):
        raise LoginError(
            "Claude Code's login left no readable account metadata; "
            "no account was added."
        ) from None
    oauth_account = data.get("oauthAccount") if isinstance(data, dict) else None
    if not isinstance(oauth_account, dict):
        raise LoginError(
            "Claude Code's login left no account metadata; no account was added."
        )
    email = oauth_account.get("emailAddress")
    if not isinstance(email, str) or not email.strip():
        raise LoginError(
            "Claude Code's login left no account email; no account was added."
        )
    return LoginResult(
        credentials=credentials,
        config=config,
        email=email.strip(),
        account_uuid=oauth_account.get("accountUuid") or "",
        organization_uuid=oauth_account.get("organizationUuid") or "",
        organization_name=oauth_account.get("organizationName") or "",
    )

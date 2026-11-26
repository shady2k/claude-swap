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
``run.disableNonessentialTraffic``. For a scheme urllib cannot speak the
variables carry the loopback address of a bridge opened for this one child
(``account_proxy.bridge``), so the proxy's password never enters that child's
environment. Nothing here prints a credential, a proxy URL or its password.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from claude_swap import macos_keychain, oauth, proxy_bridge, spawn
from claude_swap.account_proxy import ProxyRoute, bridge as account_bridge
from claude_swap.exceptions import CredentialReadError, LoginError
from claude_swap.models import Platform
from claude_swap.session import (
    _keychain_account_name,
    _probe_env,
    keychain_service_name,
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


def _delete_profile_keychain(config_dir: Path) -> None:
    """Delete the temporary profile's Keychain item, warning when that fails.

    Claude Code stores the isolated profile's credential under the service
    name ``keychain_service_name`` derives from ``CLAUDE_CONFIG_DIR``. An
    absent item is success (rc 44, which ``delete_password`` already treats
    as such). Any other failure leaves an item behind for a directory that is
    about to disappear, so it is reported and the command continues. The
    warning names neither the credential nor anything read from the item.
    """
    if Platform.detect() != Platform.MACOS:
        return
    try:
        macos_keychain.delete_password(
            keychain_service_name(config_dir), _keychain_account_name()
        )
    except macos_keychain.KEYCHAIN_ERRORS:
        print(
            "warning: could not delete the temporary login Keychain entry; "
            "it may remain in the Keychain.",
            file=sys.stderr,
        )


@contextmanager
def isolated_profile() -> Iterator[Path]:
    """A private ``CLAUDE_CONFIG_DIR`` that holds nothing once the block ends.

    ``tempfile.mkdtemp`` already creates a 0700 directory on POSIX; the
    explicit ``chmod`` states the requirement rather than relying on it.
    Windows has no POSIX mode bits, so the call is POSIX-only.

    Both cleanups run in ``finally`` even when the body raised. A failure to
    delete the Keychain item or to remove the directory is reported on
    ``stderr`` and never replaces the body's own exception or hides the other
    cleanup.
    """
    config_dir = Path(tempfile.mkdtemp(prefix="cswap-login-"))
    try:
        if os.name != "nt":
            os.chmod(config_dir, 0o700)
        yield config_dir
    finally:
        _delete_profile_keychain(config_dir)
        try:
            shutil.rmtree(config_dir)
        except FileNotFoundError:
            pass
        except OSError:
            print(
                f"warning: could not remove the temporary login profile at "
                f"{config_dir}; check for leftover files.",
                file=sys.stderr,
            )


def login_environment(
    config_dir: Path,
    route: ProxyRoute | None,
    backup_dir: Path,
    bridge: "proxy_bridge.Bridge | None" = None,
) -> dict[str, str]:
    """The environment ``claude auth login`` runs with in the isolated profile.

    Built from the same pieces a ``cswap run`` launch uses, so the login
    exchange follows the account's proxy and the ``run`` settings instead of a
    second copy of those rules. ``bridge`` is that launch's local bridge when
    the account's scheme needs one.
    """
    run = load_run_settings(backup_dir)
    no_proxy = DEFAULT_NO_PROXY if route is None else run.no_proxy
    env = _probe_env(
        config_dir, route, no_proxy, run.disable_nonessential_traffic, bridge
    )
    env.pop("CLAUDE_SECURESTORAGE_CONFIG_DIR", None)
    return env


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
    try:
        # A scheme urllib cannot speak gets a bridge for the length of the
        # login: the child reads the loopback address, and the account's own
        # URL stays in this process.
        with account_bridge(route) as bridge:
            completed = spawn.run(
                argv, env=login_environment(config_dir, route, backup_dir, bridge)
            )
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

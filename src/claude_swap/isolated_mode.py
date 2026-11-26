"""The fork's one active account: the slot in ``sequence.json``, not the
global ``~/.claude`` login.

Upstream's active account *is* Claude Code's default login: a switch rewrites
``~/.claude/.credentials.json`` (or the default Keychain item) and
``oauthAccount`` in ``~/.claude.json``, and every "where is the user now" read
goes through those files. This fork never writes them. ``activeAccountNumber``
in ``sequence.json`` is the only record of the active slot, and
``cswap run --active`` — what the thin ``claude`` wrapper runs — starts that
slot in its own profile under ``sessions/<num>-<email>/`` with that slot's
proxy and egress rule.

The rules this module owns:

- **A switch changes ``activeAccountNumber`` and ``lastUpdated`` only.** No
  credential, config or Keychain write, so a switch cannot pull a login out
  from under a running Claude Code and cannot spend a slot's refresh token.
- **A global login is never the active account.** It is reported (the
  ``cswap list``/``status`` note and the additive ``globalLogin`` JSON field)
  and left alone, so a user who logged in with a bare ``claude`` sees why the
  wrapper ignores it and that ``cswap add`` imports it.
- **``cswap add`` takes the global login over.** Once the slot is saved, the
  global copy goes: the credential file or default Keychain item, and only the
  ``oauthAccount`` key of ``~/.claude.json``. One one-time refresh token must
  not exist twice. Shared files there (``settings.json``, ``CLAUDE.md``,
  ``skills/``, ``projects/``, ``mcpServers``, …) stay: every session profile
  links them from that same place. The cleanup is limited to the DEFAULT
  profile — an ``add`` from another profile (``CLAUDE_CONFIG_DIR``,
  ``CLAUDE_SECURESTORAGE_CONFIG_DIR``) skips it — and it removes a credential
  only when its fingerprint is the one just saved, because a copy Claude Code
  refreshed meanwhile is the only live one.
- **Fail closed.** A launch on the active slot refuses when no slot is
  recorded, when the slot is disabled, when it has no stored credential or
  config, when the same account's login still sits in the global ``~/.claude``
  (one ``cswap add`` clears it), or when the slot's proxy or exit check
  refuses. Nothing falls back to a plain ``claude`` on the global profile.

What users see is in [auto-launch.md](../../docs/auto-launch.md).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from claude_swap import oauth, paths
from claude_swap.claude_locks import claude_config_lock, claude_credentials_lock
from claude_swap.exceptions import (
    AccountNotFoundError,
    ConfigError,
    LockError,
    SwitchError,
)
from claude_swap.json_output import account_ref
from claude_swap.locking import FileLock
from claude_swap.models import Platform, get_timestamp
from claude_swap.printer import accent, dimmed, warning

if TYPE_CHECKING:  # pragma: no cover - the switcher imports this module
    from claude_swap.switcher import ClaudeAccountSwitcher

#: The one field a switch writes besides ``lastUpdated``.
ACTIVE_FIELD = "activeAccountNumber"


def active_slot(switcher: "ClaudeAccountSwitcher") -> str | None:
    """The recorded active slot, or None when there is none (or it is gone).

    Read from ``sequence.json`` alone — the live ``~/.claude`` login never
    decides it, which is the whole point of the fork: a user logged in with a
    bare ``claude`` is not "on" a managed account.
    """
    data = switcher._get_sequence_data() or {}
    recorded = data.get(ACTIVE_FIELD)
    if recorded is None:
        return None
    num = str(recorded)
    return num if num in (data.get("accounts") or {}) else None


def require_active_slot(switcher: "ClaudeAccountSwitcher") -> str:
    """The active slot, or a refusal a launcher can show as it stands.

    A launch that got here must not fall back to anything: no slot recorded is
    a refusal (``cswap switch <num>`` records one), a disabled slot is a
    refusal with ``cswap enable`` / ``cswap next`` as the remedy, and a slot
    that lost its stored credential or config since it was recorded is the same
    refusal with the remedy that fits it.

    A recorded slot whose account still has its login in the global
    ``~/.claude`` is also refused: after an upgrade from upstream's paradigm
    that login is the same one-time token the slot holds, or a newer
    generation of it, and a session would either be a second copy of one
    login or seed the profile with a token Claude Code already spent. One
    ``cswap add`` takes the global login over (the slot keeps its settings)
    and clears it.
    """
    num = active_slot(switcher)
    if num is None:
        raise ConfigError(
            "No active account is recorded (sequence.json has no "
            "activeAccountNumber). Pick one with: cswap switch <num|email>"
        )
    email = switcher.account_email(num)
    if switcher.is_account_disabled(num):
        raise ConfigError(
            f"Account-{num} ({email}) is the active account but is disabled. "
            f"Re-enable it with: cswap enable {num} — or pick another with: "
            "cswap next"
        )
    if not switcher._account_is_switchable(num):
        raise ConfigError(
            f"Account-{num} ({email}) is the active account but has no stored "
            f"credentials/config. Re-add it with: cswap add --slot {num}"
        )
    if _global_login_is_active_slot(switcher, num, email):
        raise ConfigError(
            f"The global ~/.claude holds the login of Account-{num} ({email}), "
            "so a session would be a second copy of the same one-time login. "
            "Run 'cswap add' once to take it over (the slot keeps its settings), "
            "then start claude again."
        )
    return num


def _global_login_is_active_slot(
    switcher: "ClaudeAccountSwitcher", num: str, email: str
) -> bool:
    """Whether ``~/.claude.json`` names this slot's account. No token read."""
    data = switcher._get_sequence_data() or {}
    record = data.get("accounts", {}).get(str(num)) or {}
    identity = switcher._get_current_identity_triple(
        paths.get_default_global_config_path()
    )
    if identity is None:
        return False
    return identity[0] == email and identity[1] == (
        record.get("organizationUuid", "") or ""
    )


def activate(
    switcher: "ClaudeAccountSwitcher", target: str, *, emit_output: bool = True
) -> dict:
    """Record ``target`` as the active slot. Returns ``_perform_switch``'s shape.

    ``{"from": ref|None, "to": ref, "warnings": []}`` — the same dict
    ``ClaudeAccountSwitcher._switch_result_from_op`` renders, so the switch
    callers and their ``--json`` payloads do not care which path produced it.

    Under ``FileLock(switcher.lock_file)`` and nothing else: the slot must
    exist, not be disabled, and still have a stored credential and a stored
    config (the two things a launch reads), and the only bytes written are the
    two fields of ``sequence.json``. Running sessions are untouched by
    construction — no file they read is opened for writing.

    A disabled slot is refused: disabling holds it away from a launch, and the
    user who named it is given the re-enable command instead.
    """
    target = str(target)
    switcher._refuse_session_shell()
    with FileLock(switcher.lock_file):
        data = switcher._get_sequence_data() or {}
        accounts = data.get("accounts") or {}
        record = accounts.get(target)
        if record is None:
            raise AccountNotFoundError(f"Account-{target} does not exist")
        email = record.get("email", "")
        if record.get("disabled"):
            raise SwitchError(
                f"Account-{target} ({email}) is disabled. Re-enable it with: "
                f"cswap enable {target} — or pick another with: cswap next"
            )
        previous = data.get(ACTIVE_FIELD)
        from_num = (
            str(previous)
            if previous is not None and str(previous) in accounts
            else None
        )
        from_ref = (
            account_ref(int(from_num), accounts[from_num].get("email", ""))
            if from_num is not None
            else None
        )
        to_ref = account_ref(int(target), email)
        if from_num != target:
            # The two things a launch will read, checked under the same lock
            # that records the slot: the credential (fresh, never the display
            # cache — a locked Keychain is "retry later", not "re-add") and the
            # stored config. Both errors name the remedy.
            switcher._read_target_credentials(target, email)
            if not switcher._read_account_config(target, email):
                raise SwitchError(
                    f"Account-{target} has no stored config backup. "
                    f"Re-add with: cswap --add-account --slot {target}"
                )
            data[ACTIVE_FIELD] = int(target)
            data["lastUpdated"] = get_timestamp()
            switcher._write_json(switcher.sequence_file, data)
            switcher._logger.info(
                f"Active account recorded as {target} (was {from_num})"
            )
    if emit_output and from_num != target:
        email = to_ref["email"]
        print(f"{accent('Switched to')} Account-{target} ({email})")
        print(dimmed(
            "The next `claude` launch runs this account in its own profile — "
            "already running sessions are untouched."
        ))
    if from_num != target:
        switcher._replan_new_active(
            target, to_ref["email"], record.get("organizationUuid", "") or ""
        )
    return {"from": from_ref, "to": to_ref, "warnings": []}


def global_login(switcher: "ClaudeAccountSwitcher") -> dict | None:
    """The login left in the global ``~/.claude``, or None when there is none.

    A read-only look at the DEFAULT profile (``CLAUDE_CONFIG_DIR`` does not
    decide it): an ``oauthAccount`` in ``~/.claude.json`` is the mark a login
    leaves there. Returned as ``{"email": ...}`` — the email is all the notice
    and the ``--json`` field carry, never any part of the credential.

    A credential file with no ``oauthAccount`` beside it is also a login, and
    exactly what a partially failed cleanup leaves behind; the email is then
    empty. One ``stat`` of the default profile's file answers it. The Keychain
    is not read, so an orphaned item there is not reported: reading it would
    turn every ``cswap list`` into a Keychain access.

    Nothing is written and nothing is adopted: this is the detector behind
    "you still have a login cswap does not manage". Importing it is an explicit
    ``cswap add``.
    """
    identity = switcher._get_current_identity_triple(
        paths.get_default_global_config_path()
    )
    if identity is not None:
        return {"email": identity[0]}
    cred_file = paths.get_default_claude_config_home() / ".credentials.json"
    try:
        if cred_file.is_file() and cred_file.stat().st_size > 0:
            return {"email": ""}
    except OSError:
        pass
    return None


def global_login_notice(switcher: "ClaudeAccountSwitcher") -> str | None:
    """One line for ``cswap list``/``status`` about that leftover login."""
    login = global_login(switcher)
    if login is None:
        return None
    email = login["email"] or "an account with no recorded email"
    return (
        f"Global ~/.claude holds a login for {email}. cswap neither uses it "
        "nor overwrites it: import it with `cswap add`, or remove it and keep "
        "the wrapper's login isolated."
    )


def _default_credential_state(switcher: "ClaudeAccountSwitcher") -> dict[str, Any]:
    """The DEFAULT profile's credential copies: ``file`` and ``keychain``.

    Paths are the default profile's own, not ``get_credentials_path()``: this
    is only called with no profile variable set (``clear_global_login`` skips
    otherwise), so the two agree, and naming them here makes the boundary
    visible. A copy is its text; ``keychain_failed`` separates "no item" from
    "could not ask" on macOS.
    """
    state: dict[str, Any] = {
        "file": None,
        "keychain": None,
        "keychain_failed": False,
    }
    cred_file = paths.get_default_claude_config_home() / ".credentials.json"
    try:
        if cred_file.exists():
            text = cred_file.read_text(encoding="utf-8")
            if text.strip():
                state["file"] = text
    except OSError as e:
        switcher._logger.warning(f"Could not read {cred_file}: {e}")
    if switcher.platform == Platform.MACOS:
        from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE

        value, failed = switcher._store._read_one_oauth_keychain(
            CLAUDE_CODE_KEYCHAIN_SERVICE
        )
        state["keychain"] = value or None
        state["keychain_failed"] = bool(failed)
    return state


def clear_global_login(
    switcher: "ClaudeAccountSwitcher", saved_credentials: str | None
) -> bool:
    """Drop the global login once its slot is saved. True when nothing is left.

    Called by ``add_account`` after the slot is committed, so the one-time
    ``refresh_token`` does not exist in two places (cswap's backup and Claude
    Code's default login) where either could spend it first. Removes:

    - the credential from the DEFAULT profile — ``.credentials.json`` and, on
      macOS, the default Keychain item — but only when its fingerprint is the
      one just saved in ``saved_credentials``. A copy whose fingerprint differs
      was refreshed by a running Claude Code after the add read it, and is then
      the only live generation of that login: it is left in place, with a
      warning, instead of being spent from both sides;
    - the ``oauthAccount`` key of ``~/.claude.json``, under Claude Code's own
      config lock.

    The cleanup is a DEFAULT-profile operation. With ``CLAUDE_CONFIG_DIR`` or
    ``CLAUDE_SECURESTORAGE_CONFIG_DIR`` set, ``add_account`` imported from
    another profile, so there is no ``~/.claude`` of its own to clean: the call
    says so in one line and does nothing.

    Returns False when a global copy is still there (unreadable, unremovable,
    refreshed, or skipped as another profile). The reason is already on screen
    at that point — the caller has nothing further to say, and the add itself
    has succeeded either way.
    Nothing else in ``~/.claude`` is touched: ``settings.json``, ``CLAUDE.md``,
    ``skills/``, ``projects/``, ``mcpServers`` and the rest are the single
    shared source every session profile links from there.
    """
    if os.environ.get("CLAUDE_CONFIG_DIR") or os.environ.get(
        "CLAUDE_SECURESTORAGE_CONFIG_DIR"
    ):
        print(dimmed(
            "Skipped clearing the global ~/.claude login: cswap is running in "
            "another profile (CLAUDE_CONFIG_DIR or "
            "CLAUDE_SECURESTORAGE_CONFIG_DIR is set)."
        ))
        return False

    expected = (
        oauth.credential_fingerprint(saved_credentials)
        if saved_credentials
        else None
    )
    state: dict[str, Any] = {}
    try:
        with claude_credentials_lock():
            state = _default_credential_state(switcher)
            live = [text for text in (state["file"], state["keychain"]) if text]
            if live and (
                expected is None
                or any(
                    oauth.credential_fingerprint(text) != expected
                    for text in live
                )
            ):
                warning(
                    "The global ~/.claude login has changed since this account "
                    "was read, so it is the only live copy of that token. "
                    "Leaving it in place: run 'cswap add' again when no Claude "
                    "Code is running."
                )
                return False
            if live:
                switcher._store._clear_oauth_credential()
                state = _default_credential_state(switcher)
    except LockError as e:
        warning(f"Could not take Claude Code's credential lock: {e}")
        return False

    if state.get("file") or state.get("keychain"):
        warning(
            "The global ~/.claude login is still there: it could not be "
            "removed. Remove it by hand, or run 'cswap add' again, before "
            "starting claude outside the wrapper."
        )
        return False

    config_path = paths.get_default_global_config_path()

    def drop_oauth_account(config: dict) -> None:
        config.pop("oauthAccount", None)

    try:
        with claude_config_lock():
            if config_path.exists():
                switcher._store._update_global_config(drop_oauth_account)
    except LockError as e:
        switcher._logger.warning(
            f"Could not remove the global oauthAccount from {config_path}: {e}"
        )
        return False
    except Exception as e:
        switcher._logger.warning(
            f"Could not remove the global oauthAccount from {config_path}: {e}"
        )
        return False
    return True


def report_global_login(switcher: "ClaudeAccountSwitcher") -> None:
    """Print the leftover-global-login note, if there is one."""
    notice = global_login_notice(switcher)
    if notice:
        warning(notice)

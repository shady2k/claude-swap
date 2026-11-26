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
  links them from that same place.
- **Fail closed.** A launch on the active slot refuses when no slot is
  recorded, when the slot has no stored credential or config, or when the
  slot's proxy or exit check refuses. Nothing falls back to a plain ``claude``
  on the global profile.

What users see is in [auto-launch.md](../../docs/auto-launch.md).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from claude_swap import paths
from claude_swap.claude_locks import claude_config_lock
from claude_swap.exceptions import (
    AccountNotFoundError,
    ConfigError,
    LockError,
    SwitchError,
)
from claude_swap.json_output import account_ref
from claude_swap.locking import FileLock
from claude_swap.models import get_timestamp
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
    a refusal (``cswap switch <num>`` records one), and a slot that lost its
    stored credential or config since it was recorded is the same refusal with
    the remedy that fits it.
    """
    num = active_slot(switcher)
    if num is None:
        raise ConfigError(
            "No active account is recorded (sequence.json has no "
            "activeAccountNumber). Pick one with: cswap switch <num|email>"
        )
    if not switcher._account_is_switchable(num):
        email = switcher.account_email(num)
        raise ConfigError(
            f"Account-{num} ({email}) is the active account but has no stored "
            f"credentials/config. Re-add it with: cswap add --slot {num}"
        )
    return num


def activate(
    switcher: "ClaudeAccountSwitcher", target: str, *, emit_output: bool = True
) -> dict:
    """Record ``target`` as the active slot. Returns ``_perform_switch``'s shape.

    ``{"from": ref|None, "to": ref, "warnings": []}`` — the same dict
    ``ClaudeAccountSwitcher._switch_result_from_op`` renders, so the switch
    callers and their ``--json`` payloads do not care which path produced it.

    Under ``FileLock(switcher.lock_file)`` and nothing else: the slot must
    exist and still have a stored credential and a stored config (the two
    things a launch reads), and the only bytes written are the two fields of
    ``sequence.json``. Running sessions are untouched by construction — no
    file they read is opened for writing.

    An explicit transition to a disabled slot is allowed: disabling holds a
    slot out of automatic rotation, not away from a user who named it.
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

    Nothing is written and nothing is adopted: this is the detector behind
    "you still have a login cswap does not manage". Importing it is an explicit
    ``cswap add``.
    """
    identity = switcher._get_current_identity_triple(
        paths.get_default_global_config_path()
    )
    if identity is None:
        return None
    return {"email": identity[0]}


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


def clear_global_login(switcher: "ClaudeAccountSwitcher") -> bool:
    """Drop the global login once its slot is saved. True when nothing is left.

    Called by ``add_account`` after the slot is committed, so the one-time
    ``refresh_token`` does not exist in two places (cswap's backup and
    Claude Code's default login) where either could spend it first. Removes:

    - the default profile's credential — ``.credentials.json``, and on macOS
      the default Keychain item (``CredentialStore._clear_oauth_credential``,
      best-effort on a Keychain that refuses);
    - the ``oauthAccount`` key of ``~/.claude.json``, under Claude Code's own
      config lock.

    Nothing else in ``~/.claude`` is touched: ``settings.json``, ``CLAUDE.md``,
    ``skills/``, ``projects/``, ``mcpServers`` and the rest are the single
    shared source every session profile links from there.
    """
    switched = False
    try:
        switcher._store._clear_oauth_credential()
        switched = True
    except Exception as e:  # best-effort, like the store's own delete
        switcher._logger.warning(f"Could not clear the global credential: {e}")

    config_path = paths.get_default_global_config_path()

    def drop_oauth_account(config: dict) -> None:
        config.pop("oauthAccount", None)

    try:
        with claude_config_lock():
            if config_path.exists():
                switcher._store._update_global_config(drop_oauth_account)
    except (LockError, Exception) as e:  # noqa: B014 - LockError first for the log
        switcher._logger.warning(
            f"Could not remove the global oauthAccount from {config_path}: {e}"
        )
        return False
    return switched


def report_global_login(switcher: "ClaudeAccountSwitcher") -> None:
    """Print the leftover-global-login note, if there is one."""
    notice = global_login_notice(switcher)
    if notice:
        warning(notice)

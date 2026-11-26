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
    if not login["email"]:
        # Only the credential file is there, so there is no account for
        # `cswap add` to import (it reads the identity from `~/.claude.json`)
        # and it would refuse: the file is the step that has to be undone.
        return (
            "Global ~/.claude holds a credential file with no account beside "
            "it. cswap neither uses it nor overwrites it: remove "
            "~/.claude/.credentials.json by hand, or log in again and run "
            "`cswap add`, so the wrapper's login stays isolated."
        )
    return (
        f"Global ~/.claude holds a login for {login['email']}. cswap neither "
        "uses it nor overwrites it: import it with `cswap add`, or remove it "
        "and keep the wrapper's login isolated."
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


_KEYCHAIN_UNREADABLE = (
    "Could not read the macOS Keychain, so cswap cannot tell whether the "
    "global ~/.claude login is gone. Nothing more was removed: remove the "
    "login by hand, or run 'cswap add' again once the Keychain answers."
)


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
    refreshed, or skipped as another profile). A Keychain that could not be
    read is one of those: "could not ask" is not "no item", so the cleanup
    stops instead of deleting a login it cannot see. The reason is already on
    screen at that point — the caller has nothing further to say, and the add
    itself has succeeded either way.
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
            if state["keychain_failed"]:
                # The item may be the live login of another generation, and
                # deleting it blind could be the only copy left.
                warning(_KEYCHAIN_UNREADABLE)
                return False
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

    if state.get("keychain_failed"):
        warning(_KEYCHAIN_UNREADABLE)
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
    except Exception as e:
        switcher._logger.warning(
            f"Could not remove the global oauthAccount from {config_path}: {e}"
        )
        warning(
            f"Could not remove the 'oauthAccount' key from {config_path} "
            f"({e}). The account is saved, but cswap still sees this login as "
            "a global one: delete the 'oauthAccount' key from ~/.claude.json "
            "by hand."
        )
        return False
    return True


def report_global_login(switcher: "ClaudeAccountSwitcher") -> None:
    """Print the leftover-global-login note, if there is one."""
    notice = global_login_notice(switcher)
    if notice:
        warning(notice)

def _suitable_slot_numbers(
    switcher: "ClaudeAccountSwitcher", data: dict, active_key: str
) -> list[str]:
    """Slot numbers in rotation that could take over as active.

    Everything the launch would refuse is out: a missing record, a disabled
    slot, an API-key account (a launch refuses one), a slot without stored
    credentials or without a stored config. Order is the rotation order of
    ``sequence`` — the order a fallback pick walks.
    """
    accounts = data.get("accounts") or {}
    suitable: list[str] = []
    for num in data.get("sequence") or []:
        key = str(num)
        if key == active_key or key not in accounts:
            continue
        record = accounts[key]
        if record.get("disabled") or record.get("kind") == "api_key":
            continue
        email = record.get("email", "")
        if not switcher._account_is_switchable(key):
            continue
        suitable.append(key)
    return suitable


def _slot_is_marked(
    marks: dict[tuple[str, str], float],
    entry,
    email: str,
    org_uuid: str,
) -> bool:
    """Whether this slot carries a stop-failure mark newer than its reading.

    A ``UsageEntry`` is always what comes back from the store, so no type
    dispatch is needed: the mark is the only evidence for a slot without a
    reading (``fetched_at`` None), and a reading at or after the stamp clears
    it.
    """
    at = marks.get((email, org_uuid or ""))
    if at is None:
        return False
    return entry is None or entry.fetched_at is None or entry.fetched_at < at


def switch_active_after_rate_limit(
    switcher: "ClaudeAccountSwitcher", email: str, org_uuid: str
) -> bool:
    """Move the recorded active slot off an account Claude Code refused.

    Called by ``ClaudeAccountSwitcher.record_stop_failure`` after the stop
    mark is written (the ``cswap rate-limited`` hook target). Decides under
    ``FileLock(switcher.lock_file)`` and re-reads ``sequence.json`` inside
    that lock, so a ``cswap switch``, ``cswap next`` or another session that
    already moved the active slot wins: nothing changes unless the refused
    account is still the recorded ``activeAccountNumber``.

    The pick reads only the usage store's already-cached readings
    (``_usage_store.entries`` with an empty fetch set — never a network
    request) and the stop marks, so a refusal during a plain launch costs no
    quota pass. Disabled slots, API-key accounts, slots without stored
    credentials or config, and slots whose cached reading is trusted at or
    below zero headroom are never picked:

    - prefer an unmarked slot with cached headroom above zero — the most
      headroom wins, ties in rotation order;
    - when no other slot has a usable cached reading (no ``cswap auto`` pass
      has run, for instance), take the next unmarked suitable slot in
      rotation order after the current active one, so the goal works without
      a running ``cswap auto``;
    - when every other suitable slot is marked (its reading predates a
      ``StopFailure`` report, so its headroom is stale evidence), the marked
      slot with the oldest report takes over — ties in rotation order — so a
      refusal never pins the active slot on the refused account;
    - when no other suitable slot exists at all (one account, or everything
      else is disabled / an API key / without credentials / exhausted) the
      recorded ``activeAccountNumber`` is left as is.

    A marked slot's reading is never trusted (it predates the refusal), so a
    marked slot is decided by its report's age, not its stale headroom.

    After the lock is released, ``_replan_new_active`` pulls the new active
    slot's poll plan to the active floor — so ``cswap auto`` does not wait up
    to ``CANDIDATE_MAX_INTERVAL_S`` to poll the account that just took over.

    Writes only ``activeAccountNumber`` and ``lastUpdated`` into
    ``sequence.json`` — never ``~/.claude``, never the Keychain — and prints
    nothing: the hook's output is not the user's.

    Returns ``True`` when the recorded active slot changed.
    """
    org_uuid = org_uuid or ""
    target = None
    target_email = None
    target_org = None
    try:
        with FileLock(switcher.lock_file):
            target, target_email, target_org = _switch_active_after_rate_limit_locked(
                switcher, email, org_uuid
            )
    except (LockError, OSError):
        # A hook must never fail the report it carries; a missed move is
        # repaired by the next launch's own ranking or a `cswap list` pass.
        switcher._logger.warning(
            f"Could not move the active slot off {email} after a rate-limit "
            "stop: the account lock was unavailable"
        )
        return False
    if target is not None:
        switcher._replan_new_active(target, target_email, target_org)
    return target is not None


def _switch_active_after_rate_limit_locked(
    switcher: "ClaudeAccountSwitcher", email: str, org_uuid: str
) -> tuple[str | None, str | None, str | None]:
    data = switcher._get_sequence_data() or {}
    accounts = data.get("accounts") or {}
    sequence = [str(num) for num in data.get("sequence") or []]
    active_num = data.get("activeAccountNumber")
    active_key = str(active_num) if active_num is not None else None
    record = accounts.get(active_key) if active_key is not None else None
    if record is None:
        return None, None, None
    active_org = record.get("organizationUuid", "") or ""
    if (record.get("email", ""), active_org) != (email, org_uuid):
        # `cswap auto` / `cswap next` / another session already moved it.
        return None, None, None

    from claude_swap import oauth
    from claude_swap.settings import load_settings, parse_model_names

    settings = load_settings(switcher.backup_dir)
    models = parse_model_names(settings.model)
    marks = switcher._stop_failure_marks()
    candidates = _suitable_slot_numbers(switcher, data, active_key)
    if not candidates:
        return None, None, None

    identities = {
        key: (accounts[key].get("email", ""), accounts[key].get("organizationUuid", "") or "")
        for key in candidates
    }
    entries: dict = switcher._usage_store.entries(identities, models)
    position = {key: index for index, key in enumerate(sequence) if key in candidates}

    def mark_at(key: str) -> float:
        e_email, e_org = identities[key]
        return marks.get((e_email, e_org or ""), 0.0)

    def classify(key: str) -> tuple[bool, float | None]:
        entry = entries.get(key)
        e_email, e_org = identities[key]
        if _slot_is_marked(marks, entry, e_email, e_org):
            return True, None
        room = oauth.account_headroom(entry.decision_value(), models)
        return False, room

    classified = {key: classify(key) for key in candidates}
    preferred = [
        key
        for key in candidates
        if not classified[key][0]
        and classified[key][1] is not None
        and classified[key][1] > 0
    ]
    target = None
    if preferred:
        target = max(
            preferred,
            key=lambda key: (classified[key][1], -position.get(key, 0)),
        )
    else:
        suitable = {
            key
            for key in candidates
            if not classified[key][0]
            and (classified[key][1] is None or classified[key][1] > 0)
        }
        if suitable:
            start = sequence.index(active_key) if active_key in sequence else -1
            for key in sequence[start + 1:] + sequence[:start]:
                if key in suitable:
                    target = key
                    break
        else:
            # Every other suitable slot is marked (its reading predates the
            # refusal, so its headroom is stale evidence): the slot whose
            # StopFailure report is the oldest is the least stale — ties in
            # rotation order. Headroom<=0 slots are skipped above on trusted
            # readings; a marked slot's reading is never trusted.
            marked = [key for key in candidates if classified[key][0]]
            if marked:
                target = min(
                    marked,
                    key=lambda key: (mark_at(key), position.get(key, 0)),
                )
    if target is None or target == active_key:
        return None, None, None
    previous = data.get(ACTIVE_FIELD)
    data[ACTIVE_FIELD] = int(target)
    data["lastUpdated"] = get_timestamp()
    switcher._write_json(switcher.sequence_file, data)
    switcher._logger.info(
        f"Active slot moved off {email} by the rate-limit hook to "
        f"Account-{target}"
        + (f" (was {previous})" if previous is not None else "")
    )
    target_record = accounts[target]
    return target, target_record.get("email", ""), target_record.get("organizationUuid", "") or ""

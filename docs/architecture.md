# Architecture: where things live and how they fit

For contributors and their coding agents. This page is a map: which module owns what, how the few flows that cross modules run, and the rules that hold across the codebase. It names files and functions instead of linking to lines, so search for the name.

Each topic has one home. What users see is in the [README](../README.md) and the other pages in this folder. How a mechanism works, with its numbers and edge cases, is in the docstring of the module that owns it. This page only connects them, so it should change rarely.

## What the tool does

claude-swap keeps a backup of each Claude Code login in a numbered slot: the credential, and the `oauthAccount` section of `.claude.json`. Switching makes one slot the live login by writing it where Claude Code reads it. Usage display, auto-switch, session mode and the menu bar are all built on that.

It works on the same files and Keychain items Claude Code uses, and takes Claude Code's own locks while it does.

## Modules

**Surfaces.** They parse input and render output, and hold no account logic.

- `cli.py`: argument parsing and one function per command. `printer.py` styles the output; `json_output.py` owns the shapes of `--json` for list, status and switch.
- `tui/`: the Textual dashboard. Blocking work runs in thread workers, never on the UI loop.
- `menubar.py`: the macOS menu bar shell. `launch_agent.py` runs it under launchd and `app_bundle.py` gives it a bundle identifier.

**Core.**

- `switcher.py`: `ClaudeAccountSwitcher`. Slots, add, remove, switch, swap, move, usage collection and the token refresh gate. See the map below.
- `autoswitch.py`: `AutoSwitchEngine`. Decides when to switch and reports through typed events; it never prints. `lines.py` holds the per-window switch lines.
- `session.py`: `SessionManager`, behind `cswap run`. `mappings.py` maps a directory to an account.
- `usage_store.py`: `UsageStore`, the per-account usage table. `poll_policy.py` holds every polling number. `snapshot_source.py` is the read path for dashboards.
- `oauth.py`: the token, usage and profile endpoints, the header probe, and the formatting of reset times. `subscription.py` reads the plan label; `pace.py` computes the weekly pace marker.
- `transfer.py`: export and import. `settings.py`: `settings.json`. `migrations.py`: one-time data migrations. `update_check.py`: the PyPI version check.

**Storage and platform.** Leaf modules that the core calls.

- `credentials.py`: `CredentialStore`, which decides Keychain or file and reads and writes both. `macos_keychain.py` wraps the `security` tool.
- `paths.py`: resolves Claude Code's config and credential paths the way Claude Code does, and the backup root.
- `claude_locks.py`: Claude Code's lock protocol. `locking.py`: cswap's own `FileLock`.
- `process_detection.py`: finds running Claude Code instances. `spawn.py`: owns subprocess creation and terminal handoff.
- `transparent.py`: installs the PATH shim and applies launch policy without running CLI migrations. `launch_policy.py` owns the shared-history consent and recipient pool. `claude_forms.py` classifies arguments. `real_claude.py` resolves the original Claude Code for the shim and session launches, including auth probes. `fsguard.py` and `python_chain.py` check the executable chains.
- `fsutil.py`: atomic writes and link helpers. It imports nothing from the package.

## Finding things in `switcher.py`

It is one class of about 8,000 lines. The methods sit in roughly this order:

| Looking for | Search for |
|---|---|
| Slot lookup, aliases, reordering | `resolve_account`, `set_alias`, `swap_accounts`, `move_account` |
| Per-account threshold, priority, disable | `set_account_threshold`, `set_account_priority`, `set_account_disabled` |
| Refreshing a stored token | `consume_backup_grant` |
| Adding and removing accounts | `add_account`, `add_account_from_token`, `remove_account` |
| Fetching usage | `_fetch_active_usage`, `_fetch_account_usage`, `_collect_usage_entries` |
| What dashboards read | `accounts_snapshot` |
| `cswap list` and `cswap status` | `list_accounts`, `status` |
| Switching | `switch`, `switch_to`, `_classify_outgoing_credential`, `_perform_switch` |

## State on disk

Everything lives under the backup root (its location per platform is in the [README](../README.md#data-locations)).

| Path | Owner | Holds |
|---|---|---|
| `sequence.json` | `switcher.py` | The slots, each slot's identity, alias and policy, and which slot is active |
| `configs/`, `credentials/` (Keychain on macOS) | `switcher.py` through `CredentialStore` | Each slot's backed-up config and credential |
| `cache/usage.json` | `usage_store.py` | Last good usage reading and fetch state per account |
| `settings.json` | `settings.py` | User preferences |
| `autoswitch_state.json` | `autoswitch.py` | Cooldown and quarantined accounts |
| `mappings.json` | `mappings.py` | Directory to account |
| `sessions/<num>-<email>/` | `session.py` | One Claude Code profile per account |
| `profile-ownership/` | `profile_ownership.py` | External launch reservations and profile generations; never removed with a profile |

## Flows that cross modules

### Usage collection

Every surface gets usage from one function, `_collect_usage_entries` in `switcher.py`. `cswap list`, `cswap status` and the usage-aware switch strategies call it on demand. The TUI and the menu bar reach it through `SnapshotSource.take`. The auto engine calls it on its own schedule from `_collect_scheduled_usage`.

A caller only nominates accounts. Whether a request is actually sent is decided in one place, `UsageStore.reserve`, which checks freshness, backoff, another process's claim and the stored poll plan under the store lock, then hands out a lease. This is why a dashboard that repaints every few seconds sends no more requests than one `cswap list`.

The fetch runs with no store lock held. `UsageStore.record` then merges the result: a success replaces the last good reading and stores the next poll time from `poll_policy.py`; a failure only updates the backoff fields, so the last good reading keeps being shown.

Read next: the module docstrings of `usage_store.py`, `poll_policy.py` and `snapshot_source.py`.

### A switch

`switch` picks a target and `switch_to` is given one; both end in `_perform_switch`. It takes three locks in a fixed order: cswap's own lock, Claude Code's credential lock, Claude Code's config lock. Under them it:

1. backs up the outgoing login into its slot, after `_classify_outgoing_credential` decides whether the live credential really belongs to that slot;
2. reads the target slot's backup;
3. writes the target credential to the live store;
4. replaces `oauthAccount` in the live `.claude.json`, leaving the rest of the file alone;
5. records the new active slot in `sequence.json`.

A failure rolls the earlier steps back. Everything under the locks is local I/O; the identity lookup that step 1 needs is fetched before the locks are taken.

Read next: the module docstring of `claude_locks.py`, and the docstring of `_classify_outgoing_credential`.

### Token refresh

A refresh token works once: after it is used, only its successor is valid. Refreshing a stored credential therefore goes through one gate, `consume_backup_grant`, which serializes refreshes per slot, re-reads the freshest copy before it posts, and always persists or stashes the successor. The auto engine uses it before activating a target, and session mode before seeding a profile.

Both refresh paths share an identity-scoped OS consume lock in `refresh_authority.py`. Credential snapshots bind bytes to the slot identity and `loginGen` under the account lock. Replacement logins advance `loginGen`; rotation and stash adoption preserve it. Mutations probe the right without waiting under the account lock and refuse while refresh is in flight. Explicit session launches wait for the right before taking the account lock, then reserve the profile while holding both.

The backup gate posts outside the account lock and holds its right through CAS or stash. Active recovery in `_fetch_active_usage` re-reads both stores under the account and Claude credential locks. Its bounded POST is the sole network-under-account-lock exception, needed to serialize with Claude's default-store rotation. Both paths persist without taking ownership state under the account lock, then invalidate profiles after releasing the refresh right.

Read next: the docstrings of `consume_backup_grant` and `_fetch_active_usage`.

### Session mode

`cswap run` calls `SessionManager.run`. `setup_session` creates or reuses the account's profile directory, seeds it with the slot's credential, and links the user's settings and history from `~/.claude` into it. Claude Code is then started with `CLAUDE_CONFIG_DIR` pointing at the profile, which leaves the default login untouched. Both session and routed transparent launches exclude the default-login account at reservation and publication, then publish through `profile_ownership.mark_running_locked` under ownership state → account locks. Multiple reservations can prepare one profile; running readers forbid profile overwrite or deletion, while generation changes invalidate competing preparations. On admitted Linux launches, `spawn.owned_launch` protects signals from before publication through cleanup, probes supervision support, and waits for all descendants before `profile_ownership.release_completed` retries ownership-lock contention and releases only that launch record. A supervisor failure leaves completion unconfirmed. A trustworthy same-machine boot ID change also proves completion of an old tree.

If an ordinary OAuth slot is already the active default login, it starts plain `claude` instead, because two copies of one refresh grant drift apart. A setup-token slot has no refresh grant and is not excluded by matching the default-login identity.

Read next: the module docstring of `session.py`.

### Transparent launch

The PATH shim checks the shared-history policy, prepares a candidate without holding the account lock, then confirms the current policy and recipient under the account lock before recording the launch. Network and process handoff are outside that lock. See [the PATH shim reference](transparent.md) for consent and revocation.

### Auto-switch

`AutoSwitchEngine.tick` collects usage, ranks the candidates (`_rank_candidates`), freshens the chosen target's token (`_freshen_target`) and calls `switcher.switch_to`. `cswap auto`, the TUI's auto screen and the menu bar all run this same engine and render its events. Cooldown and quarantine are kept in `autoswitch_state.json` under their own lock, so a cron-driven `--once` and a long-running loop agree.

Read next: the module docstring of `autoswitch.py`. The rules as users see them are in [auto-switch.md](auto-switch.md).

## Rules that hold everywhere

- **Lock order.** Profile ownership state lock → identity-scoped refresh consume right → `switcher.lock_file` → Claude Code's credential lock → its config lock → stash manifest lock. Ownership checks at mutation and publication require state before cswap. Never wait for a consume right under `switcher.lock_file`; account-locked callers may only probe it without waiting. Stash snapshots hold the manifest lock only for the manifest and directory read, never across adoption.
- **No network under ownership locks.** A switch does only local I/O under its locks, and the usage store never holds its lock across a fetch. Backup-token refresh posts outside the ownership and account locks. Only active recovery holds account and Claude credential locks across a bounded POST to serialize default-store rotation with Claude. Both paths hold the same identity-scoped consume right through persistence or stash; account-locked callers may only probe that right without waiting.
- **A used refresh token's successor is never dropped.** Once the refresh is posted, the new credential is persisted or stashed, whatever else fails.
- **A live credential enters a slot only when it is known to belong there.** Writing another account's credential into a slot destroys that slot's only refresh token.
- **The usage store persists readings and fetch state only.** Labels such as "token expired" are derived on every pass and never written.
- **Polling numbers live in `poll_policy.py` only.**
- **Collection and the engine tick never raise.** A failure becomes a state or an event.
- **Surfaces hold no account logic.** Dashboards read through `SnapshotSource`; the engine does not print.
- **Import direction.** `session.py` and `credentials.py` do not import `switcher.py`. `fsutil.py` imports nothing from the package. The TUI's heavy imports stay inside `tui.run`.
- **Paths come from `paths.py`.** Do not hardcode `~/.claude`; Claude Code's own resolution has cases that differ.

## Tests

`uv sync`, then `uv run pytest`. CI runs the same on Linux, macOS and Windows. Tests are mostly one file per module, `tests/test_<module>.py`.

Tests cannot write the real account store: `tests/conftest.py` installs a process-wide guard that refuses any write under the real data paths, on top of the per-test temporary home.

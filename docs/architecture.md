# Architecture: where things live and how they fit

For contributors and their coding agents. This page is a map: which module owns what, how the few flows that cross modules run, and the rules that hold across the codebase. It names files and functions instead of linking to lines, so search for the name.

Each topic has one home. What users see is in the [README](../README.md) and the other pages in this folder. How a mechanism works, with its numbers and edge cases, is in the docstring of the module that owns it. This page only connects them, so it should change rarely.

## What the tool does

claude-swap keeps a backup of each Claude Code login in a numbered slot: the credential, and the `oauthAccount` section of `.claude.json`. This fork's active account is a field of its own state — `sequence.json`'s `activeAccountNumber` (`isolated_mode.py`) — and a switch writes that field and nothing else. A launch starts that slot in its own session profile; the global `~/.claude` login is read (by `cswap add`, and to report a leftover login) but never written and never active. Usage display, auto-switch, session mode and the menu bar are all built on that.

It works on the same files and Keychain items Claude Code uses, and takes Claude Code's own locks only where it writes them — the switch path does not.

## Modules

**Surfaces.** They parse input and render output, and hold no account logic.

- `cli.py`: argument parsing and one function per command. `printer.py` styles the output; `json_output.py` owns the shapes of `--json` for list, status and switch.
- `tui/`: the Textual dashboard. Blocking work runs in thread workers, never on the UI loop.
- `menubar.py`: the macOS menu bar shell. `launch_agent.py` runs it under launchd and `app_bundle.py` gives it a bundle identifier.

**Core.**

- `switcher.py`: `ClaudeAccountSwitcher`. Slots, add, remove, switch, swap, move, usage collection and the token refresh gate. See the map below.
- `isolated_mode.py`: the active slot (`activeAccountNumber`), the switch that only records it, the read-only detector of a leftover global login, and the clearing of that login when `cswap add` commit its slot.
- `autoswitch.py`: `AutoSwitchEngine`. Decides when to switch and reports through typed events; it never prints. `lines.py` holds the per-window switch lines.
- `session.py`: `SessionManager`, behind `cswap run`. `mappings.py` maps a directory to an account.
- `login.py`: the isolated `claude auth login` profile behind `cswap add --login`: a temporary `CLAUDE_CONFIG_DIR`, its cleanup, and reading the credential and identity Claude Code leaves there.
- `usage_store.py`: `UsageStore`, the per-account usage table. `poll_policy.py` holds every polling number. `snapshot_source.py` is the read path for dashboards.
- `oauth.py`: the token, usage and profile endpoints, the header probe, and the formatting of reset times. `subscription.py` reads the plan label; `pace.py` computes the weekly pace marker.
- `account_proxy.py`: an account's proxy, and the pinned route its requests take. Every network call in `oauth.py` and `subscription.py` goes through it.
- `egress.py`: an account's expected exit country/IP, its storage rules, and the pre-launch check of them through the account's own route.
- `proxy_bridge.py`: the local HTTP proxy that carries a route urllib cannot speak (`https://`, `socks5h://`/`socks5://`) to the account's real proxy. It imports nothing from the package; `account_proxy` uses it through `ProxyRoute.open`/`probe` and `bridge`.
- `wrapper.py`: the thin `claude` script (`scripts/claude`) and the rule that keeps cswap and the wrapper from launching each other.
- `transfer.py`: export and import. `settings.py`: `settings.json`. `migrations.py`: one-time data migrations. `update_check.py`: the PyPI version check.

**Storage and platform.** Leaf modules that the core calls.

- `credentials.py`: `CredentialStore`, which decides Keychain or file and reads and writes both. `macos_keychain.py` wraps the `security` tool.
- `paths.py`: resolves Claude Code's config and credential paths the way Claude Code does, and the backup root.
- `claude_locks.py`: Claude Code's lock protocol. `locking.py`: cswap's own `FileLock`.
- `process_detection.py`: finds running Claude Code instances. `spawn.py`: runs helper processes without `fork()`.
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
| `sequence.json` | `switcher.py` | The slots, each slot's identity, alias and policy, and which slot is active (`isolated_mode.py` writes that field) |
| `configs/`, `credentials/` (Keychain on macOS) | `switcher.py` through `CredentialStore` | Each slot's backed-up config and credential |
| `cache/usage.json` | `usage_store.py` | Last good usage reading and fetch state per account |
| `settings.json` | `settings.py` | User preferences |
| `autoswitch_state.json` | `autoswitch.py` | Cooldown and quarantined accounts |
| `mappings.json` | `mappings.py` | Directory to account |
| `sessions/<num>-<email>/` | `session.py` | One Claude Code profile per account |

## Flows that cross modules

### Usage collection

Every surface gets usage from one function, `_collect_usage_entries` in `switcher.py`. `cswap list`, `cswap status` and the usage-aware switch strategies call it on demand. The TUI and the menu bar reach it through `SnapshotSource.take`. The auto engine calls it on its own schedule from `_collect_scheduled_usage`.

A caller only nominates accounts. Whether a request is actually sent is decided in one place, `UsageStore.reserve`, which checks freshness, backoff, another process's claim and the stored poll plan under the store lock, then hands out a lease. This is why a dashboard that repaints every few seconds sends no more requests than one `cswap list`.

The fetch runs with no store lock held. `UsageStore.record` then merges the result: a success replaces the last good reading and stores the next poll time from `poll_policy.py`; a failure only updates the backoff fields, so the last good reading keeps being shown.

The collector's pass that sends no request and every display row resolve "which credential generation is this account now" through `switcher._current_credential` (a newer session profile, else the backup). A display consults it only when the stored copy itself is due, so a repaint does not read every profile.

Read next: the module docstrings of `usage_store.py`, `poll_policy.py` and `snapshot_source.py`.

### A switch

`switch` picks a target and `switch_to` is given one; both end in
`isolated_mode.activate`. Under cswap's account lock it checks that the slot
exists and still holds a stored credential and config (fresh reads, so a locked
Keychain is "retry later", not "re-add"), then writes `activeAccountNumber` and
`lastUpdated` into `sequence.json`. No credential, config or Keychain write and
no Claude Code lock, so a running Claude Code cannot be disturbed or blocked and
no slot's one-time refresh token is spent.

Upstream's live-login switch (`_perform_switch`, its transaction and the
outgoing-credential classifier) is still in `switcher.py` and is unreachable from
the fork's commands; it is kept verbatim to keep rebases against upstream cheap.

Read next: the module docstring of `isolated_mode.py`.

### Token refresh

A refresh token works once: after it is used, only its successor is valid. Refreshing a stored credential therefore goes through one gate, `consume_backup_grant`, which serializes refreshes per slot, re-reads the freshest copy before it posts, and always persists or stashes the successor. The auto engine uses it before activating a target, and session mode before seeding a profile.

The active account is the one exception. Its expired token is refreshed in `_fetch_active_usage`, inside Claude Code's own credential lock, so a running Claude Code adopts the new token instead of colliding with it.

Read next: the docstrings of `consume_backup_grant` and `_fetch_active_usage`.

### Session mode

`cswap run` calls `SessionManager.run`. `setup_session` creates or reuses the account's profile directory, seeds it with the slot's credential, and links the user's settings and history from `~/.claude` into it. Claude Code is then started with `CLAUDE_CONFIG_DIR` pointing at the profile, which leaves the default login untouched.

Every launch is a session profile: `cswap run --active` (what the `claude`
wrapper runs) starts the recorded slot, `cswap run` with nothing mapped does the
same, and an account that happens to be the global login is launched in its
profile too. Nothing launches on `~/.claude`, and nothing falls back to it.

A launch of an account with a proxy reads the route and the egress rule from ONE record, refuses before any Claude Code process (the `claude auth status` probe included) when one `CONNECT` through it fails, and hands Claude Code that proxy in its environment. When the route's scheme is `https://` or `socks5h://`/`socks5://` that environment names a local `proxy_bridge` (opened for the launch, closed in `finally`) instead of the account's URL, so the launch runs Claude Code as a child rather than `exec`-ing it; the `auth status` probe reads its own short-lived bridge the same way. An account with an egress expectation is refused the same way when the exit does not match it, measured through that route before Claude Code starts — and an unusable proxy for such an account is that same refusal, so `cswap run --auto` moves to the next ranked candidate either way. A `swap`/`move` that gives the slot to another account while the checks run ends the launch.

Read next: the module docstring of `session.py`, and [proxy.md](proxy.md#launching-claude-code).

### Adding an account by login

`cswap add --login` validates its arguments and resolves `claude` first, then checks the given proxy and its egress rule outside every lock. It runs the official `claude auth login` in a throwaway profile (`login.py`, removed with its Keychain entry in `finally`) and reads the credential and `oauthAccount` metadata from that profile only. A route whose scheme needs `proxy_bridge` gets one for the length of that child, so the login's environment carries the loopback address rather than the account's URL. The slot is chosen and the overwrite question asked after the login, because only then is the account known; the write of the credential, the config and `sequence.json` is one step under the account lock; `activeAccountNumber` is left alone unless the account is moving out of the active slot, in which case it follows the backup.

### A launch on the best account

`cswap run --auto` picks the account with `ClaudeAccountSwitcher.auto_run_plan` from one capture of the roster (`_build_accounts_info`): the launchable slots ranked by headroom above 0, then by "Claude Code has not reported a rate-limit stop on it", then by headroom. The plan confirms a candidate's reading once when the walk reaches it (`_collect_usage_entries(fetch={candidate})`) and moves to the next one when that confirmation has no room left — `SERVE_TTL_S` is the oldest a ranking reading may be. The same plan answers the next candidate after a refused exit check, so a rejection costs one row of the order rather than a second capture. The launch is then the session-mode one above, without touching `sequence.json`; the slot travels into it as the (slot, email, organization) it was read with.

`StopFailure` with matcher `rate_limit` is what Claude Code reports a refused turn with; every launch that runs the recorded active account — `cswap run --active` (what the thin `claude` wrapper runs) and the fallback launch when the directory has no `cswap map` — passes that hook through `--settings` (`--auto` carries the same hook for the launch it picks). It runs `cswap rate-limited <email> <organization>` (`record_stop_failure`), which stamps `cache/stop-failure.json` and delegates to `isolated_mode` to update `sequence.json`: `switch_active_after_rate_limit` moves the recorded `activeAccountNumber` off the refused account — only while it is still that account's slot, writing `activeAccountNumber`/`lastUpdated` only. Marked means "the reading predates the refusal" — a reading newer than the stamp clears it, so no deadline is stored.

The thin `claude` wrapper calls `cswap run --active` for every launch — the recorded slot — and `cswap run --auto` keeps the quota-ranked launch for anyone who asks for it. `session.find_claude` is the one place that resolves the binary a launch hands the terminal to (`CSWAP_CLAUDE_BIN` first), and it never returns the wrapper: a `claude` that is the wrapper (recognised by a marker line in its first bytes) is walked past on `PATH`.

Read next: `wrapper.py` and [auto-launch.md](auto-launch.md).

### Auto-switch

`AutoSwitchEngine.tick` collects usage, ranks the candidates (`_rank_candidates`), freshens the chosen target's token (`_freshen_target`) and calls `switcher.switch_to`. `cswap auto`, the TUI's auto screen and the menu bar all run this same engine and render its events. Cooldown and quarantine are kept in `autoswitch_state.json` under their own lock, so a cron-driven `--once` and a long-running loop agree.

Read next: the module docstring of `autoswitch.py`. The rules as users see them are in [auto-switch.md](auto-switch.md).

## Rules that hold everywhere

- **Lock order.** cswap's lock, then Claude Code's credential lock, then its config lock. Never the other way round.
- **No network under a lock.** A switch does only local I/O under its locks, and the usage store never holds its lock across a fetch. The single deliberate exception is the token refresh described above.
- **A used refresh token's successor is never dropped.** Once the refresh is posted, the new credential is persisted or stashed, whatever else fails.
- **A live credential enters a slot only when it is known to belong there.** Writing another account's credential into a slot destroys that slot's only refresh token.
- **The usage store persists readings and fetch state only.** Labels such as "token expired" are derived on every pass and never written.
- **Polling numbers live in `poll_policy.py` only.**
- **Collection and the engine tick never raise.** A failure becomes a state or an event.
- **Surfaces hold no account logic.** Dashboards read through `SnapshotSource`; the engine does not print.
- **Import direction.** `session.py` and `credentials.py` do not import `switcher.py`. `fsutil.py` imports nothing from the package. The TUI's heavy imports stay inside `tui.run`.
- **Paths come from `paths.py`.** Do not hardcode `~/.claude`; Claude Code's own resolution has cases that differ.
- **A launch hands the terminal to the real Claude Code, never to the wrapper.** `session.find_claude` is the only resolver, and the wrapper's `cswap run --active` is the only place an account is chosen for a plain `claude`.
- **A switch writes `sequence.json` only.** `activeAccountNumber` is the active account; the global `~/.claude` login is reported and imported, never written and never active. No Claude Code lock is taken to switch.
- **A proxy password stays in this process.** It is stored in `sequence.json` (0600) and masked everywhere it is shown; it reaches a child's environment (Claude Code, `claude auth login`) only for an `http://` route, and for the schemes `proxy_bridge` carries the child reads `http://127.0.0.1:<port>` instead.
- **A request for an account travels that account's route.** Every network call in `oauth.py` and `subscription.py` takes an `account_proxy` route; a slot with no proxy goes direct, and one whose proxy is set never does. The route comes from the same read as the credential it is used for (`AccountInfo` in `switcher.py`), so a concurrent `swap`/`move` cannot pair one account's token with another slot's route. A launch of such an account takes the same route — checked before Claude Code starts and handed to it in the environment — and one whose route cannot be confirmed is refused rather than run direct. An egress expectation is measured on that same route, before Claude Code starts, and never through a direct connection.

## Tests

`uv sync`, then `uv run pytest`. CI runs the same on Linux, macOS and Windows. Tests are mostly one file per module, `tests/test_<module>.py`.

Tests cannot write the real account store: `tests/conftest.py` installs a process-wide guard that refuses any write under the real data paths, on top of the per-test temporary home.

# Launching Claude Code on a managed account

`cswap run --active -- <arguments>` starts Claude Code as the account recorded as
active (`sequence.json`'s `activeAccountNumber`), in that account's own session
profile with its own proxy. Every `claude` launch goes through it, so the account
is chosen by `cswap switch` — a switch writes that one field and nothing in
`~/.claude`, which means a running Claude Code is never pulled out from under and
another terminal keeps the account it started with.

`cswap run --auto -- <arguments>` is still there for a launch that picks for
itself: the managed account with the most remaining quota, without changing the
recorded active slot. The rest of this page describes it.

## Install the Claude wrapper

The wrapper is available on Linux and macOS. Accept the one-time prompt after
`cswap add` or `cswap add --login`, use **Claude wrapper…** in the TUI menu, or run:

```bash
cswap wrapper install
cswap wrapper status
```

The installer puts the symlink where `claude` is resolved from without any
profile edit when it can: `~/.local/bin/claude`, provided `~/.local/bin` is
already on `PATH` ahead of the real Claude Code and nothing else is there. The
wrapper is then active in the running session and in background services and
IDEs that never read a shell profile.

Otherwise — the name is taken by a real or foreign `claude`, `~/.local/bin` is
not on `PATH` or comes after the real one, or it is not writable — the symlink
goes to `~/.local/claude-swap/bin/claude` and a marked `PATH` block is added to
the profile for your `$SHELL` (`~/.bashrc`, `~/.zshrc`, or
`~/.config/fish/config.fish`). Open a new shell or source that profile to
activate it; background services and IDEs do not read the profile, so add that
directory to their `PATH` yourself if they need the wrapper. For another shell,
add the directory ahead of the real Claude Code in its `PATH` setup using the
instruction printed by the installer.

Use `cswap wrapper install --dir PATH` to choose a different directory. If
that directory is already in `PATH`, the installer skips the profile edit.
It must still come before the real Claude Code for the wrapper to be active.
Installation requires a real, executable Claude Code on `PATH` or at
`CSWAP_CLAUDE_BIN`, and refuses to replace an existing file it does not
recognize as the wrapper.

`cswap wrapper status` shows the wrapper's location, which `claude` the
current `PATH` selects, and where cswap finds the real executable. Both it and
`cswap wrapper uninstall` without `--dir` look in both standard directories,
so they find the wrapper whichever one the installer used; a real `claude` in
the other directory is left untouched. `cswap wrapper uninstall` removes the
wrapper and the marked blocks it added. Pass the same `--dir PATH` to uninstall
from a custom directory.

For manual setup, `cswap wrapper` prints the shipped script's path. Create
the symlink and prepend its directory to `PATH`, for example in Bash or Zsh.

```bash
mkdir -p ~/.local/claude-swap/bin
ln -s "$(cswap wrapper)" ~/.local/claude-swap/bin/claude
export PATH="$HOME/.local/claude-swap/bin:$PATH"
```

To make a manual setup persistent, add that `PATH` entry to your shell's
profile and remove the entry yourself if you uninstall the wrapper.

Every `claude`, `claude --resume` and `claude -p "…"` then runs the account
recorded as active, in its own profile, with its arguments passed through
unchanged and its exit code kept. It refuses — never falling back to a bare
`claude` on `~/.claude` — when no slot is recorded, when the recorded slot is
disabled, when its login is still in the global `~/.claude`, or when its proxy
or exit check fails.

## Which account

One ranked pass over the launchable slots
(`ClaudeAccountSwitcher.auto_run_plan`), from the same capture `cswap list`
reads:

- **A slot is launchable** when it is in rotation, not disabled, holds stored
  credentials and config, and is not an API-key account (`cswap run` cannot
  launch one).
- **The headroom** is the existing one: 100% minus the highest of the account's
  5h and 7d windows, folded with the per-model weekly windows
  `autoswitch.model` names. The readings are the ones `cswap list` shows, on the
  usual poll plan — a launch can fetch usage for accounts that are due.
- **Ranking**, best first: a reading with quota left (headroom above 0) before
  none; an account Claude Code has not just reported a rate-limit stop on before
  one it has (see below); more headroom before less. Ties are settled in rotation
  order.
- **The winner is confirmed once** before the launch: its usage is read again
  through the store's own rules. A reading may be up to 180 s old
  (`SERVE_TTL_S`, derived from the usage endpoint's request budget) and the
  account may have spent its quota inside that window; if the confirmed reading
  has no room left, the next candidate is taken, each confirmed at most once.
- **Nothing with quota left is a refusal**, not a fallback: the command names
  the reason and, when every account is at its limit, when the nearest one is
  usable again. It launches nothing and exits non-zero. The time it names is the
  last spent window's reset (`poll_policy.limiting_reset_ts`) — an account with
  its 7d window at 100% resetting in three days is not "in 59m" because its 5h
  window at 5% resets in an hour.

An account that carries an egress expectation ([proxy.md](proxy.md#egress-expectation))
must also pass it: when the proxy cannot be used (no connection, 407), the exit
IP or country does not match, or no GeoIP service can be asked, the launch
prints the slot and the reason and takes the next candidate in the same
ranking. If every candidate is rejected that way, nothing is launched and the
command exits non-zero, naming each refusal and — when the accounts that were
not rejected have spent their quota — when the nearest reset is. The whole walk
comes from one capture of the account list and one pass over the readings, so a
rejected candidate costs one row of the ranking, not a fresh list.

The choice is not a switch: `sequence.json` keeps the account it had, so
`cswap status`, the menu bar and auto-switching see no change. The launch is the
ordinary session-mode one — that account's profile, its proxy checked and handed
to Claude Code, and the usual shared settings, skills, MCP servers, `CLAUDE.md`
and chat history, so `--resume` lists the same conversations. The chosen slot is
carried into the launch as the (slot, email, organization) it was read with, and
a `swap` or `move` that gives the slot to another account between the choice and
the start refuses the launch with a reason instead of running the newcomer.

Every launch is a session profile — for `--active` and for a named account too.
There is no plain `claude` on a login in `~/.claude`, so `--require-session` has
nothing left to refuse: isolation is unconditional.

## After an account runs out

The next launch picks another account. Two things say when an account is spent,
in this order:

- **The reading itself.** An account at its limit has headroom 0 or less, so the
  ranking passes it over. An exhausted account keeps being polled every 600 s
  (`EXHAUSTED_INTERVAL_S`) rather than being parked until its advertised reset,
  so a bucket Anthropic resets or tops up early is seen — but that is slower than
  a launch.
- **Claude Code's own report.** Every launch that runs the recorded active
  account — `--active` (what the thin `claude` wrapper runs) and the fallback
  launch when the directory has no `cswap map` — passes a `StopFailure` hook
  (`--settings`, matcher `rate_limit`); `--auto` carries the same hook for the launch it picks itself. A user `--settings`
  on the command line and one-word subcommands (`auth`, `doctor`, …) keep the
  hook off, exactly as with `--auto`: in front of a subcommand `--settings`
  turns the line into a prompt (measured on 2.1.329), and a user's own
  `--settings` owns that switch.

  When the server refuses a turn on the rate limit, the hook records the
  moment against that account — by `(email, organization)`, not by slot — and,
  if the refused account is still the recorded active slot, that slot moves to
  the best other suitable one right then: an unmarked slot with the most
  cached headroom above zero wins (ties in rotation order); when no other
  slot has a cached reading, the next unmarked suitable slot in rotation
  order takes over — so the next `claude` picks a different account even with
  no `cswap auto` running. When every other suitable slot is marked (its
  reading predates a `StopFailure` report, so its headroom is stale evidence),
  the marked slot with the oldest report takes over — ties in rotation order —
  so a refusal never pins the active slot on the refused account. The move
  writes only `activeAccountNumber` and `lastUpdated` into `sequence.json`
  (never `~/.claude`, never the Keychain), prints nothing, and costs no
  network request: it reads the usage store's already-cached readings and
  the stop marks. A `cswap switch`, `cswap next` or another session that
  already moved the active slot wins — nothing changes. If no other suitable
  slot exists (one account, or everything else disabled / an API key /
  without credentials / exhausted) the recorded slot stays.

  The same evidence rule guards `--strategy best`: a slot whose stop mark is
  newer than its cached reading is provably stale and can never win the pick,
  so a `cswap switch --strategy best` pass right after a refusal cannot roll
  the active slot back onto the account that just refused. A newer reading is
  the only thing that clears a mark: there is no deadline to expire. If every
  account is marked, the best of them is launched anyway (a plain 429
  produces the same report).

Claude Code 2.1.329 was the version measured for this: a 429 carrying
`anthropic-ratelimit-unified-status: rejected` ran the hook with
`"hook_event_name": "StopFailure", "error": "rate_limit"` in both a `-p` run and
an interactive session on a pseudo-terminal, and a hook of the user's own in
`settings.json` ran alongside cswap's `--settings` one. A command line that
already carries the user's `--settings` gets no hook from cswap.

Neither does a command line whose first argument reads as one of Claude Code's
subcommands — `attach`, `logs`, `stop`, `remote-control`, `respawn`, and the
ones a later release adds. In front of a subcommand `--settings` turns the whole
line into a prompt instead of running it (measured on 2.1.329: `claude
--settings {} attach nosuch` answers "Not logged in", and `remote-control
--help` refuses the flag), so `cswap` reads the first argument rather than
holding a list of command names, which would go stale. The rule is "one lowercase
word" (`re.fullmatch(r"[a-z][a-z-]*")`), and its cost is a prompt that is
exactly one such word: `claude hello` runs without a mark, so a second
`claude hello` can choose the account the first one chose again. The launch's
own confirmation of the candidate's reading does not rule that out: a reading
younger than the 180 s serve window (`poll_policy.SERVE_TTL_S`) — 20 s old
under a 600 s poll plan, say — is served from the cache, no request is made,
and the same ranking picks the same slot. What a repeat run relies on is
Claude Code's mark, and a one-word prompt gets none.

## What `--auto` does not do

- **It ignores `cswap map`.** A directory mapping is a choice of account; it
  applies to `cswap run` with no account named, not to `--auto`.
- **It does not isolate nested launches.** A `claude` started inside a session
  goes through the wrapper and launches the recorded active account in its own
  profile again. On an account with no proxy it inherits the proxy variables of
  the session that started it — the accepted rule of
  [proxy.md](proxy.md#launching-claude-code), which only replaces the variables
  of an account that has a proxy of its own.
- **It does not change background sessions.** Claude Code's `--bg` sessions and
  `attach` belong to the profile they were started from; a later launch choosing
  another account neither detaches them nor moves them.

## Claude Code's own commands

Claude Code's housekeeping commands are not sessions, so each launch form
answers them where they belong rather than starting one:

- **`claude mcp …`** manages the user's shared server list. A session profile's
  copy is deleted by the next launch's MCP sync, so a write there would be lost
  and the profile the user manages their servers on would never see it. Every
  launch form — `--active` (what the wrapper runs), `--auto`, a named account
  and the directory-mapping launch — sends it to the primary profile
  (`manager.exec_default(..., primary_profile=True)`), whose login's proxy is
  still checked and handed over, fail-closed. The command runs on the user's
  own profile even from inside a session, whose terminal exports its profile in
  `CLAUDE_CONFIG_DIR`: that variable is dropped for the child, so the server
  lands in the profile the next session launch syncs FROM.
- **`claude --version`, `-v`, `--help`, `-h`** answer a property of the
  installed binary: `--auto` runs them on the real binary directly
  (`manager.exec_local`), with no login, profile, proxy or quota involved. The
  thin wrapper hands them over the same way before it calls cswap at all.
- **`claude auth …`, `plugin …`, `update`, `doctor` and the rest** need a
  login, so they are a launch: `--active` runs them on the recorded account's
  session profile (so `claude auth status --json` answers about that account)
  and `--auto` runs them through its ranking like any other launch. Neither
  hands them to the global `~/.claude` outside the account's proxy.

## The wrapper

The wrapper is a symlink to the shipped script (`scripts/claude` in the package),
so it picks up updates to the package's script. The script handles each launch
as follows.

- `export DISABLE_AUTOUPDATER=1` before anything else: Claude Code's own updater
  would otherwise install a second, unwrapped launcher under `~/.local/bin` or
  `~/.claude/local`, and every update after that would bypass the wrapper;
- `--version`, `-v`, `--help` and `-h` as the first argument hand over to the
  real Claude Code directly, with no quota check and no network — an SDK, a
  package manager or a person asking which version is installed gets an answer
  without an account;
- with `cswap` missing from `PATH`, it prints that to stderr and exits `127`;
- otherwise it replaces itself with `cswap run --active -- "$@"` (`exec`), so the
  launch's notices go to stderr, stdout stays Claude Code's, and the exit code is
  `cswap`'s and therefore Claude Code's. A refusal (no active slot, a disabled
  one, a proxy or exit check that fails) is a non-zero exit — never a bare
  `claude` on `~/.claude`.

The real binary is resolved by `CSWAP_CLAUDE_BIN` first when it names an
executable that is not the wrapper, then by walking `PATH`; a bare `claude` need
not be on `PATH` at all. Inside cswap the same variable is read first by
`session.find_claude`, the only place that resolves the binary a launch hands the
terminal to, and it never returns the wrapper: a `claude` on `PATH` that is the
wrapper is walked past, so an explicit `cswap run 3` is not replaced by the
active account and the `claude auth status` probe does not become a second cswap.
cswap knows its own script by a marker line near its top, so an edited copy or
another version is recognised too, and it reads only the first kilobytes of a
candidate — Claude Code's own binary is 377 MB.

## Non-essential traffic

Every launch through `cswap run`, `--auto` included, sets
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`: Claude Code's auto-updates,
telemetry, error reporting, release notes, availability checks and feature flags
are off, which is what makes Remote Control unavailable in these sessions. These
are Claude Code's own behaviours and what the variable covers are in
[proxy.md](proxy.md#launching-claude-code). `cswap config set
run.disableNonessentialTraffic false` stops cswap from setting the variable (it
never unsets an inherited one), giving those features back; the proxy settings an
account carries are unaffected either way.

A launch on the recorded account (or the one `--auto` chose) drops the shell's auth
overrides (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and the rest of
`AUTH_OVERRIDE_ENV_VARS`): the account, and the proxy it was checked with, were
chosen for the user, and an exported key would bill someone else's credential
through that proxy.

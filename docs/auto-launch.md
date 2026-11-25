# Launch on the account with the most quota

`cswap run --auto -- <arguments>` starts Claude Code as the managed account with
the most remaining quota. The account is chosen for that one process: the
default login is read, never switched, so another terminal and the VS Code
extension keep the account they had.

The thin `claude` wrapper runs it for every launch. Put a symlink to it in a
directory of its own, ahead of the real Claude Code in `PATH` — **not** in the
directory Claude Code's own installer keeps its launcher in (`~/.local/bin` on
Linux and macOS, which it links into `versions/`, so a symlink there either
fails with `File exists` or replaces that launcher and leaves nothing else on
`PATH` to run):

```bash
mkdir -p ~/.local/claude-swap/bin
ln -s "$(cswap wrapper)" ~/.local/claude-swap/bin/claude
export PATH="$HOME/.local/claude-swap/bin:$PATH"
```

Every `claude`, `claude --resume` and `claude -p "…"` then picks an account, with
its arguments passed through unchanged and its exit code kept.

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
  one it has (see below); more headroom before less; and the login the terminal
  already has before another slot at equal headroom — that one is launched on the
  default login itself (the same-account fast path), not in a session profile.
  Ties are otherwise settled in rotation order.
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

The choice is not a switch: `sequence.json` and the default login keep the
account they had, so `cswap status`, the menu bar and auto-switching see no
change. The launch is the ordinary session-mode one — that account's profile,
its proxy checked and handed to Claude Code, and the usual shared settings,
skills, MCP servers, `CLAUDE.md` and chat history, so `--resume` lists the same
conversations. The chosen slot is carried into the launch as the
(slot, email, organization) it was read with, and a `swap` or `move` that gives
the slot to another account between the choice and the start refuses the launch
with a reason instead of running the newcomer.

With `--require-session` the current-login case still refuses, as it does for a
named account: `--auto` then reports it instead of choosing another account.

## After an account runs out

The next launch picks another account. Two things say when an account is spent,
in this order:

- **The reading itself.** An account at its limit has headroom 0 or less, so the
  ranking passes it over. An exhausted account keeps being polled every 600 s
  (`EXHAUSTED_INTERVAL_S`) rather than being parked until its advertised reset,
  so a bucket Anthropic resets or tops up early is seen — but that is slower than
  a launch.
- **Claude Code's own report.** A launch of `--auto` passes a `StopFailure` hook
  (`--settings`, matcher `rate_limit`). When the server refuses a turn on the
  rate limit, the hook records the moment against that account — by
  `(email, organization)`, not by slot — and the next launch ranks that account
  below any other one with quota until a reading newer than the report arrives.
  A newer reading is the only thing that clears it: there is no deadline to
  expire. If every account is marked, the best of them is launched anyway (a
  plain 429 produces the same report).

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
  goes through the wrapper and chooses an account again. On an account with no
  proxy it inherits the proxy variables of the session that started it — the
  accepted rule of [proxy.md](proxy.md#launching-claude-code), which only
  replaces the variables of an account that has a proxy of its own.
- **It does not change background sessions.** Claude Code's `--bg` sessions and
  `attach` belong to the profile they were started from; a later launch choosing
  another account neither detaches them nor moves them.

## Claude Code's own commands

`claude mcp add …`, `claude plugin …`, `claude auth …`, `claude update`,
`claude --version`, `claude doctor` and the rest of Claude Code's housekeeping
are not sessions, so `--auto` hands them to the default login
(`manager.exec_default`) instead of choosing an account:

- `claude mcp add -s user` would otherwise write the server into the chosen
  account's profile, which the next launch's MCP sync deletes, and the login the
  user manages their MCP servers on would never see it;
- `claude --version` and `claude update` would be refused when no account has
  quota left.

The default login's own proxy is still checked and handed over, fail-closed, the
same as any launch of that login. These commands run on the user's own profile
even from inside a session, whose terminal exports its profile in
`CLAUDE_CONFIG_DIR`: that variable is dropped for the child, so `claude mcp add`
writes the profile the next session launch syncs FROM rather than a copy it
overwrites.

## The wrapper

`cswap wrapper` prints the path of the shipped script (`scripts/claude` in the
package); install it as a symlink, because a symlink is what the documentation
below is written for and what keeps the package's copy a single file to update.
What it does:

- with `cswap` missing from `PATH`, it prints that to stderr and exits `127`;
- otherwise it replaces itself with `cswap run --auto -- "$@"` (`exec`), so the
  launch's notices go to stderr, stdout stays Claude Code's, and the exit code is
  `cswap`'s and therefore Claude Code's.

It searches for nothing. `session.find_claude` is the only place that resolves
the real Claude Code, and it never returns the wrapper: a `claude` on `PATH` that
is the wrapper is walked past, so an explicit `cswap run 3` is not replaced by
an automatic choice and the `claude auth status` probe does not become a second
cswap. cswap knows its own script by a marker line near its top, so an edited
copy or another version is recognised too, and it reads only the first
kilobytes of a candidate — Claude Code's own binary is 377 MB.

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

`--auto` also drops the shell's auth overrides (`ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN` and the rest of `AUTH_OVERRIDE_ENV_VARS`) on the
same-account fast path, where an explicit `cswap run` keeps its environment: the
account, and the proxy it was checked with, were chosen for the user.

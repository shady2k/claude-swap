# Launch on the account with the most quota

`cswap run --auto -- <arguments>` starts Claude Code as the managed account with
the most remaining quota. The account is chosen for that one process: the
default login is read, never switched, so another terminal and the VS Code
extension keep the account they had.

The thin `claude` wrapper runs it for every launch. Put a symlink to it in a
directory ahead of the real Claude Code in `PATH`:

```bash
ln -s "$(cswap wrapper)" ~/.local/bin/claude
```

Every `claude`, `claude --resume` and `claude -p "…"` then picks an account, with
its arguments passed through unchanged and its exit code kept.

## Which account

The same comparison `cswap switch --strategy best` makes, read as a launch
(`ClaudeAccountSwitcher.auto_run_target`):

- **A slot is a candidate** when it is in rotation, not disabled, holds stored
  credentials and config, and is not an API-key account (`cswap run` cannot
  launch one).
- **The headroom** is the existing one: 100% minus the highest of the account's
  5h and 7d windows, folded with the per-model weekly windows
  `autoswitch.model` names. The readings are the ones `cswap list` shows, on
  the usual poll plan — a launch can fetch usage for accounts that are due.
- **A strictly better account is taken**, exactly as `best` would switch to it.
  When `best` would stay put, the account the terminal's login already is holds
  the most headroom and that is the one launched — on the default login itself
  (the same-account fast path), not in a session profile.
- **Nothing with quota left is a refusal**, not a fallback: the command names
  the reason and, when every account is at its limit, the nearest reset time.
  It launches nothing and exits non-zero.

The choice is not a switch: `sequence.json` and the default login keep the
account they had, so `cswap status`, the menu bar and auto-switching see no
change. The launch is the ordinary session-mode one — that account's profile,
its proxy checked and handed to Claude Code, and the usual shared settings,
skills, MCP servers, `CLAUDE.md` and chat history, so `--resume` lists the same
conversations.

With `--require-session` the current-login case still refuses, as it does for a
named account: `--auto` then reports it instead of choosing another account.

## After an account runs out

The next launch picks another account. Nothing has to mark the exhausted one:
its reading already says 100%, its headroom is 0 or less, so the comparison
passes it over, and the usage store holds that reading until the account's own
`resets_at` and refetches then (see [usage polling in the
architecture](architecture.md#usage-collection)). No signal is read from Claude
Code itself, so a session that is refused by the server mid-turn changes nothing
about the next launch's choice until its usage reading shows it.

## The wrapper

`cswap wrapper` prints the path of the shipped script (`scripts/claude` in the
package); install it as a symlink, because a symlink is what the script resolves
to find itself and what cswap recognises as its own wrapper. What it does:

- resolves its own path through symlinks, then finds the real Claude Code — the
  first `claude` on `PATH` that is not itself — and hands that path to cswap in
  `CSWAP_REAL_CLAUDE`;
- with no real Claude Code on `PATH`, or with `cswap` missing, it prints what is
  missing to stderr and exits `127`;
- otherwise it replaces itself with `cswap run --auto -- "$@"` (`exec`), so the
  launch's notices go to stderr, stdout stays Claude Code's, and the exit code is
  `cswap`'s and therefore Claude Code's.

cswap never starts the wrapper. Given `CSWAP_REAL_CLAUDE`, it uses that path;
started as `cswap run 3` with the wrapper on `PATH`, it walks `PATH` past the
wrapper to the real binary, so an explicit account is not replaced by an
automatic choice and the `claude auth status` probe does not become a second
cswap. `CSWAP_REAL_CLAUDE` is dropped from the environment Claude Code gets, so
a `claude` a session starts later goes through the wrapper again.

A copy of the script that is edited, or from another version, is not recognised
as the wrapper. It still finds the real binary, but cswap then treats it as an
ordinary `claude` on `PATH`, and the account cswap chose can be replaced by the
copy's own choice. Install it as a symlink.

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

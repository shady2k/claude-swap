# Experimental PATH shim

On POSIX, `cswap transparent enable` installs a separate `claude` launcher and prints the PATH change. Apply that change only in the client environment that should use the shim. The original executable is not changed. `cswap transparent disable` removes the installed launcher, not the original. You can then remove the shim directory from PATH.

`cswap transparent status` reports which `claude` this PATH would find, whether the installed shim is current, the original executable, PATH entries rejected during the safe lookup, and launch attempts recorded in the last 24 hours. It does not inspect another client's PATH. An absolute path bypasses the shim. On Windows, a client's application directory or working directory can also take precedence over PATH; Windows installation is disabled pending launcher verification (PR1).

Only the isolated synthetic test route has a verified settings layer. No production build has been admitted for profile routing (PR3). Strict mode (`transparent.requireProxy=true`) refuses production launches with code 4. In optional mode, accountless and unrecognized forms and `CLAUDE_SWAP_BYPASS=1` launch outside the profile route, with a warning. `transparent.allowUnverified=true` also permits unverified main invocations outside the route. Do not combine it with `requireProxy`. Test mode refuses bypass, caller-supplied settings, and unsafe lower settings layers before launching Claude. It is not a network sandbox.

The isolated Linux stand can opt into synthetic direct TLS with `CLAUDE_SWAP_TEST_DIRECT=<loopback>:<port>` and matching reserved HTTPS origins on that port. This does not admit a production Claude build or enable a production direct route.


## Profile ownership

Both explicit `cswap run ACCOUNT` and routed shim launches reserve the selected
profile before reuse or preparation, excluding the default-login account both
when reserving and publishing. Multiple launches may reserve and reuse the same
profile. Reserved/warming peers do not block preparation. First creation of an
absent profile keeps its generation; rebuilding or deleting an existing profile
changes `profileGen`, so stale preparations refuse and remove
only their own records. Running launches block overwrite or deletion of their
profile. Reservations and `profileGen` live under `profile-ownership/` outside
the removable profile. Swap, move, remove, switch
(including auto-switch), and replacement import refuse affected busy slots even
when disabled or removed from the transparent pool.

Isolated explicit account launches also require build and invocation admission
before reuse, including when the shim is disabled. A launch using the unchanged
default login does not prepare an isolated profile. Production build admission
is deferred to PR3 (`transparent._prepare_launch`); no production build is
admitted here. Only the isolated synthetic Linux route can publish a running
reservation.
Linux launches use a dedicated single-threaded subreaper supervisor. The
reservation is released only after it has reaped the leader and all descendants,
including descendants that change session. A failed handoff also releases it
once the tree is empty. Supervisor death or an uncertain wait leaves it busy;
a PID disappearing alone does not prove completion. A live launch must finish
its entire descendant tree: after the leader exits, INT/TERM/HUP are forwarded
to remaining verified descendants and supervision keeps waiting. A descendant
that ignores the signal keeps the profile protected. After proven completion,
release retries ownership-lock contention without an overall deadline; storage
errors are reported separately.

A dead supervisor leaves completion unconfirmed; repeating a switch does not
clear that uncertainty. There is no forced-reset or recovery command. On the
same machine, a recorded Linux boot ID different from the current trustworthy
boot ID proves the old tree ended. Missing boot metadata, an unreadable boot ID,
or a different machine identity does not. PID start ticks distinguish process
instances within a boot, not boots. Non-Linux publication fails closed; Windows
job completion is not verified.

Invalidation, deletion and backup credential changes advance the external
profile generation, including for disabled accounts outside the pool. Purge
refuses busy or unknown owners and keeps ownership records, generation
tombstones and the account lock file. These restrictions still leave production
build admission and non-Linux lifecycle support incomplete.

## Shared history consent

The shim requires `run.shareHistory` and explicit consent to share the **whole** `projects/` archive with the pool's recipients. This includes history from the main login, `cswap run`, and accounts that are no longer in the pool. `--resume` and `--continue` use the same recipient policy as a fresh launch; the session's source account does not have to be a recipient.

Use `cswap transparent enable --accept-shared-history` when there is no terminal, for example in automation. To choose an ordered pool, repeat `--account N` with `enable`. Use `cswap transparent pool --account N` (repeat for each retained account) to remove or reorder recipients. Removing an account stops it from receiving history; it does not remove its past conversations from the archive. Use `cswap transparent revoke-shared-history` to withdraw consent, or `cswap transparent disable` to remove the shim. A launch already published is not stopped; policy changes apply to subsequent publications. Disabling transparent mode does not take back anything already sent.

The default `~/.claude/projects` directory must belong to the current user and grant no permissions to group or others. The shim checks the path to the home directory, following trusted links there, but `.claude` and `projects` themselves must not be symlinks or junctions. cswap checks the archive path at `transparent enable` and when preparing and publishing a routed launch. If the archive directory is missing when preparing a routed launch, cswap creates it with mode `0700`. Unsafe archive paths cause exit code 4 when checked. Missing or outdated consent and disabled sharing still cause exit code 4 before Claude starts, even outside the profile route. The launch journal does not store conversation IDs or contents.

Set `transparent.claudePath` to an absolute executable path to override discovery. Use `cswap transparent enable` again if the Python installation or launcher policy changes.

# Experimental PATH shim

On POSIX, `cswap transparent enable` installs a separate `claude` launcher and prints the PATH change. Apply that change only in the client environment that should use the shim. The original executable is not changed. `cswap transparent disable` removes the installed launcher, not the original. You can then remove the shim directory from PATH.

`cswap transparent status` reports which `claude` this PATH would find, whether the installed shim is current, the original executable, PATH entries rejected during the safe lookup, and launch attempts recorded in the last 24 hours. It does not inspect another client's PATH. An absolute path bypasses the shim. On Windows, a client's application directory or working directory can also take precedence over PATH; Windows installation is disabled pending launcher verification (PR1).

Only the isolated synthetic test route has a verified settings layer. No production build has been admitted for profile routing (PR3). Strict mode (`transparent.requireProxy=true`) refuses production launches with code 4. In optional mode, accountless and unrecognized forms and `CLAUDE_SWAP_BYPASS=1` launch outside the profile route, with a warning. `transparent.allowUnverified=true` also permits unverified main invocations outside the route. Do not combine it with `requireProxy`. Test mode refuses bypass, caller-supplied settings, and unsafe lower settings layers before launching Claude. It is not a network sandbox.

The isolated Linux stand can opt into synthetic direct TLS with `CLAUDE_SWAP_TEST_DIRECT=<loopback>:<port>` and matching reserved HTTPS origins on that port. This does not admit a production Claude build or enable a production direct route.

## Shared history consent

The shim requires `run.shareHistory` and explicit consent to share the **whole** `projects/` archive with the pool's recipients. This includes history from the main login, `cswap run`, and accounts that are no longer in the pool. `--resume` and `--continue` use the same recipient policy as a fresh launch; the session's source account does not have to be a recipient.

Use `cswap transparent enable --accept-shared-history` when there is no terminal, for example in automation. To choose an ordered pool, repeat `--account N` with `enable`. Use `cswap transparent pool --account N` (repeat for each retained account) to remove or reorder recipients. Removing an account stops it from receiving history; it does not remove its past conversations from the archive. Use `cswap transparent revoke-shared-history` to withdraw consent, or `cswap transparent disable` to remove the shim. A launch already published is not stopped; policy changes apply to subsequent publications.

Missing or outdated consent, disabled sharing, and unsafe archive paths cause exit code 4 before Claude starts. The launch journal does not store conversation IDs or contents.

Set `transparent.claudePath` to an absolute executable path to override discovery. Use `cswap transparent enable` again if the Python installation or launcher policy changes.

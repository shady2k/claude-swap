# Experimental PATH shim

On POSIX, `cswap transparent enable` installs a separate `claude` launcher and prints the PATH change. Apply that change only in the client environment that should use the shim. The original executable is not changed. `cswap transparent disable` removes the installed launcher, not the original. You can then remove the shim directory from PATH.

`cswap transparent status` reports which `claude` this PATH would find, whether the installed shim is current, the original executable, PATH entries rejected during the safe lookup, and launch attempts recorded in the last 24 hours. It does not inspect another client's PATH. An absolute path bypasses the shim. On Windows, a client's application directory or working directory can also take precedence over PATH; Windows installation is disabled pending launcher verification (PR1).

Only the isolated synthetic test route has a verified settings layer. No production build has been admitted for profile routing (PR3). Strict mode (`transparent.requireProxy=true`) refuses production launches with code 4. In optional mode, accountless and unrecognized forms and `CLAUDE_SWAP_BYPASS=1` launch outside the profile route, with a warning. `transparent.allowUnverified=true` also permits unverified main invocations outside the route. Do not combine it with `requireProxy`. Test mode refuses bypass, caller-supplied settings, and unsafe lower settings layers before launching Claude. It is not a network sandbox.

Set `transparent.claudePath` to an absolute executable path to override discovery. Use `cswap transparent enable` again if the Python installation or launcher policy changes.

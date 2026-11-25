# Per-account proxy

`cswap proxy <num|email> <url>`, `cswap proxy <num|email> --unset`, `cswap proxy` (list) and `cswap add --proxy <url>` set, clear, show and set-on-add one account's HTTP proxy. `cswap proxy` is in the [README](../README.md#per-account-proxy); how the route is built is in the module docstring of `account_proxy.py`.

## The URL

- `http://[user:pass@]host[:port]`, port 80 when omitted. Credentials are optional and travel as `Proxy-Authorization` (`Basic`) on the proxy request and on the `CONNECT` tunnel; the account's OAuth token is never sent to the proxy.
- HTTPS endpoints are tunneled through the proxy with `CONNECT`.
- Only `http://` is accepted: cswap cannot speak TLS to the proxy itself, so an `https://` value would fail later instead of at the command.
- Anything else is refused before `sequence.json` is touched, with a message that never repeats the value.

## What it routes

Every request cswap makes *for that account*: the usage endpoint, the token refresh and its retries (the consume gate, the active-account refresh, the retry after a 401), the header probes, the profile read and the plan read. `update_check` keeps its own path — it is not an account's traffic — and an account without a proxy behaves as before, going direct.

The route is pinned to the account, not to the slot number: it is read in the same pass as the account's identity and credential (`_build_accounts_info`), and a request started before a `swap`/`move` keeps the route of the account whose token it holds. The backup-token gate reads its route under the same lock as the grant it POSTs. A change therefore applies to the next request.

Known risk, accepted: the ownership lookup for the live login takes the route of the slot `~/.claude.json` names, so a live token that actually belongs to another proxied account is checked over the named slot's route (direct when it has none). A token the lookup proves to be another account's is never written into a slot; when ownership cannot be determined at all (offline, a malformed reply), the switch keeps its pre-proxy behavior and reserves the slot for the credential it already stores.

## Launching Claude Code

A launch of a proxied account — `cswap run`, its plain-claude fast path on the default login, and `cswap run` with no account at all — is checked and dressed before Claude Code starts.

**The check.** One `CONNECT api.anthropic.com:443` with the URL's credentials, 5 s, no TLS handshake and no token. A 200 proves the proxy is listening, speaks the proxy protocol, accepted the credentials, and could reach that one target. It does not prove TLS survives the proxy, that the proxy allows every other host Claude Code may use, or that it stays up for the session. Everything it does not like ends the command before any Claude Code process — including the `claude auth status` probe — with a message that repeats neither the URL nor its user name: no connection, no 200, 407, a redirect, an unreachable address, or a stored value that does not parse.

**The environment.** That account's route goes into `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY`, in both cases, over whatever the shell carried: Claude Code resolves `https_proxy` before `HTTPS_PROXY`, so an inherited lower-case value would otherwise win, and an inherited `NO_PROXY=*` would switch the proxy off. `NO_PROXY` comes from `run.noProxy` alone — `cswap config set run.noProxy 'localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'` is the default, and an entry of `*` is refused because it bypasses the proxy for every host (how a `10.0.0.0/8` entry is read is up to the client that reads it; Claude Code does not document subnet support). An account without a proxy keeps the proxy variables it inherited. Every `cswap run` also gets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` ([env-vars](https://code.claude.com/docs/en/env-vars)); the switch that turns that off belongs to the `cswap run --auto` stage and will *unset* the variable, since `0` disables the traffic too.

**No account selected.** With no account named and no directory mapping (or a mapping whose account is gone), `cswap run` still launches plain claude on the default login. When that login belongs to a managed slot that has a proxy, the launch takes it and passes the check above; when the login is not a managed account, there is no route to apply and the inherited variables stay as they were.

**What this is not.** Nothing forbids a direct connection at the OS level. A launch can still reach the internet directly through a program that ignores these variables (`psql`, `ssh`, `curl --noproxy '*'`), and cswap's own requests remain strictly on the account's route.

Known limits of the environment, all Claude Code's own behaviour:

- An `env` block in Claude Code's `settings.json` [replaces](https://code.claude.com/docs/en/settings-reference#how-env-values-interact-with-your-shell) the shell environment, so a proxy or `NO_PROXY` put there overrides the account's. Keep them out of `settings.json`.
- Background sessions (`claude --bg`, `claude agents`) are served by one process per user with the environment of the terminal that started it first ([network-config](https://code.claude.com/docs/en/network-config#apply-network-settings-to-background-agents)); a session started later can therefore carry another account's proxy.
- `cswap switch` and auto-switching change the account, not the proxy of a `claude` already running. The new proxy applies to the next launch.

## Boundaries

The guarantee above is for ONE cswap command at a time, which is upstream's contract: two commands that change the account list at the same moment are not supported.

- Two commands at once can publish the second one's snapshot over the first — for example `cswap remove` waiting for its confirmation while `cswap proxy` sets a setting in another terminal. The new proxy is lost, and that account goes direct until it is set again.
- Two organizations with one email: a background request can travel the sibling's route when the slots are swapped while it runs, and on macOS a Keychain delete that fails leaves the old item readable. Stop `auto`, the menu bar and the TUI before swapping such slots; that does not protect against a refusing Keychain.
- A slot moved during a background token refresh can leave the account needing a new login. It does not create a direct connection.

Within one command, `switch`, `swap`, `move` and `cswap proxy` take the same account lock, and `add` reads the credential and the identity that labels it under it. A slot they move therefore cannot pair one account's token with another slot's route or setting.

## Fail-closed

With a proxy set, none of these falls back to a direct connection:

| Case | Reported as |
|---|---|
| the proxy refuses the URL's credentials (HTTP 407) | `proxy-auth` |
| the proxy answers a redirect (3xx) instead of forwarding | `proxy-redirect` |
| the stored value cannot be parsed, or the key is present with a value that is not a URL (a hand-edited `"proxy": null` included) | `proxy-invalid` |
| the proxy is unreachable, times out, or the certificate is refused | `network`, `timeout`, `tls-cert` |

407 and 3xx are recognised whether they answer the plain request or the `CONNECT` tunnel an HTTPS request travels; the proxy's own status phrase is dropped rather than repeated in the error or the debug log, because a proxy may put a credential in it.

`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` and the platform's proxy settings are not consulted, and `NO_PROXY`/`no_proxy` is ignored in both spellings: a bypass there would turn the same request into a direct connection. A refused request changes no credential and strikes no token, so a dead proxy never marks an account as needing a re-login — the row shows the error and backs off.

## Storage and transfer

The setting is a field on the account's record in `sequence.json` (written atomically, mode 0600): it moves with the account on `cswap swap` and `cswap move`, survives a re-add into the same slot and an import over that slot, and is deleted with `cswap remove`. `cswap proxy` resolves, reads and writes under the same account lock as `switch` and `swap`, so neither can publish a snapshot over the other's change (one run at a time — see [Boundaries](#boundaries)).

Only an absent key means "direct" — it is what `--unset` leaves and what every account had before this setting existed. A key with a value that is not a URL, an explicit `null` included, is damage and reads as `proxy-invalid`; `cswap list --json`/`status --json` then show `"invalid (…)"` instead of hiding it. The password is stored there because cswap must present it; every surface prints the masked form (`http://user:***@host:port`), and `cswap list --json`/`status --json` carry that masked form in an additive `proxy` field.

`cswap export` never carries the proxy, in either mode, and prints a masked reminder of the accounts that had one. `cswap import` keeps the proxy this machine already has for the same account.

## Rolling back

A build without proxy support ignores the field, and its requests for those accounts go direct. It also starts Claude Code with whatever proxy variables the shell carries — no pre-start check, no account route. Before switching back, save the URLs and stop running such accounts through that version.

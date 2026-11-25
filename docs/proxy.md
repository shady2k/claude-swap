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

## Egress expectation

`cswap proxy <num|email> --expect-country <CC> --expect-ip <IP>` sets, and `--unset-expect` clears, an optional promise about where that account's traffic leaves. Either flag alone is a rule; both may be set without repeating the URL. The country is an ISO 3166-1 alpha-2 code (input is case-insensitive and stored upper case), the IP is an IPv4 or IPv6 address (stored in canonical `ipaddress` form). Both are validated before `sequence.json` is written, and a rule on an account with no usable proxy is refused: it could never be checked, so it is not stored. `cswap proxy <num|email> --unset` removes the proxy and the rule; changing the URL keeps the rule.

The rule is a field pair on the account's record, `proxy_expected_country` and `proxy_expected_ip`, written atomically (mode 0600) under the same account lock as the proxy. It follows the account on `cswap swap` and `cswap move`, survives a re-add into the same slot and an import over it, and is removed with the account. `cswap export` never carries it, like the proxy. Only absent keys mean "no rule" — a hand-edited `null`, a non-string or an unparsable value is damage, reads as `invalid (…)` in the surfaces (`proxyExpected` in `--json`) and refuses every launch closed.

No rule means no request and no delay. With a rule, a launch measures the exit **before starting Claude Code and before `claude auth status`**, outside every file lock, strictly through the account's own route (`ProxyRoute.open`): no direct branch, no `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, no `NO_PROXY`, no redirects. The chain is three public GeoIP services — `https://ipinfo.io/json`, `https://ipwho.is/` and `https://ifconfig.co/json`, 3 s each — asked in that order. A request that fails (network, timeout, HTTP 4xx/5xx, invalid JSON) or an answer without a needed field moves to the next service; the first answer carrying an expected field with a different value refuses immediately, without asking the rest, with a message naming the expected and measured values. When none answers, the refusal names each service's reason. Neither message repeats the proxy URL, its credentials or any token.

The check is per launch: `cswap run <slot>`, the directory-mapping launch, the default-login launch and Claude Code's own housekeeping commands launched by `--auto` all refuse closed. `cswap run --auto` — and therefore the thin `claude` wrapper — treats a failed check as a reason to try the next ranked account: it prints the slot and the reason, then takes the next candidate; if every candidate fails, it launches nothing and exits non-zero. The account's identity is re-read when the profile is prepared, so a `swap` or `move` between the check and that step still ends the launch instead of preparing a neighbour's profile.

## Launching Claude Code

A launch of a proxied account — `cswap run`, its plain-claude fast path on the default login, and `cswap run` with no account at all — is checked and dressed before Claude Code starts. The proxy check below and the [egress check](#egress-expectation) above come first, in that order.

**The check.** One `CONNECT api.anthropic.com:443` with the URL's credentials, 5 s, no TLS handshake and no token. A 200 proves the proxy is listening, speaks the proxy protocol, accepted the credentials, and could reach that one target. It does not prove TLS survives the proxy, that the proxy allows every other host Claude Code may use, or that it stays up for the session. Everything it does not like ends the command before any Claude Code process — including the `claude auth status` probe — with a message that repeats neither the URL nor its user name: no connection, no 200, 407, a redirect, an unreachable address, a port that answers some other protocol, or a stored value that does not parse.

The account is resolved once, and the slot is read again when the profile is prepared: a `swap` or `move` that gives the slot to another account while the check runs ends the launch there, before any profile of the neighbour is touched, rather than preparing that profile under this account's proxy.

**The environment.** That account's route goes into `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY`, in both cases, over whatever the shell carried: Claude Code resolves `https_proxy` before `HTTPS_PROXY`, so an inherited lower-case value would otherwise win, and an inherited `NO_PROXY=*` would switch the proxy off. `NO_PROXY` comes from `run.noProxy` alone — `cswap config set run.noProxy 'localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'` is the default, entries may be separated by commas or spaces (Claude Code documents both), and an entry of `*` is refused because it bypasses the proxy for every host (how a `10.0.0.0/8` entry is read is up to the client that reads it; Claude Code does not document subnet support). An account without a proxy keeps the proxy variables it inherited.

Every `cswap run` also gets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` ([env-vars](https://code.claude.com/docs/en/env-vars)). That one variable turns off what Claude Code would otherwise send for its own purposes: auto-updates, telemetry, error reporting, `/feedback` and Claude-drafted feedback, release notes, the PR/MR status badge checks, availability checks such as the fast mode check, and the feature flags it fetches — which is what makes Remote Control unavailable in these sessions. `0` does not turn the traffic back on; only unsetting the variable does. `cswap config set run.disableNonessentialTraffic false` is that: cswap then does not set the variable at all (an inherited one is left as the shell has it), so Claude Code keeps its auto-updates and Remote Control. Nothing else about a launch changes.

**No account selected.** With no account named and no directory mapping (or a mapping whose account is gone), `cswap run` still launches plain claude on the default login. When that login belongs to a managed slot that has a proxy, the launch takes it and passes the check above; when the login is not a managed account, there is no route to apply and the inherited variables stay as they were.

**What this is not.** Nothing forbids a direct connection at the OS level. A launch can still reach the internet directly through a program that ignores these variables (`psql`, `ssh`, `curl --noproxy '*'`), and cswap's own requests remain strictly on the account's route.

Known limits of the environment, all Claude Code's own behaviour:

- An `env` block in Claude Code's `settings.json` [replaces](https://code.claude.com/docs/en/settings-reference#how-env-values-interact-with-your-shell) the shell environment, so a proxy or `NO_PROXY` put there overrides the account's. Keep them out of `settings.json`.
- Background sessions (`claude --bg`, `claude agents`) are served by one process per user with the environment of the terminal that started it first ([network-config](https://code.claude.com/docs/en/network-config#apply-network-settings-to-background-agents)); a session started later can therefore carry another account's proxy.
- `cswap switch` and auto-switching change the account, not the proxy of a `claude` already running. The new proxy applies to the next launch.

## Boundaries

The guarantee above is for ONE cswap command at a time, which is upstream's contract: two commands that change the account list at the same moment are not supported.

- Two commands at once can publish the second one's snapshot over the first — for example `cswap remove` waiting for its confirmation while `cswap proxy` sets a setting in another terminal. The new proxy is lost, and that account goes direct until it is set again.
- A `swap` or `move` that gives the launch's slot to another account while the pre-start check runs ends that launch. One that lands after the profile is prepared leaves the running launch as it was — the account it selected, on the route it checked — and the next launch sees the new owner. In neither case does one account's process get the other account's proxy.
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
| the account has an egress expectation and no usable proxy, or the rule is damaged | a refusal naming the expectation |
| the exit differs from the expectation | a refusal naming expected and measured values |
| no GeoIP service gave a usable answer | a refusal listing each service's reason |

407 and 3xx are recognised whether they answer the plain request or the `CONNECT` tunnel an HTTPS request travels; the proxy's own status phrase is dropped rather than repeated in the error or the debug log, because a proxy may put a credential in it.

`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` and the platform's proxy settings are not consulted, and `NO_PROXY`/`no_proxy` is ignored in both spellings: a bypass there would turn the same request into a direct connection. A refused request changes no credential and strikes no token, so a dead proxy never marks an account as needing a re-login — the row shows the error and backs off.

## Storage and transfer

The setting is a field on the account's record in `sequence.json` (written atomically, mode 0600), and the [egress expectation](#egress-expectation) is two more fields beside it: both move with the account on `cswap swap` and `cswap move`, survive a re-add into the same slot and an import over that slot, and are deleted with `cswap remove`. `cswap proxy` resolves, reads and writes under the same account lock as `switch` and `swap`, so neither can publish a snapshot over the other's change (one run at a time — see [Boundaries](#boundaries)).

Only an absent key means "direct" — it is what `--unset` leaves and what every account had before this setting existed. A key with a value that is not a URL, an explicit `null` included, is damage and reads as `proxy-invalid`; `cswap list --json`/`status --json` then show `"invalid (…)"` instead of hiding it. The password is stored there because cswap must present it; every surface prints the masked form (`http://user:***@host:port`), and `cswap list --json`/`status --json` carry that masked form in an additive `proxy` field.

`cswap export` never carries the proxy or its egress expectation, in either mode, and prints a masked reminder of the accounts that had a proxy. `cswap import` keeps the proxy and the expectation this machine already has for the same account.

## Rolling back

A build without proxy support ignores the field, and its requests for those accounts go direct. It also starts Claude Code with whatever proxy variables the shell carries — no pre-start check, no account route. Before switching back, save the URLs and stop running such accounts through that version.

# Per-account proxy

`cswap proxy <num|email> <url>`, `cswap proxy <num|email> --unset`, `cswap proxy` (list) and `cswap add --proxy <url>` set, clear, show and set-on-add one account's HTTP proxy. `cswap proxy` is in the [README](../README.md#per-account-proxy); how the route is built is in the module docstring of `account_proxy.py`.

## The URL

- `http://[user:pass@]host[:port]`, port 80 when omitted. Credentials are optional and travel as `Proxy-Authorization` (`Basic`) on the proxy request and on the `CONNECT` tunnel; the account's OAuth token is never sent to the proxy.
- HTTPS endpoints are tunneled through the proxy with `CONNECT`.
- Only `http://` is accepted: cswap cannot speak TLS to the proxy itself, so an `https://` value would fail later instead of at the command.
- Anything else is refused before `sequence.json` is touched, with a message that never repeats the value.

## What it routes

Every request cswap makes *for that account*: the usage endpoint, the token refresh and its retries (the consume gate, the active-account refresh, the retry after a 401), the header probes, the profile read and the plan read. `update_check` keeps its own path — it is not an account's traffic — and an account without a proxy behaves as before, going direct.

The route is pinned to the account, not to the slot number: it is read in the same pass as the account's identity and credential (`_build_accounts_info`), and a request started before a `swap`/`move` keeps the route of the account whose token it holds. The backup-token gate reads its route under the same lock as the grant it POSTs. A change therefore applies to the next request, and no concurrent relocation can send a proxied account's token out directly.

Known risk, accepted: the ownership lookup for the live login takes the route of the slot `~/.claude.json` names, so a live token that actually belongs to another proxied account is checked over the named slot's route (direct when it has none). cswap still never writes such a token into a slot it could not attribute.

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

The setting is a field on the account's record in `sequence.json` (written atomically, mode 0600): it moves with the account on `cswap swap` and `cswap move`, survives a re-add into the same slot and an import over that slot, and is deleted with `cswap remove`. `cswap proxy` resolves, reads and writes under the same account lock as `switch` and `swap`, so neither can publish a snapshot over the other's change.

Only an absent key means "direct" — it is what `--unset` leaves and what every account had before this setting existed. A key with a value that is not a URL, an explicit `null` included, is damage and reads as `proxy-invalid`; `cswap list --json`/`status --json` then show `"invalid (…)"` instead of hiding it. The password is stored there because cswap must present it; every surface prints the masked form (`http://user:***@host:port`), and `cswap list --json`/`status --json` carry that masked form in an additive `proxy` field.

`cswap export` never carries the proxy, in either mode, and prints a masked reminder of the accounts that had one. `cswap import` keeps the proxy this machine already has for the same account.

## Rolling back

A build without proxy support ignores the field and its requests for those accounts go direct. Before switching back, save the URLs and stop running such accounts through that version.

# JSON output reference

`cswap list --json`, `cswap status --json` and `cswap switch --json` print a single JSON object on stdout; human-readable notices go to stderr. The commands and an example are in the [README](../README.md#json-output-for-scripting).

## Contract

- Every payload carries a `schemaVersion` (currently `1`).
- On a handled error stdout is `{"schemaVersion":1,"error":{...}}` with a non-zero exit code.
- `--switch`/`--switch-to` report `{"switched": true|false, "from": …, "to": …, "reason": …}`.
- `activeAccountNumber` is the slot recorded as active in cswap's own state. `active` in the `status` payload is that slot, never a login read from `~/.claude`.
- `globalLogin` (`{"email": …}`) appears in `list` and `status` payloads only when a login is left in the global `~/.claude`. It is reported, never adopted and never written; the fork has no other field for it. An empty `email` means the credential file is there with no `oauthAccount` beside it — the residue of a cleanup that did not finish. `cswap add` imports only an account it can see in `~/.claude.json`, so there it refuses; delete `~/.claude/.credentials.json` by hand, or log in again and run `cswap add`.

## Usage windows

Each account row has a `usageStatus` and a `usage` object with `fiveHour` and `sevenDay` windows (`pct`, `resetsAt`).

`usageStatus` reports the state of the reading, not the quota: `ok`, `unavailable` (nothing decision-grade is stored), `no_credentials`, `api_key` (no subscription quota), `keychain_unavailable`, `token_expired`, `relogin_required`, `foreign_credential` (the live login belongs to another account), and `owner_changed` — this pass could not confirm the account's owner and route (another cswap process held the account lock, or the account moved between the reads), so no request was sent and the last stored reading is shown. `owner_changed` is re-derived on every pass; it is not a stored state.

- A window's `pct` is `null` when the usage API reported `utilization: null` for it.
- A window the account does not have (an Ultra account's `fiveHour`) is omitted.
- A per-model `scoped` window carries `probeAfter` (ISO-8601) when a setup-token's Fable probe (`usage.fableProbe`) found it used up: the row is kept as read, and Fable is not asked again before that time.
- Usage is served from a per-account cache: when the usage API is briefly unreachable, the last-known numbers are shown instead of nothing (the human view marks them with their age, e.g. `· 2m ago`).

## Optional row fields

These apply to `list` rows and the managed active row from `status --json`. All are additive.

| Field | Present when | Meaning |
|---|---|---|
| `usageFetchedAt`, `usageAgeSeconds` | the row has decision-trusted usage | How old the measurement is. |
| `lastGoodUsage`, `lastGoodFetchedAt`, `lastGoodAgeSeconds` | `usage` is null but a last-known measurement exists: data too old to drive a decision (`usageStatus` stays `unavailable`), or a row in a non-`ok` state such as `token_expired` | Preserves the human display without making the account actionable. |
| `usageError` | `usage` is null and nothing else explains it (`usageStatus` is `unavailable`) | The last fetch failure by kind (e.g. `http-429`, `timeout`). |
| `usageRetryAt` | the cache is backing off from that failure | The time of the next attempt. |
| `disabled` | the account is held out of rotation with `cswap disable` | `true`; absent otherwise. |
| `threshold` | a per-account threshold is set with `cswap threshold` | e.g. `85.0`; absent otherwise, so a fleet that never sets a policy emits rows identical to before. |
| `alias` | an alias is set with `cswap alias` | e.g. `"dev"`; accounts without one omit the key. |
| `loginExpiresAt` | the stored login records when its refresh token expires | ISO-8601 UTC: the moment the slot will need a fresh `/login` and `cswap add --slot N`, so a script can warn a few days ahead instead of discovering `relogin_required`. Absent when Claude Code recorded no such date for that login. |
| `proxy` | the account has a proxy set with `cswap proxy` | The stored setting, masked: e.g. `"http://user:***@127.0.0.1:3128"` — the password never leaves the store. A stored value that cannot be used reads `"invalid (…)"` and fails every request closed instead of going direct. Absent only for a direct account (no key at all). A request skipped this pass (see `owner_changed`) does not change this field. |
| `proxyExpectedCountry` | the account has an exit-country rule (`cswap proxy … --expect-country`) | ISO 3166-1 alpha-2, upper case, e.g. `"US"`. |
| `proxyExpectedIp` | the account has an exit-IP rule (`cswap proxy … --expect-ip`) | The canonical IPv4/IPv6 address, e.g. `"203.0.113.7"` or `"2001:db8::1"`. |
| `proxyExpected` | the stored rule is damaged (an explicit `null`, a non-string, an unparsable value) | `"invalid (…)"`, mirroring `proxy`; every launch of that account refuses closed. The two typed fields are absent in this case. |
| `plan` | the slot's subscription plan has been read from the profile endpoint at least once | `label` as the human views print it (`Ultra`, `Max 5x`, `Pro`, `Team`, `Free`), the raw `tier`, then `organizationType`, `billingType`, `subscriptionStatus` and `planDisplayName` when the profile carried them, `expired` (`true` once the subscription is `canceled` and the account is back on the free tier; the human views show that as a highlighted `Free`) and `fetchedAt`, the last successful profile read. Plans refresh on their own six-hour cadence, not with usage. |

## Pace fields on weekly windows

Weekly windows (`sevenDay` and per-model `scoped` entries, never `fiveHour`) additively carry pace fields once the week is about a day old.

| Field | Meaning |
|---|---|
| `expectedPct` | Where usage would sit if spread evenly across the week. |
| `aheadOfPace` | `true` when meaningfully above that: the same signal the human views show as an `(ahead)`/`(ahead of pace)` marker. |
| `projectedExhaustionAt` | The current rate extrapolated into an ETA to 100%. |
| `willLastToReset` | Whether the quota will last to the reset at the current rate. |

The two projections stay `--json`-only, since a linear projection is too rough to present as fact in the UI.

## `cswap auto --json`

`cswap auto --json` emits an event stream instead: one JSON object per line (`{"schemaVersion":1,"event":"switch","ts":…, …}`) with kinds like `poll`, `switch`, `no-switch`, `account-quarantined`, `all-exhausted`, `error`. The contract is additive: new kinds and fields may appear, so scripts should ignore unknown ones.

"""An account's expected exit country and IP, and the check that measures them.

An account may carry an egress expectation in its ``sequence.json`` record:
``proxy_expected_country`` (an ISO 3166-1 alpha-2 code) and/or
``proxy_expected_ip`` (an IPv4 or IPv6 address). Both are optional and set
with ``cswap proxy <num> [url] --expect-country CC --expect-ip IP``; they are
stored by :meth:`ClaudeAccountSwitcher.update_account_proxy` under the account
lock, and cleared with ``--unset-expect`` or by clearing the proxy itself.

The expectation is a promise about where that account's traffic leaves, and
:func:`check` measures it before a launch, strictly through the account's own
:class:`account_proxy.ProxyRoute`. There is no direct branch and no system
``*_PROXY``: an account with an expectation and no usable proxy is refused,
never checked directly. The check asks up to :data:`ENDPOINTS`' three public
GeoIP services in turn and reads only two fields of each answer — the exit IP
and the country. The first answer that carries a field the account expects
decides it: a different value is a refusal there and then, so the remaining
services are not asked. An answer that lacks a needed field, or a request that
fails (network, timeout, HTTP 4xx/5xx, invalid JSON, a redirect), moves on to
the next service; when none answers, the launch is refused with the
per-service reason. A redirect is not the proxy's fault once the request
travels an HTTPS tunnel: it is that service refusing to answer in place, so
the chain continues instead of stopping on a route that may still be fine.
Only a refused route (no connection, 407 on the ``CONNECT``, an unparsable
stored value) stops the chain, because every service would meet it.

No rule means no request and no delay: :func:`check` returns before it reads
an endpoint when :func:`read` gives it nothing, and ``check`` is the only
caller of the endpoints.

A stored value this module cannot read is damage, not "no rule": a
hand-edited ``null`` or a malformed code/address makes :func:`read` return an
expectation carrying ``error``, and :func:`check` refuses the launch instead
of skipping the rule. ``cswap list``/``status`` show it as
``invalid (…)``, the same convention the stored proxy uses.

The response fields differ per service and are fixed here: ipinfo's ``ip``
and ``country``, ipwho.is' ``ip`` and ``country_code``, and ifconfig.co's
``ip`` and ``country_iso``. The addresses are public and the requests carry
no token; only the proxy URL's credentials travel, on the tunnel.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass

from claude_swap.account_proxy import PROXY_REDIRECT, ProxyRoute, ProxyRouteError
from claude_swap.exceptions import EgressCheckError

#: The ``sequence.json`` account fields. Either one alone is a rule; both
#: absent means no check at all.
COUNTRY_FIELD = "proxy_expected_country"
IP_FIELD = "proxy_expected_ip"
FIELDS = (COUNTRY_FIELD, IP_FIELD)

#: Seconds one endpoint may take. Short because the check sits in front of a
#: launch: three unreachable services cost three such waits, not thirty.
TIMEOUT_S = 3.0

#: How much of an answer is read. These services answer with a few hundred
#: bytes; the cap keeps an unexpected body from being held in memory.
MAX_BODY_BYTES = 64 * 1024

#: The codes ISO 3166-1 assigns to a country, territory or special area: what
#: a rule and a service answer may name. User-assigned codes (``ZZ``, ``XK``),
#: unassigned pairs and anything longer are not countries, so a value outside
#: this set is never compared as one. Grouped for review against the
#: maintenance agency's list; membership is all the code uses.
ISO_COUNTRY_CODES = frozenset(
    """
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
    BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
    CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
    DE DJ DK DM DO DZ
    EC EE EG EH ER ES ET
    FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
    HK HM HN HR HT HU
    ID IE IL IM IN IO IQ IR IS IT
    JE JM JO JP
    KE KG KH KI KM KN KP KR KW KY KZ
    LA LB LC LI LK LR LS LT LU LV LY
    MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
    NA NC NE NF NG NI NL NO NP NR NU NZ
    OM
    PA PE PF PG PH PK PL PM PN PR PS PT PW PY
    QA
    RE RO RS RU RW
    SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
    TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
    UA UG UM US UY UZ
    VA VC VE VG VI VN VU
    WF WS
    YE YT
    ZA ZM ZW
    """.split()
)


class ExpectationError(ValueError):
    """A country or IP value that cannot be an expectation.

    The message is static text: the offending value is never repeated, so a
    hand-edited record cannot put arbitrary text (or a typo'd secret) into a
    command's output.
    """


def normalize_country(value: object) -> str:
    """``US`` for ``us``/``Us``; anything but an assigned code is refused.

    The stored form is upper case, so a comparison never depends on how the
    user typed the code. Two ASCII letters are not enough: ``ZZ`` is
    user-assigned and names no country, so a rule for it could never be
    confirmed by a service answer.
    """
    code = value.strip().upper() if isinstance(value, str) else ""
    if code not in ISO_COUNTRY_CODES:
        raise ExpectationError(
            "the expected country must be a two-letter ISO 3166-1 alpha-2 "
            "code assigned to a country"
        )
    return code


def normalize_ip(value: object) -> str:
    """The canonical spelling of an IPv4/IPv6 address, or a refusal.

    ``str(ipaddress.ip_address(...))`` is the canonical form: an IPv6 address
    is compressed and lower-cased, and an IPv4 address keeps no leading
    zeros, so two spellings of one address compare equal.

    An address carrying an IPv6 zone (``fe80::1%eth0``) is refused rather
    than canonicalised: ``ipaddress`` keeps the zone's text, and that text
    arrives from a stored record or a service's answer and would then be
    repeated in a refusal. Only the address itself is ever echoed.
    """
    if not isinstance(value, str) or not value.strip() or "%" in value:
        raise ExpectationError(
            "the expected IP must be a valid IPv4 or IPv6 address"
        )
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ExpectationError(
            "the expected IP must be a valid IPv4 or IPv6 address"
        ) from None


@dataclass(frozen=True)
class Expectation:
    """What an account promises about its exit, and how that went wrong."""

    country: str | None = None
    ip: str | None = None
    error: str | None = None

    @property
    def required(self) -> bool:
        """Whether a check has anything to confirm."""
        return self.error is not None or self.country is not None or self.ip is not None

    def text(self) -> str:
        """``country US, IP 1.2.3.4``, with only the parts that are set."""
        if self.error is not None:
            return f"invalid ({self.error})"
        parts = []
        if self.country is not None:
            parts.append(f"country {self.country}")
        if self.ip is not None:
            parts.append(f"IP {self.ip}")
        return ", ".join(parts)

    def mismatch(self, observation: "Observation") -> str | None:
        """The first expected value the observation contradicts, if any."""
        if (
            self.country is not None
            and observation.country is not None
            and observation.country != self.country
        ):
            return (
                f"the exit country is {observation.country}, but "
                f"{self.country} was expected"
            )
        if (
            self.ip is not None
            and observation.ip is not None
            and observation.ip != self.ip
        ):
            return (
                f"the exit IP is {observation.ip}, but {self.ip} was expected"
            )
        return None

    def missing(self, observation: "Observation") -> str:
        """The expected fields the observation did not carry, e.g. ``country``."""
        parts = []
        if self.country is not None and observation.country is None:
            parts.append("country")
        if self.ip is not None and observation.ip is None:
            parts.append("IP")
        return " and ".join(parts)


def read(record: Mapping | None) -> Expectation | None:
    """One record's expectation, or ``None`` when it has no rule.

    ``None`` is the absent-keys case only. A key that exists but does not hold
    a readable country/address yields an expectation with ``error`` set: the
    account may be subject to a rule, so skipping it is the one answer this
    module never gives.
    """
    if not isinstance(record, Mapping):
        return None
    has_country = COUNTRY_FIELD in record
    has_ip = IP_FIELD in record
    if not (has_country or has_ip):
        return None
    country = ip = None
    errors = []
    if has_country:
        try:
            country = normalize_country(record[COUNTRY_FIELD])
        except ExpectationError as e:
            errors.append(str(e))
    if has_ip:
        try:
            ip = normalize_ip(record[IP_FIELD])
        except ExpectationError as e:
            errors.append(str(e))
    return Expectation(country=country, ip=ip, error="; ".join(errors) or None)


def describe(record: Mapping | None) -> str | None:
    """The human line for a record's expectation, or ``None`` without one."""
    expected = read(record)
    if expected is None:
        return None
    if expected.error is not None:
        return f"invalid ({expected.error})"
    return "expects " + expected.text()


def json_fields(record: Mapping | None) -> dict:
    """The additive ``--json`` fields for a record's expectation.

    Absent without a rule. A damaged rule is one field carrying ``invalid
    (…)`` instead of two typed values, mirroring the stored proxy's field.
    """
    expected = read(record)
    if expected is None:
        return {}
    if expected.error is not None:
        return {"proxyExpected": f"invalid ({expected.error})"}
    fields = {}
    if expected.country is not None:
        fields["proxyExpectedCountry"] = expected.country
    if expected.ip is not None:
        fields["proxyExpectedIp"] = expected.ip
    return fields


@dataclass(frozen=True)
class Endpoint:
    """One public GeoIP service, and where its answer keeps the two values."""

    url: str
    ip_field: str = "ip"
    country_field: str = "country"


#: The chain, in the order it is asked. Public JSON endpoints with no key and
#: no account; each names a different field for the country code.
ENDPOINTS = (
    Endpoint("https://ipinfo.io/json"),
    Endpoint("https://ipwho.is/", country_field="country_code"),
    Endpoint("https://ifconfig.co/json", country_field="country_iso"),
)


@dataclass(frozen=True)
class Observation:
    """What one answer said about the exit, in canonical form."""

    ip: str | None = None
    country: str | None = None


class _EndpointFailed(Exception):
    """This service did not give a usable answer; ask the next one."""


def _host(endpoint: Endpoint) -> str:
    return urllib.parse.urlsplit(endpoint.url).hostname or endpoint.url


def _observe(endpoint: Endpoint, route: ProxyRoute, timeout: float) -> Observation:
    """Read one endpoint through ``route`` and project its two fields.

    Raises:
        ProxyRouteError: the route cannot be used. It is the same failure for
            every endpoint, so the caller stops instead of retrying it.
        _EndpointFailed: this endpoint's answer cannot be used; the next one
            may.
    """
    request = urllib.request.Request(
        endpoint.url,
        headers={
            "Accept": "application/json",
            "User-Agent": "claude-swap",
        },
    )
    try:
        with route.open(request, timeout=timeout) as response:
            raw = response.read(MAX_BODY_BYTES)
    except ProxyRouteError as e:
        if e.kind == PROXY_REDIRECT:
            # Over an HTTPS tunnel this is the service's own 3xx, not the
            # proxy's: it refuses to answer in place, and the next service may
            # still answer. The redirect is still not followed.
            raise _EndpointFailed("redirect") from None
        raise
    except urllib.error.HTTPError as e:
        e.close()
        raise _EndpointFailed(f"HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise _EndpointFailed(
            "timeout" if isinstance(e.reason, TimeoutError) else "network error"
        ) from None
    except TimeoutError:
        raise _EndpointFailed("timeout") from None
    except OSError:
        raise _EndpointFailed("network error") from None
    except http.client.HTTPException:
        # A truncated reply is this service's answer, not the route's: the
        # next one may still answer.
        raise _EndpointFailed("invalid HTTP reply") from None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        # A deeply nested body is not JSON this module can use, and it is this
        # service's answer, not the route's.
        raise _EndpointFailed("invalid JSON") from None
    if not isinstance(data, dict) or data.get("success") is False:
        raise _EndpointFailed("no usable answer")

    ip = None
    raw_ip = data.get(endpoint.ip_field)
    if isinstance(raw_ip, str):
        try:
            ip = normalize_ip(raw_ip)
        except ExpectationError:
            ip = None
    country = None
    raw_country = data.get(endpoint.country_field)
    if isinstance(raw_country, str):
        try:
            country = normalize_country(raw_country)
        except ExpectationError:
            country = None
    if ip is None and country is None:
        raise _EndpointFailed("no usable IP or country")
    return Observation(ip=ip, country=country)


def check(
    route: ProxyRoute | None,
    expectation: Expectation | None,
    timeout: float = TIMEOUT_S,
) -> None:
    """Refuse unless the account's exit matches ``expectation``.

    Does nothing when there is no expectation, so an account without a rule
    causes no request and no delay. With a rule the request travels
    ``route`` only: no proxy is a refusal, never a direct check, and the
    route's own unusable/auth/redirect failures are refusals too.

    A service whose answer carries an expected field with a different value
    ends the check immediately; the last refusal names both values and never
    the proxy URL or its credentials.

    Raises:
        EgressCheckError: the rule is damaged, the route cannot be used, a
            service contradicted the rule, or no service produced a usable
            answer.
    """
    if expectation is None or not expectation.required:
        return
    if expectation.error is not None:
        raise EgressCheckError(
            "the account's egress expectation is unusable: "
            f"{expectation.error}"
        )
    if route is None:
        raise EgressCheckError(
            "the account has an egress expectation but no proxy, so its exit "
            "cannot be checked without a direct connection"
        )

    failures: list[str] = []
    for endpoint in ENDPOINTS:
        try:
            observation = _observe(endpoint, route, timeout)
        except ProxyRouteError as e:
            raise EgressCheckError(
                f"the account's proxy could not be used for the egress check: {e}"
            ) from None
        except _EndpointFailed as e:
            failures.append(f"{_host(endpoint)}: {e}")
            continue
        mismatch = expectation.mismatch(observation)
        if mismatch is not None:
            raise EgressCheckError(mismatch)
        missing = expectation.missing(observation)
        if missing:
            failures.append(f"{_host(endpoint)}: no usable {missing}")
            continue
        return
    raise EgressCheckError(
        "no GeoIP endpoint could confirm the account's exit: "
        + "; ".join(failures)
    )

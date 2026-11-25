"""The per-account HTTP proxy claude-swap's own requests travel through.

An account may carry a proxy (``cswap proxy <slot> <url>``, ``cswap add
--proxy <url>``). Every request claude-swap makes *for that account* — the
usage fetch, the token refresh and its retries, the profile read, the plan
read — then goes through that proxy or not at all. ``update_check`` keeps its
own path: it is not an account's traffic.

A route is pinned rather than negotiated:

- the proxy comes from the slot's record in ``sequence.json``, never from
  ``HTTP_PROXY``/``HTTPS_PROXY``/``ALL_PROXY`` or the platform's proxy
  settings;
- ``NO_PROXY``/``no_proxy`` is not consulted at all: a bypass there would
  turn the same request into a direct connection;
- redirects are refused. urllib rebuilds a redirected request from scratch,
  which would drop the tunnel and go direct;
- an unreachable proxy, a 407, or a stored value that does not parse is an
  error the caller reports — never a fallback to a direct connection.

Only ``http://`` proxies are accepted. urllib can tunnel an HTTPS request
through an HTTP proxy (``CONNECT``), but cannot speak TLS to the proxy
itself, so an ``https://`` value would only fail later, once per request.
Credentials are optional (``http://user:pass@host:port``) and travel as
``Proxy-Authorization`` on the tunnel; the account's own OAuth token and the
API keys are never sent to the proxy.

How the request is placed on the route, measured with CPython 3.14's
``urllib.request`` (3.12–3.14 share this code): :meth:`Request.set_proxy`
with the proxy's address sets ``_tunnel_host`` for an ``https`` target and
rewrites ``host``/``selector`` to an absolute URL for an ``http`` one;
``AbstractHTTPHandler.do_open`` moves ``Proxy-Authorization`` from the
origin's headers into the ``CONNECT`` headers, so the header never reaches
the origin. Both halves are exercised in ``tests/test_account_proxy.py``
against a local proxy: an absolute-form ``http://`` request and a ``CONNECT``
tunnel. A refused tunnel (407, a redirect) reaches ``open`` as a ``URLError``
carrying http.client's own phrase, and is re-raised as the same
``ProxyRouteError`` kinds with that phrase dropped — it is the proxy's text
and may name a credential.

The stored value keeps the password in ``sequence.json`` (mode 0600, written
atomically by the switcher), because cswap has to present it. It is masked
wherever it leaves the process, and it never enters an export; see
:func:`describe` and ``docs/json-output.md``.
"""

from __future__ import annotations

import base64
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

#: The ``sequence.json`` account field. Absent means "direct", which is how
#: every account behaved before this setting existed.
FIELD = "proxy"

#: Default port of an ``http://`` proxy URL without one.
DEFAULT_PORT = 80

#: ``ProxyRouteError.kind`` values. They reach the usage store as
#: ``last_error``, so they are stable tokens (see ``ERROR_NOTES`` in
#: ``switcher.py`` for the user-facing remedy of each).
PROXY_INVALID = "proxy-invalid"
PROXY_AUTH = "proxy-auth"
PROXY_REDIRECT = "proxy-redirect"


class ProxyUrlError(ValueError):
    """A proxy URL that cannot be used. The message never repeats a password."""


class ProxyRouteError(Exception):
    """A request that could not be placed on its route.

    ``kind`` is one of :data:`PROXY_INVALID`, :data:`PROXY_AUTH`,
    :data:`PROXY_REDIRECT`, and is what the callers report instead of the
    network outcome — none of these may be retried directly.
    """

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect instead of following it.

    ``redirect_request`` returning None is urllib's documented way to stop a
    redirect: the reply continues down the handler chain and surfaces as the
    original ``HTTPError``, which :meth:`ProxyRoute.open` turns into a
    :data:`PROXY_REDIRECT` failure.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class ProxyRoute:
    """One account's proxy, parsed and pinned.

    ``invalid`` is set instead of the address when a stored value does not
    parse: the record was hand-edited or written by a version that accepted
    something else. Such a route fails every request with
    :data:`PROXY_INVALID` rather than falling back to a direct connection, so
    a corrupted setting can never silently un-proxy an account.
    """

    host: str = ""
    port: int = DEFAULT_PORT
    username: str | None = None
    password: str | None = None
    invalid: str | None = None

    @property
    def authorization(self) -> str | None:
        """The ``Proxy-Authorization`` value, or None when the URL had no user."""
        if self.username is None:
            return None
        pair = f"{self.username}:{self.password or ''}".encode()
        return "Basic " + base64.b64encode(pair).decode("ascii")

    def text(self) -> str:
        """The canonical stored form (credentials included, still secret).

        Re-encoded from the parsed parts, so ``--proxy`` typing variations
        (an extra slash, upper-case scheme, an unscaped ``@`` in the password,
        an omitted ``:80``) all store one spelling.
        """
        userinfo = ""
        if self.username is not None:
            userinfo = urllib.parse.quote(self.username, safe="")
            if self.password:
                userinfo += ":" + urllib.parse.quote(self.password, safe="")
            userinfo += "@"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{userinfo}{host}:{self.port}"

    def display(self) -> str:
        """The form shown to people: same URL with the password masked.

        Also used for an unusable stored value, which is shown as an error
        rather than echoed — it may hold a password in a shape the parser
        could not be sure about.
        """
        if self.invalid is not None:
            return f"invalid ({self.invalid})"
        userinfo = ""
        if self.username is not None:
            userinfo = urllib.parse.quote(self.username, safe="") + ":***@"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{userinfo}{host}:{self.port}"

    def open(self, request: urllib.request.Request, timeout: float = 5.0):
        """Send ``request`` through this proxy, refusing to go direct.

        The request is modified in place (proxy address, absolute URL or
        tunnel, ``Proxy-Authorization``), so a caller must pass a request it
        built for this one attempt — every caller in ``oauth.py`` and
        ``subscription.py`` does.

        Raises:
            ProxyRouteError: the stored value is unusable, the proxy asked for
                credentials it rejected (407), or it redirected. Transport
                failures of the connection itself stay ``URLError``/
                ``HTTPError``, so the existing classification (timeout,
                certificate, network) keeps working.
        """
        if self.invalid is not None:
            raise ProxyRouteError(
                PROXY_INVALID,
                f"the account's proxy setting is unusable: {self.invalid}",
            )
        request.set_proxy(f"{self.host}:{self.port}", "http")
        authorization = self.authorization
        if authorization is not None:
            request.add_header("Proxy-Authorization", authorization)
        try:
            return _opener().open(request, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code == 407:
                raise ProxyRouteError(
                    PROXY_AUTH,
                    "the proxy rejected the credentials in its URL (HTTP 407)",
                ) from None
            if 300 <= e.code < 400:
                raise ProxyRouteError(
                    PROXY_REDIRECT,
                    f"the proxy answered HTTP {e.code} instead of forwarding "
                    "the request",
                ) from None
            raise
        except urllib.error.URLError as e:
            # An ``https`` request travels a CONNECT tunnel, and http.client
            # reports a refusal of that tunnel as ``OSError("Tunnel
            # connection failed: <code> <phrase>")`` — urllib wraps it in
            # ``URLError``, so the HTTPError handler above never sees it
            # (measured on CPython 3.12-3.14). The phrase is the proxy's own
            # text and can name a credential, so only the code survives this
            # boundary; the rest of the message is ours.
            status = _tunnel_status(e.reason)
            if status is None:
                raise
            if status == "407":
                raise ProxyRouteError(
                    PROXY_AUTH,
                    "the proxy rejected the credentials in its URL "
                    "(HTTP 407 to CONNECT)",
                ) from None
            if status.isdigit() and 300 <= int(status) < 400:
                raise ProxyRouteError(
                    PROXY_REDIRECT,
                    f"the proxy answered HTTP {status} to CONNECT instead of "
                    "opening the tunnel",
                ) from None
            raise urllib.error.URLError(
                f"the proxy refused the CONNECT tunnel (HTTP {status})"
                if status.isdigit()
                else "the proxy refused the CONNECT tunnel"
            ) from None


_TUNNEL_REFUSED = "Tunnel connection failed: "


def _tunnel_status(reason: object) -> str | None:
    """The status of a refused CONNECT tunnel, from http.client's message.

    ``HTTPConnection._tunnel`` raises ``OSError`` whose message is "Tunnel
    connection failed: <code> <phrase>" for every reply other than 200, and
    only the leading code is kept: the phrase is the proxy's text, which this
    module never repeats. Anything else — a refused connection, a timeout —
    is not a tunnel reply and returns None.
    """
    if not isinstance(reason, OSError):
        return None
    text = str(reason)
    if not text.startswith(_TUNNEL_REFUSED):
        return None
    return text[len(_TUNNEL_REFUSED):].split(" ", 1)[0]


def parse(text: str) -> ProxyRoute:
    """Parse ``http://[user[:pass]@]host[:port]`` into a :class:`ProxyRoute`.

    Raises:
        ProxyUrlError: anything else. The message names what is wrong and
            never includes the value, which may carry a password.
    """
    raw = text.strip() if isinstance(text, str) else ""
    if not raw:
        raise ProxyUrlError("a proxy URL is required")
    if "://" not in raw:
        raise ProxyUrlError(
            "a proxy URL must include a scheme, e.g. http://host:3128"
        )
    if raw.split("://", 1)[0].lower() != "http":
        # Static: whatever precedes ``://`` may be a mistyped scheme with a
        # credential in it, and this text reaches the log and the JSON.
        raise ProxyUrlError(
            "only http:// proxies are supported (the URL's scheme must be http)"
        )
    try:
        parts = urllib.parse.urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ProxyUrlError(
            "the proxy URL is not a valid URL (check the host and the port)"
        ) from None
    if not host:
        raise ProxyUrlError("the proxy URL has no host")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ProxyUrlError(
            "the proxy URL must be only scheme, host and port "
            "(no path, query or fragment)"
        )
    if port is None:
        port = DEFAULT_PORT
    if not 1 <= port <= 65535:
        raise ProxyUrlError("the proxy port must be between 1 and 65535")
    username = (
        urllib.parse.unquote(parts.username) if parts.username else None
    )
    password = (
        urllib.parse.unquote(parts.password)
        if parts.password is not None
        else None
    )
    if password is not None and username is None:
        raise ProxyUrlError("a proxy password needs a user name before it")
    return ProxyRoute(host=host, port=port, username=username, password=password)


def unusable(reason: str) -> ProxyRoute:
    """A route that fails every request, for a setting that cannot be read."""
    return ProxyRoute(invalid=reason)


def route_for(record: Mapping | None) -> ProxyRoute | None:
    """The route of one ``sequence.json`` account record.

    ``None`` means the account has no proxy (absent field) — the direct
    connection it always had. A field that exists but does not parse yields
    an unusable route: the account *may* be proxied, so guessing "no proxy"
    is the one answer this module never gives.
    """
    if not isinstance(record, Mapping):
        return None
    if FIELD not in record:
        # Absent is the only shape that means "direct": it is how every
        # account behaved before this setting existed, and how ``--unset``
        # leaves a record. An explicit JSON ``null`` is damage — a hand edit
        # or a writer that did not know the field — and must not read as a
        # cleared setting, which would send the account direct.
        return None
    raw = record[FIELD]
    if not isinstance(raw, str) or not raw.strip():
        return unusable("the stored value is not a URL")
    try:
        return parse(raw)
    except ProxyUrlError as e:
        return unusable(str(e))


def describe(record: Mapping | None) -> str | None:
    """The masked form of a record's proxy, or None when it has none."""
    route = route_for(record)
    return None if route is None else route.display()


#: A URL, with a scheme or with credentials but no scheme: the two shapes a
#: proxy value takes when someone mistypes it into a command line.
_URL_SHAPED = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s'\"]+")
_USERINFO_SHAPED = re.compile(r"\b[^\s:/@'\"]+:[^\s/@'\"]+@[^\s'\"]+")


def redact_urls(text: str, values: Iterable[str] = ()) -> str:
    """``text`` with every URL-shaped run replaced by a static ``<URL>``.

    For the diagnostics of the two commands that accept a proxy URL: argparse
    formats the offending value into its own errors (an extra positional, a
    value attached to a flag, a failed integer conversion), and the identifier
    message does too — any of which may be ``http://user:password@host``.

    ``values`` are the command line's own tokens. A password is arbitrary
    text, spaces included, and the patterns below end at the first space, so a
    token that is itself URL-shaped is removed whole first — including the
    part after ``=``, which is the shape argparse echoes for a value attached
    to a flag. Tokens that are not URL-shaped are left alone.
    """
    for value in values:
        for token in (value, value.partition("=")[2]):
            if _URL_SHAPED.match(token) or _USERINFO_SHAPED.search(token):
                text = text.replace(token, "<URL>")
    return _USERINFO_SHAPED.sub("<URL>", _URL_SHAPED.sub("<URL>", text))


def send(
    request: urllib.request.Request,
    timeout: float,
    route: ProxyRoute | None,
):
    """Send ``request`` on ``route``, or directly when the account has none.

    The single entry point of every network call in ``oauth.py`` and
    ``subscription.py``: the direct branch is the ``route is None`` case only,
    so a proxied account cannot reach the network any other way.
    """
    if route is None:
        return urllib.request.urlopen(request, timeout=timeout)
    return route.open(request, timeout=timeout)


def _opener() -> urllib.request.OpenerDirector:
    """The opener every proxied request uses.

    ``ProxyHandler({})`` is passed explicitly: ``build_opener`` would
    otherwise install one from the environment, which is the fallback this
    module exists to close. Building it twice under a race is harmless (both
    are stateless), so there is no lock around the cache.
    """
    global _OPENER
    if _OPENER is None:
        _OPENER = urllib.request.build_opener(
            _NoRedirects(), urllib.request.ProxyHandler({})
        )
    return _OPENER


_OPENER: urllib.request.OpenerDirector | None = None

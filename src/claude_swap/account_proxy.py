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

Four schemes are accepted. ``http://`` is the direct one: urllib tunnels an
HTTPS request through it (``CONNECT``) by itself. ``https://`` and
``socks5h://``/``socks5://`` are schemes urllib cannot speak, so a request on
one of them runs through ``proxy_bridge`` — a local HTTP proxy on
``127.0.0.1:0`` that talks to the account's real proxy and copies the bytes
(see :func:`bridge` and the module docstring of ``proxy_bridge.py``). The
schemes with no such transport are refused when the value is stored.
Credentials are optional (``user:pass@`` in any of them) and travel as
``Proxy-Authorization`` on an HTTP tunnel, or by RFC 1929 to a SOCKS5 proxy;
the account's own OAuth token and the API keys are never sent to the proxy.

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

The same route serves a launch, in two more shapes. :func:`probe` is the
pre-start check: one tunnel to :data:`PROBE_TARGET`, so an unreachable or
misconfigured proxy refuses the launch before Claude Code starts.
:func:`launch_env` is the other half — the variables Claude Code reads a proxy
from, written in both spellings over whatever the shell carried. For a scheme
that needs the bridge those variables carry the bridge's loopback address, not
the account's URL: the proxy password never enters the child's environment,
and the bridge lives exactly as long as the child (:func:`bridge`). Nothing
here forbids a direct connection at the OS level, so a program that ignores
these variables still goes out directly (``docs/proxy.md``).
"""

from __future__ import annotations

import base64
import http.client
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from claude_swap import proxy_bridge

#: The ``sequence.json`` account field. Absent means "direct", which is how
#: every account behaved before this setting existed.
FIELD = "proxy"

#: Default port of each accepted scheme, for a URL without one.
DEFAULT_PORTS = {"http": 80, "https": 443, "socks5h": 1080, "socks5": 1080}

#: The schemes urllib cannot speak and ``proxy_bridge`` therefore carries.
#: ``socks5://`` is an alias of ``socks5h://``: this module only ever sends the
#: target as a domain, so both mean "remote DNS".
BRIDGED_SCHEMES = frozenset({"https", "socks5h", "socks5"})

#: ``ProxyRouteError.kind`` values. They reach the usage store as
#: ``last_error``, so they are stable tokens (see ``ERROR_NOTES`` in
#: ``switcher.py`` for the user-facing remedy of each).
PROXY_INVALID = "proxy-invalid"
PROXY_AUTH = "proxy-auth"
PROXY_REDIRECT = "proxy-redirect"
#: The launch's pre-start probe got no usable answer: nothing listening, no
#: name resolution, a timeout, or a CONNECT status of the proxy's own. It
#: never reaches a usage row — the probe runs before a launch and its message
#: is that launch's error.
PROXY_UNREACHABLE = "proxy-unreachable"

#: Seconds the launch's one ``CONNECT`` may take; the same budget
#: :meth:`ProxyRoute.open` gives each request.
PROBE_TIMEOUT_S = 5.0

#: What the probe asks the proxy to open a tunnel to: the endpoint every
#: Claude Code run needs.
PROBE_TARGET = ("api.anthropic.com", 443)

#: The variables a launch sets for a proxied account, and drops from what the
#: shell carried. ``NO_PROXY`` included: an inherited ``NO_PROXY=*`` would
#: switch the account's proxy off.
LAUNCH_ENV_NAMES = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY")


class ProxyUrlError(ValueError):
    """A proxy URL that cannot be used. The message never repeats a password."""


class ProxyRouteError(Exception):
    """A request that could not be placed on its route.

    ``kind`` is one of :data:`PROXY_INVALID`, :data:`PROXY_AUTH`,
    :data:`PROXY_REDIRECT`, and is what the callers report instead of the
    network outcome — none of these may be retried directly.
    """

    def __init__(self, kind: str, message: str, status: int | None = None):
        super().__init__(message)
        self.kind = kind
        #: The HTTP status the proxy refused a ``CONNECT`` with, when that is
        #: what happened: the code, never the proxy's phrase. ``egress.py``
        #: reports it as ``CONNECT HTTP <code>`` and nothing here repeats it.
        self.status = status


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
    port: int = DEFAULT_PORTS["http"]
    username: str | None = None
    password: str | None = None
    invalid: str | None = None
    scheme: str = "http"

    @property
    def needs_bridge(self) -> bool:
        """Whether this route's requests travel a local ``proxy_bridge``.

        An ``http://`` route (and an unusable one, which raises before it gets
        this far) keeps the direct ``urllib`` path it always had.
        """
        return self.scheme in BRIDGED_SCHEMES

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
        return f"{self.scheme}://{userinfo}{host}:{self.port}"

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
        return f"{self.scheme}://{userinfo}{host}:{self.port}"

    def open(self, request: urllib.request.Request, timeout: float = 5.0):
        """Send ``request`` through this proxy, refusing to go direct.

        The request is modified in place (proxy address, absolute URL or
        tunnel, ``Proxy-Authorization``), so a caller must pass a request it
        built for this one attempt — every caller in ``oauth.py`` and
        ``subscription.py`` does.

        An ``http://`` route is handed to urllib as it always was. The other
        schemes run through a :func:`bridge` opened for this one request: the
        request goes to the loopback address, and the bridge speaks to the
        account's real proxy.

        Raises:
            ProxyRouteError: the stored value is unusable, the proxy asked for
                credentials it rejected (407), or it redirected. Transport
                failures of the connection itself stay ``URLError``/
                ``HTTPError``, so the existing classification (timeout,
                certificate, network) keeps working.
            ssl.SSLCertVerificationError: the ``https://`` proxy's own
                certificate was refused; nothing touches the target.
        """
        if self.invalid is not None:
            raise ProxyRouteError(
                PROXY_INVALID,
                f"the account's proxy setting is unusable: {self.invalid}",
            )
        if self.needs_bridge:
            return self._open_through_bridge(request, timeout)
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
                    status=e.code,
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
            status = tunnel_status(e.reason)
            if status is None:
                raise
            if status == "407":
                raise ProxyRouteError(
                    PROXY_AUTH,
                    "the proxy rejected the credentials in its URL "
                    "(HTTP 407 to CONNECT)",
                    status=407,
                ) from None
            if status.isdigit() and 300 <= int(status) < 400:
                raise ProxyRouteError(
                    PROXY_REDIRECT,
                    f"the proxy answered HTTP {status} to CONNECT instead of "
                    "opening the tunnel",
                    status=int(status),
                ) from None
            raise urllib.error.URLError(
                f"the proxy refused the CONNECT tunnel (HTTP {status})"
                if status.isdigit()
                else "the proxy refused the CONNECT tunnel"
            ) from None

    def _open_through_bridge(
        self, request: urllib.request.Request, timeout: float
    ):
        """``open`` for a scheme urllib cannot speak: one bridge, one request.

        The local client only ever sees a status code, so the bridge keeps the
        typed upstream failure for this process: ``URLError`` after a refused
        tunnel is replaced by the proxy's own error kind (and an
        ``https://`` proxy's refused certificate by the TLS error itself),
        which is what the token and usage classifications read.

        A returned response carries the bridge (see :class:`_BridgedResponse`):
        ``open`` comes back once the reply's head has arrived, and its body
        still travels that bridge. A request that produces no response closes
        the bridge here instead, so nothing outlives it.
        """
        local = proxy_bridge.Bridge(self, timeout=timeout)
        request.set_proxy(f"{local.host}:{local.port}", "http")
        try:
            response = _opener().open(request, timeout=timeout)
        except urllib.error.HTTPError as e:
            # The error is not handed on with a readable body — its bridge is
            # closing — so it is closed here instead of being left to the
            # garbage collector; only its code and headers travel.
            e.close()
            # Closed before the failure is read: ``close`` joins the workers,
            # so whatever the bridge recorded has been recorded by now.
            local.close()
            raise_failure(local.failure)
            if e.code == 407:
                raise ProxyRouteError(
                    PROXY_AUTH,
                    "the proxy rejected the credentials in its URL "
                    "(HTTP 407)",
                    status=407,
                ) from None
            if 300 <= e.code < 400:
                raise ProxyRouteError(
                    PROXY_REDIRECT,
                    f"the proxy answered HTTP {e.code} instead of "
                    "forwarding the request",
                    status=e.code,
                ) from None
            raise
        except urllib.error.URLError:
            local.close()
            raise_failure(local.failure)
            raise
        except BaseException:
            local.close()
            raise
        return _BridgedResponse(response, local)


_TUNNEL_REFUSED = "Tunnel connection failed: "

#: :meth:`ProxyRoute.open`'s own sentence for a tunnel the proxy answered with
#: another status. Re-read by :func:`tunnel_status`, so the code survives even
#: though the proxy's phrase does not.
_OUR_TUNNEL_REFUSAL = re.compile(
    r"^the proxy refused the CONNECT tunnel \(HTTP (\d{3})\)$"
)


def tunnel_status(reason: object) -> str | None:
    """The status of a refused CONNECT tunnel, from a failure's own text.

    ``HTTPConnection._tunnel`` raises ``OSError`` whose message is "Tunnel
    connection failed: <code> <phrase>" for every reply other than 200, and
    only the leading code is kept: the phrase is the proxy's text, which this
    module never repeats. Reading a reply through urllib ends with that
    ``OSError`` as a ``URLError``'s reason, while :meth:`ProxyRoute.open`
    re-raises a 4xx/5xx refusal as a ``URLError`` whose reason is this
    module's own static sentence — both shapes are read here, and neither can
    carry the proxy's phrase.

    ``egress.check`` reads the code the same way, so a refused tunnel is
    reported as ``CONNECT HTTP <code>`` rather than a bare network failure.
    Anything else — a refused connection, a timeout — is not a tunnel reply
    and returns None.
    """
    if isinstance(reason, OSError):
        text = str(reason)
        if text.startswith(_TUNNEL_REFUSED):
            return text[len(_TUNNEL_REFUSED):].split(" ", 1)[0]
        return None
    if isinstance(reason, str):
        match = _OUR_TUNNEL_REFUSAL.match(reason)
        if match is not None:
            return match.group(1)
    return None


#: A bridge failure's kind, in this module's stable ``ProxyRouteError`` tokens.
_BRIDGE_ERROR_KINDS = {"auth": PROXY_AUTH, "redirect": PROXY_REDIRECT}


def raise_failure(failure: BaseException | None) -> None:
    """Re-raise a bridge's recorded upstream error in this module's terms.

    ``proxy_bridge`` keeps the typed failure because a local HTTP client only
    ever receives a status code. Nothing is lost across that hop: an
    ``https://`` proxy's refused certificate is re-raised as itself (the
    ``tls-cert`` classification and ``_NEVER_SENT`` read it), and a refused
    tunnel becomes the same :class:`ProxyRouteError` kind the direct path
    raises, with the proxy's own phrase dropped.

    Returns normally when the bridge recorded no failure: the request failed
    after the tunnel was opened, and that answer belongs to the caller.
    """
    if failure is None:
        return
    if isinstance(failure, ssl.SSLError):
        raise failure
    if isinstance(failure, proxy_bridge.BridgeError):
        raise ProxyRouteError(
            _BRIDGE_ERROR_KINDS.get(failure.kind, PROXY_UNREACHABLE),
            str(failure),
            status=failure.status,
        ) from None
    raise ProxyRouteError(
        PROXY_UNREACHABLE,
        "the account's proxy could not be used for this request",
    ) from None


class _BridgedResponse:
    """A bridged request's response, with its bridge in tow.

    ``urllib`` returns from ``open`` as soon as the head of the reply has
    arrived; the rest of the body is still behind it and travels the bridge.
    The bridge therefore lives exactly as long as the response does — the same
    lifetime ``with route.open(...)`` gives it — and closing the response
    closes it, so neither the loopback listener nor its threads outlive a
    request. Nothing else about the response changes; every attribute is the
    wrapped one's.
    """

    def __init__(self, response, local: proxy_bridge.Bridge):
        self._response = response
        self._bridge = local

    def __getattr__(self, name: str):
        return getattr(self._response, name)

    def __enter__(self) -> "_BridgedResponse":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        """Close the response and the bridge that carried it."""
        try:
            self._response.close()
        finally:
            self._bridge.close()


@contextmanager
def bridge(
    route: "ProxyRoute | None", timeout: float = proxy_bridge.TIMEOUT_S
) -> Iterator["proxy_bridge.Bridge | None"]:
    """A local HTTP proxy for a route that needs one, and nothing otherwise.

    Yields ``None`` for a direct or ``http://`` account, so a caller can wrap a
    request or a launch unconditionally and only the schemes that need the
    bridge pay for it. The bridge is closed — its listener, every live
    connection and its threads — when the block ends, whether it returned or
    raised.
    """
    if route is None or not route.needs_bridge:
        yield None
        return
    with proxy_bridge.Bridge(route, timeout=timeout) as instance:
        yield instance


def parse(text: str) -> ProxyRoute:
    """Parse ``scheme://[user[:pass]@]host[:port]`` into a :class:`ProxyRoute`.

    ``http`` (port 80), ``https`` (443), ``socks5h`` and its alias ``socks5``
    (1080) are the accepted schemes.

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
    scheme = raw.split("://", 1)[0].lower()
    if scheme not in DEFAULT_PORTS:
        # Static: whatever precedes ``://`` may be a mistyped scheme with a
        # credential in it, and this text reaches the log and the JSON.
        raise ProxyUrlError(
            "the proxy URL's scheme must be one of http, https, socks5h or "
            "socks5 (e.g. http://host:3128)"
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
        port = DEFAULT_PORTS[scheme]
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
    return ProxyRoute(
        host=host,
        port=port,
        username=username,
        password=password,
        scheme=scheme,
    )


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


def probe(route: ProxyRoute, timeout: float = PROBE_TIMEOUT_S) -> None:
    """Ask ``route``'s proxy to open one tunnel to :data:`PROBE_TARGET`.

    The launch's pre-start check, and the only request here that sends nothing
    to an origin: one ``CONNECT api.anthropic.com:443`` carrying the URL's
    credentials, no TLS handshake and no token. A 200 proves the proxy is
    listening, speaks the proxy protocol, accepted those credentials, and
    could reach that target itself. It does not prove TLS survives the proxy,
    that the proxy allows the other hosts Claude Code may use, or that it stays
    up for the session; those fail during the session instead.

    ``http.client`` reports a refused tunnel as an ``OSError`` whose message is
    "Tunnel connection failed: <code> <phrase>" — the shape
    :meth:`ProxyRoute.open` already classifies through urllib — so
    :func:`tunnel_status` reads both and the proxy's own phrase never travels
    on: it may name a credential. Everything else ``http.client`` raises on the
    way to that reply is turned into one static message here: ``BadStatusLine``
    when the port speaks another protocol carries that reply's first line, and
    ``InvalidURL``/``UnicodeError`` when the stored address cannot be turned
    into a connection would otherwise surface as a traceback (measured on
    CPython 3.14).

    For a scheme urllib cannot speak, the one tunnel is opened by
    ``proxy_bridge`` instead — the same step the bridge takes for every
    request it carries — and its typed failure comes back as the same kinds.
    A refused ``https://`` proxy certificate is a refusal here, not a
    ``ProxyRouteError`` detail: the launch has nowhere else to go.

    Raises:
        ProxyRouteError: the stored value is unusable, the proxy rejected the
            credentials (407), redirected, answered with another status, could
            not be reached at all, or did not answer a proxy reply.
    """
    if route.invalid is not None:
        raise ProxyRouteError(
            PROXY_INVALID,
            f"the account's proxy setting is unusable: {route.invalid}",
        )
    if route.needs_bridge:
        _probe_through_bridge(route, timeout)
        return
    headers = (
        {"Proxy-Authorization": route.authorization}
        if route.authorization is not None
        else {}
    )
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            route.host, route.port, timeout=timeout
        )
        connection.set_tunnel(*PROBE_TARGET, headers=headers)
        connection.connect()
    except OSError as e:
        status = tunnel_status(e)
        if status == "407":
            raise ProxyRouteError(
                PROXY_AUTH,
                "the proxy rejected the credentials in its URL (HTTP 407)",
                status=407,
            ) from None
        if status is not None and status.isdigit():
            if 300 <= int(status) < 400:
                raise ProxyRouteError(
                    PROXY_REDIRECT,
                    f"the proxy answered HTTP {status} to CONNECT instead of "
                    "opening the tunnel",
                    status=int(status),
                ) from None
            raise ProxyRouteError(
                PROXY_UNREACHABLE,
                f"the proxy answered HTTP {status} to CONNECT instead of "
                "opening the tunnel",
                status=int(status),
            ) from None
        # Not a tunnel reply: refused, unresolvable, timed out. The socket's
        # own text names the address at most, never the URL's credentials.
        raise ProxyRouteError(
            PROXY_UNREACHABLE, f"the proxy did not accept a connection ({e})"
        ) from None
    except (http.client.HTTPException, UnicodeError):
        # A reply that is not HTTP at all (another protocol listening on the
        # port) or an address no connection can be built from. Both carry text
        # the launch must not repeat: the bad status line *is* the proxy's
        # answer, and the URL exception quotes the host.
        raise ProxyRouteError(
            PROXY_UNREACHABLE,
            "the proxy's address or its reply is unusable",
        ) from None
    finally:
        if connection is not None:
            connection.close()


def _probe_through_bridge(route: ProxyRoute, timeout: float) -> None:
    """``probe`` for a scheme the account's proxy has to be reached for.

    One tunnel and nothing else: no local server, no request, no TLS to the
    target. A ``https://`` proxy's refused certificate and every transport
    failure are refusals of the launch, so they arrive as
    :data:`PROXY_UNREACHABLE` with static text — the certificate's own message
    names the proxy's host at most, never its URL or password.
    """
    tunnel: object = None
    try:
        tunnel = proxy_bridge.connect(route, *PROBE_TARGET, timeout=timeout)
    except proxy_bridge.BridgeError as e:
        raise ProxyRouteError(
            _BRIDGE_ERROR_KINDS.get(e.kind, PROXY_UNREACHABLE),
            str(e),
            status=e.status,
        ) from None
    except (ssl.SSLError, OSError):
        raise ProxyRouteError(
            PROXY_UNREACHABLE,
            "the proxy could not be reached, or its TLS certificate was "
            "refused",
        ) from None
    finally:
        if tunnel is not None:
            tunnel.close()


def launch_env(
    route: ProxyRoute,
    no_proxy: str,
    env: Mapping[str, str],
    bridge: "proxy_bridge.Bridge | None" = None,
) -> dict[str, str]:
    """``env`` with the account's proxy in place of whatever it inherited.

    Every spelling of every variable is dropped before the account's own are
    written in both cases. Claude Code resolves ``https_proxy`` before
    ``HTTPS_PROXY`` (code.claude.com/docs/en/network-config), so an inherited
    lower-case value would otherwise win over the account's, and an inherited
    ``NO_PROXY`` would add bypasses the account was never given: ``no_proxy``
    (``run.noProxy``) is the whole list.

    The URL is :meth:`ProxyRoute.text` — credentials included, because that is
    how a client presents them to a proxy — and it is as secret as the stored
    value. For a scheme that needs the bridge, ``bridge`` is that bridge and
    the URL is its loopback address: the proxy's password never enters the
    child's environment, and the child reads the account's proxy through this
    process. A bridged route without a bridge is refused rather than written
    with the real URL, which would leak it.
    """
    written = {
        name: value
        for name, value in env.items()
        if name.upper() not in LAUNCH_ENV_NAMES
    }
    if route.needs_bridge:
        if bridge is None:
            raise ValueError(
                "a bridged proxy needs a running bridge for launch_env"
            )
        url = bridge.url
    else:
        url = route.text()
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        written[name] = url
        written[name.lower()] = url
    written["NO_PROXY"] = no_proxy
    written["no_proxy"] = no_proxy
    return written


def send(
    request: urllib.request.Request,
    timeout: float,
    route: ProxyRoute | None,
):
    """Send ``request`` on ``route``, or directly when the account has none.

    The single entry point of every network call in ``oauth.py`` and
    ``subscription.py``: the direct branch is the ``route is None`` case only,
    so a proxied account cannot reach the network any other way.

    A launch's environment is :func:`launch_env`; this function is only about
    cswap's own requests.
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

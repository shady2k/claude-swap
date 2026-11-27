"""Snapshot source — the supported read path for dashboards and GUI shells.

Pacing is store-governed: the usage store's persisted poll plans plus its
freshness/backoff/claim gates (decided atomically in ``UsageStore.reserve``)
cap every surface at the same per-account cadence, so a dashboard repainting
every few seconds and a one-shot ``cswap list`` produce identical network
behavior. This class therefore just runs the same on-demand pass as ``cswap
list`` (``fetch=None``) each take — the store decides which accounts, if
any, may actually be fetched — and offers ``store_only`` for shells that
host an auto engine (which already collects on its own schedule).

``take()`` is blocking (file locks, keychain subprocesses, network): call it
from a background thread, never a UI event loop.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import replace

from claude_swap.json_output import USAGE_TOKEN_EXPIRED
from claude_swap.models import AccountSnapshot, AccountsSnapshot
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.usage_store import UsageEntry

_logger = logging.getLogger("claude-swap")


class SnapshotSource:
    """Takes one coherent snapshot per call; the store paces the network.

    ``full=True`` (the user's explicit refresh) is accepted for API
    stability but is no faster than a normal pass: even an explicit refresh
    is capped by the store's serve TTL and poll plans. ``store_only=True``
    reads the store without any network eligibility.
    """

    def __init__(self, switcher: ClaudeAccountSwitcher) -> None:
        self.switcher = switcher
        self._last: AccountsSnapshot | None = None
        self._lock = threading.Lock()
        self._plans_lock = threading.Lock()

    def take(
        self, *, full: bool = False, store_only: bool = False
    ) -> AccountsSnapshot:
        """Blocking snapshot pass; call from a thread worker."""
        fetch: set[str] | None = set() if store_only else None
        snap = self.switcher.accounts_snapshot(fetch=fetch)
        with self._lock:
            snap = self._reconcile(snap)
            self._last = snap
            return snap

    def refresh_plans(self) -> None:
        """Refresh due subscription plans; blocking, so call it from a worker.

        The counterpart of ``take(store_only=True)``, which never reaches the
        network: a shell whose snapshots are store-only calls this to keep its
        plan labels current. Overlapping calls collapse into the running one.
        Display-only, so a failure is logged and goes no further.
        """
        if not self._plans_lock.acquire(blocking=False):
            return
        try:
            self.switcher.refresh_subscription_plans()
        except Exception:
            _logger.debug("plan refresh failed", exc_info=True)
        finally:
            self._plans_lock.release()

    def _reconcile(self, snap: AccountsSnapshot) -> AccountsSnapshot:
        if self._last is None:
            return snap
        previous = {acc.number: acc for acc in self._last.accounts}
        accounts = tuple(
            self._reconcile_account(acc, previous.get(acc.number), snap.taken_at)
            for acc in snap.accounts
        )
        return replace(snap, accounts=accounts)

    def _reconcile_account(
        self,
        acc: AccountSnapshot,
        prev: AccountSnapshot | None,
        taken_at: float,
    ) -> AccountSnapshot:
        """Keep the newer account's rows, and a transient warning only while
        the generation ``acc`` represents now still satisfies it.

        The sentinel is a live overlay, never persisted: a store-only repaint
        can legitimately miss it. It is therefore carried across a repaint
        with the same measurement — but only when ``sentinel_still_applies``
        says the CURRENT credential still meets the condition. A rotated
        profile (or a replaced token) therefore clears a warning instead of
        inheriting it forever.
        """
        if prev is None or account_identity(acc) != account_identity(prev):
            return acc

        prev_fetched = prev.usage.fetched_at
        fetched = acc.usage.fetched_at
        if prev_fetched is not None and (fetched is None or fetched < prev_fetched):
            usage = _with_current_age(prev.usage, taken_at)
            if usage.sentinel == USAGE_TOKEN_EXPIRED and not sentinel_still_applies(
                prev.usage, acc
            ):
                usage = replace(usage, sentinel=None)
            return replace(acc, usage=usage)
        if acc.usage.sentinel is not None:
            return acc

        if (
            prev.usage.sentinel == USAGE_TOKEN_EXPIRED
            and fetched == prev_fetched
            and sentinel_still_applies(prev.usage, acc)
        ):
            return replace(
                acc, usage=replace(acc.usage, sentinel=USAGE_TOKEN_EXPIRED)
            )
        return acc


def sentinel_still_applies(prev: UsageEntry, acc: AccountSnapshot) -> bool:
    """Whether a transient token-expired warning still describes ``acc``.

    ``prev`` is the row that carried the warning. A locally expired access
    token carries no rejected fingerprint: the warning applies while the
    current generation is still expired. A token the server refused carries
    the refused access token's fingerprint: it applies while that token is
    still the account's current one. Any other sentinel does not travel this
    way.
    """
    if prev.sentinel != USAGE_TOKEN_EXPIRED:
        return False
    if prev.rejected_fingerprint is not None:
        return acc.access_token_fingerprint == prev.rejected_fingerprint
    return acc.token_expired


def reconciled_usage(
    current: AccountSnapshot, incoming: UsageEntry
) -> UsageEntry:
    """The usage row a late worker may contribute to a newer snapshot.

    ``current`` already holds the newer snapshot's usage. A transient
    token-expired warning from the incoming row is taken only while it still
    describes the current generation; a cleared warning must not come back
    from a worker that finished after the rotation.
    """
    if incoming.sentinel == USAGE_TOKEN_EXPIRED and not sentinel_still_applies(
        incoming, current
    ):
        return current.usage
    return incoming


def account_identity(acc: AccountSnapshot) -> tuple[str, str, str]:
    """The identity discriminator for a slot across snapshots.

    The single definition of "same account": snapshot reconciliation here and
    the TUI's snapshot merge must agree, or an identity change (e.g. a slot
    re-used by another login) is detected by one and missed by the other.
    """
    return (acc.email, acc.org_uuid, acc.kind)


def _with_current_age(usage: UsageEntry, taken_at: float) -> UsageEntry:
    fetched = usage.fetched_at
    if fetched is None:
        return usage
    return replace(usage, age_s=max(0.0, taken_at - fetched))

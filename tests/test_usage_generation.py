"""One usage generation for the engine and the menu (ALX-1983).

Two independent ``ClaudeAccountSwitcher`` instances share one temporary HOME
and one ``cache/usage.json``. The active slot's backup is expired while its
session profile holds a fresh generation, and the store already carries an
81% reading under a future poll plan. The scheduled collector and the menu
snapshot must both serve that 81% — and a token-expired warning must not
outlive the generation it described.
"""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import oauth
from claude_swap.autoswitch import (
    AutoSwitchEngine,
    NoSwitchEvent,
    PollEvent,
    SwitchEvent,
    TickOutcome,
)
from claude_swap.json_output import USAGE_TOKEN_EXPIRED
from claude_swap.settings import AutoSwitchSettings
from claude_swap.snapshot_source import SnapshotSource, reconciled_usage
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.usage_store import FetchRecord


def _iso_in(seconds: float) -> str:
    from datetime import datetime, timezone

    return (
        datetime.fromtimestamp(time.time() + seconds, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _creds(token: str, access_in: float) -> str:
    return json.dumps({"claudeAiOauth": {
        "accessToken": token,
        "refreshToken": f"rt-{token}",
        "expiresAt": int((time.time() + access_in) * 1000),
        "refreshTokenExpiresAt": int((time.time() + 30 * 86400) * 1000),
    }})


def _switcher(
    temp_home: Path, sample_sequence_data: dict
) -> ClaudeAccountSwitcher:
    sample_sequence_data["activeAccountNumber"] = 1
    sample_sequence_data["accounts"]["1"].update({
        "email": "a1@example.com", "organizationUuid": "",
        "organizationName": "",
    })
    sample_sequence_data["accounts"]["2"].update({
        "email": "a2@example.com", "organizationUuid": "",
        "organizationName": "",
    })
    switcher = ClaudeAccountSwitcher()
    switcher._setup_directories()
    switcher._write_json(switcher.sequence_file, sample_sequence_data)
    return switcher


def _write_slot(
    switcher: ClaudeAccountSwitcher, num: str, email: str, creds: str
) -> None:
    switcher._write_account_credentials(num, email, creds)
    switcher._write_account_config(num, email, json.dumps({
        "oauthAccount": {"emailAddress": email, "accountUuid": f"uuid-{num}"},
    }))


def _write_profile(
    switcher: ClaudeAccountSwitcher, num: str, email: str, creds: str
) -> None:
    session_dir = switcher._session_dir(num, email)
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / ".credentials.json").write_text(creds)
    (session_dir / ".claude.json").write_text(json.dumps({
        "oauthAccount": {"emailAddress": email, "organizationUuid": ""},
    }))


def _seed_cache(switcher: ClaudeAccountSwitcher) -> None:
    """81% active, 10% candidate, both with a future plan: no fetch is due."""
    now = time.time()
    identities = {
        "1": ("a1@example.com", ""),
        "2": ("a2@example.com", ""),
    }
    switcher._usage_store.record(
        {
            "1": FetchRecord(usage={
                "five_hour": {"pct": 81.0, "resets_at": _iso_in(3600)},
                "seven_day": {"pct": 20.0, "resets_at": _iso_in(3 * 86400)},
            }),
            "2": FetchRecord(usage={
                "five_hour": {"pct": 10.0, "resets_at": _iso_in(3600)},
                "seven_day": {"pct": 10.0, "resets_at": _iso_in(3 * 86400)},
            }),
        },
        identities,
    )
    switcher._usage_store.set_poll_plan(
        {"1": (now + 600, 300.0), "2": (now + 600, 300.0)}, identities
    )


def _setup(temp_home: Path, sample_sequence_data: dict):
    switcher = _switcher(temp_home, sample_sequence_data)
    backup_expired = _creds("sk-backup-1", -3600)
    candidate_fresh = _creds("sk-backup-2", 7200)
    _write_slot(switcher, "1", "a1@example.com", backup_expired)
    _write_slot(switcher, "2", "a2@example.com", candidate_fresh)
    _seed_cache(switcher)
    return switcher, backup_expired, candidate_fresh


def _no_network():
    return patch(
        "claude_swap.oauth.try_fetch_usage_for_account",
        side_effect=AssertionError("the cache is fresh; no request is due"),
    )


def test_a_skip_pass_uses_the_healthy_profile_generation(
    temp_home: Path, sample_sequence_data: dict
):
    """The regression for the base defect: with no claim this pass, the
    collector must not report ``token expired`` from the expired backup while
    the session profile represents the account with a working token."""
    switcher, _backup, _candidate = _setup(temp_home, sample_sequence_data)
    profile = _creds("sk-profile-1", 7200)
    _write_profile(switcher, "1", "a1@example.com", profile)

    with _no_network():
        entries = switcher.usage_entries_by_account(fetch=set())

    entry = entries["1"]
    assert entry.sentinel is None
    value = entry.decision_value()
    assert isinstance(value, dict)
    assert value["five_hour"]["pct"] == 81.0


def test_the_engine_and_the_menu_share_the_cache_reading(
    temp_home: Path, sample_sequence_data: dict
):
    """81% is the decision input for both surfaces, and 81 >= 80 switches."""
    engine_switcher, backup, _candidate = _setup(
        temp_home, sample_sequence_data
    )
    profile = _creds("sk-profile-1", 7200)
    _write_profile(engine_switcher, "1", "a1@example.com", profile)

    menu_switcher = ClaudeAccountSwitcher()
    menu_switcher._setup_directories()

    with _no_network():
        pre = engine_switcher.usage_entries_by_account(fetch=set())
    assert pre["1"].sentinel is None
    assert pre["1"].decision_value()["five_hour"]["pct"] == 81.0

    events = []
    engine = AutoSwitchEngine(
        engine_switcher, AutoSwitchSettings(threshold=80.0), events.append
    )
    real_entries = engine_switcher.usage_entries_by_account
    seen: list[tuple[set[str] | None, dict[str, str | None]]] = []

    def entries(fetch=None, *, scheduled=False):
        # Escalation would fetch; this test is about the shared store reading.
        result = real_entries(
            fetch=fetch if fetch == set() else set(), scheduled=scheduled
        )
        seen.append((fetch, {n: e.sentinel for n, e in result.items()}))
        return result

    with (
        patch.object(
            engine_switcher, "usage_entries_by_account", side_effect=entries
        ),
        patch.object(
            engine_switcher,
            "switch_to",
            return_value={
                "switched": True,
                "from": {"number": 1, "email": "a1@example.com"},
                "to": {"number": 2, "email": "a2@example.com"},
                "warnings": [],
            },
        ) as switch,
    ):
        outcome = engine.tick()

    assert outcome is TickOutcome.SWITCHED
    assert switch.call_args[0][0] == "2"
    poll = next(e for e in events if isinstance(e, PollEvent))
    assert poll.threshold == 80.0
    assert poll.headroom["1"] == pytest.approx(19.0)
    assert poll.windows["1"]["5h"] == pytest.approx(81.0)
    switched = next(e for e in events if isinstance(e, SwitchEvent))
    assert switched.trigger == "proactive"
    assert switched.to_ref["number"] == 2
    assert not any(
        isinstance(e, NoSwitchEvent) and e.reason == "active-idle"
        for e in events
    )
    assert seen[0][0] == set()
    assert seen[0][1]["1"] is None

    source = SnapshotSource(menu_switcher)
    for _ in range(3):
        snap = source.take(store_only=True)
        active = {a.number: a for a in snap.accounts}["1"]
        assert active.usage.sentinel is None
        assert active.usage.decision_value()["five_hour"]["pct"] == 81.0
        assert active.token_expired is False
        assert active.access_token_fingerprint == oauth.access_token_fingerprint(
            profile
        )

    # Selecting the profile for display never adopts it into the backup.
    assert menu_switcher.read_account_credentials(
        "1", "a1@example.com"
    ) == backup


def test_a_rotated_profile_clears_a_carried_token_expired_warning(
    temp_home: Path, sample_sequence_data: dict
):
    """A store-only repaint may carry the transient warning, but only while
    the generation it described is still the current one."""
    switcher, _backup, _candidate = _setup(temp_home, sample_sequence_data)
    source = SnapshotSource(switcher)

    with _no_network():
        expired = source.take(store_only=True)
    active = {a.number: a for a in expired.accounts}["1"]
    assert active.usage.sentinel == USAGE_TOKEN_EXPIRED
    assert active.token_expired is True

    profile = _creds("sk-profile-1", 7200)
    _write_profile(switcher, "1", "a1@example.com", profile)

    with _no_network():
        rotated = source.take(store_only=True)
        repeated = source.take(store_only=True)

    for snap in (rotated, repeated):
        active = {a.number: a for a in snap.accounts}["1"]
        assert active.usage.sentinel is None
        assert active.usage.decision_value()["five_hour"]["pct"] == 81.0
        assert active.token_expired is False


def test_the_tui_merge_does_not_restore_a_cleared_warning():
    """The TUI's late-worker merge uses the same condition as the source."""
    from tests.test_tui import make_account, make_usage_at

    current = make_account(
        1, active=True, entry=make_usage_at(100.0, pct=81.0)
    )
    incoming = make_usage_at(100.0, pct=81.0, sentinel=USAGE_TOKEN_EXPIRED)

    assert reconciled_usage(current, incoming) is current.usage
    still_expired = dataclasses.replace(current, token_expired=True)
    assert reconciled_usage(still_expired, incoming).sentinel == USAGE_TOKEN_EXPIRED

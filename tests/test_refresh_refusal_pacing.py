"""Refresh authority refusals must not fall through to stale usage requests."""
import json
import urllib.error

import pytest

from claude_swap import oauth


@pytest.mark.parametrize("error", ["ownership-lost", "superseded", "unreadable"])
@pytest.mark.parametrize("expired", [True, False])
def test_authority_refusal_keeps_error_without_extra_request(monkeypatch, error, expired):
    credentials = json.dumps({"claudeAiOauth": {
        "accessToken": "synthetic-access", "refreshToken": "synthetic-refresh",
        "expiresAt": 1 if expired else 9999999999000,
    }})
    requests = []
    def request(token):
        requests.append(token)
        raise urllib.error.HTTPError("https://example.invalid", 401, "denied", {}, None)
    monkeypatch.setattr(oauth, "request_usage_data", request)
    result = oauth.try_fetch_usage_for_account(
        "2", "synthetic@example.invalid", credentials, False,
        refresh_via=lambda *args: oauth.RefreshOutcome(None, error=error),
    )
    assert result.error == error
    assert len(requests) == (0 if expired else 1)

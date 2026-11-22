"""Portable, non-network checks of the stand hosts-file preflight."""

import pytest

from tests import stand_mock as mock


@pytest.mark.parametrize("mapping", [
    "127.0.0.1 api.mock.example",
    "::1 localhost API.MOCK.EXAMPLE. # synthetic alias",
])
def test_hosts_preflight_rejects_synthetic_alias_without_dns(mapping, tmp_path, monkeypatch):
    hosts = tmp_path / "hosts"
    hosts.write_text(mapping + "\n", encoding="ascii")

    def no_resolver(*args):
        pytest.fail("hosts preflight called a resolver")

    monkeypatch.setattr("socket.getaddrinfo", no_resolver)
    monkeypatch.setattr("socket.gethostbyname", no_resolver)
    with pytest.raises(mock.HostsPreflightError, match="contains a mapping"):
        mock.preflight_hosts(hosts)


def test_hosts_preflight_ignores_comments_and_other_hosts(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "127.0.0.1 localhost # api.mock.example\n"
        "127.0.0.1 not-api.mock.example\n",
        encoding="ascii",
    )
    mock.preflight_hosts(hosts)


def test_hosts_preflight_requires_readable_file(tmp_path):
    with pytest.raises(mock.HostsPreflightError, match="Cannot read hosts file"):
        mock.preflight_hosts(tmp_path / "missing-hosts")

"""Control HOME provenance checks, without accessing an account store."""

from pathlib import Path

import pytest

from tests import win_profile_home as control


@pytest.fixture
def profile_control(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    home = profile / ("cswap-policy-control-" + "0" * 32)
    home.mkdir()
    monkeypatch.setattr(control, "token_profile", lambda: profile)
    return profile, home


def test_control_accepts_empty_direct_child(profile_control, tmp_path):
    _, home = profile_control
    base = tmp_path / "basetemp"
    base.mkdir()
    assert control.validate(home, basetemp=base, empty=True) == home


@pytest.mark.parametrize("kind", ["parent", "nonempty", "base-inside", "home-inside"])
def test_control_refuses_invalid_provenance(profile_control, tmp_path, kind):
    profile, home = profile_control
    base = tmp_path / "basetemp"
    base.mkdir()
    if kind == "parent":
        home.rename(base / home.name)
        home = base / home.name
    elif kind == "nonempty":
        (home / "synthetic").write_text("synthetic", encoding="utf-8")
    elif kind == "base-inside":
        base = home / "basetemp"
        base.mkdir()
    else:
        base = profile
    with pytest.raises(RuntimeError):
        control.validate(home, basetemp=base, empty=True)


def test_control_refuses_redirect_before_resolution(profile_control, monkeypatch):
    _, home = profile_control
    lstat = Path.lstat

    def redirected(path, *args, **kwargs):
        if path == home:
            from types import SimpleNamespace

            return SimpleNamespace(st_mode=0o40755, st_file_attributes=0x400)
        return lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", redirected)
    with pytest.raises(RuntimeError, match="redirected"):
        control.validate(home)


def test_prepare_publishes_only_child_path_and_cleanup_removes_it(profile_control, tmp_path, monkeypatch):
    profile, _ = profile_control
    output = tmp_path / "github-env"
    monkeypatch.setenv("GITHUB_ENV", str(output))
    control.prepare()
    key, value = output.read_text(encoding="utf-8").strip().split("=", 1)
    assert key == control.ENV
    home = Path(value)
    assert home.parent.samefile(profile)
    assert not list(home.iterdir())
    monkeypatch.setenv(key, value)
    (home / "synthetic").write_text("synthetic", encoding="utf-8")
    control.cleanup()
    assert not home.exists()


def test_cleanup_refuses_unrelated_directory(profile_control, tmp_path, monkeypatch):
    unrelated = tmp_path / ("cswap-policy-control-" + "1" * 32)
    unrelated.mkdir()
    marker = unrelated / "synthetic"
    marker.write_text("synthetic", encoding="utf-8")
    monkeypatch.setenv(control.ENV, str(unrelated))
    with pytest.raises(RuntimeError, match="parent"):
        control.cleanup()
    assert marker.read_text(encoding="utf-8") == "synthetic"

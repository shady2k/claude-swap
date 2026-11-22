"""F22: classify invocation forms without changing client argv."""

import pytest

from claude_swap.claude_forms import classify


@pytest.mark.parametrize("args", [
    [], [""], ["a prompt"], ["-p", "a prompt"], ["-p", "hello"], ["-c"], ["--continue"],
    ["--resume"], ["--resume", "session-id"], ["--resume=session-id"],
    ["--model", "auth", "a prompt"], ["--model=--settings", "a prompt"],
    ["--", "auth", "--settings", "{}"], ["--print", "--", "hello"],
])
def test_main_forms(args):
    original = args.copy()
    form = classify(args)
    assert form.bypass_reason is None
    assert form.error is None
    assert form.settings is None
    assert args == original


@pytest.mark.parametrize("args, expected", [
    (["auth", "status", "--json"], "auth"),
    (["mcp", "add", "server"], "mcp"),
    (["--model", "mcp", "update"], "update"),
    (["doctor"], "doctor"),
    (["config"], "config"),
    (["install"], "install"),
    (["migrate-installer"], "migrate-installer"),
    (["--output-format=json", "future-command"], "future-command"),
    (["--unproved=do-not-echo"], "--unproved"),
    (["--model", "--settings", "{}"], "--model"),
    (["--output-format", "do-not-echo"], "--output-format"),
    (["--model=x", "--model", "y"], "--model"),
    (["-p", "--print"], "--print"),
])
def test_bypass_forms_name_argument(args, expected):
    form = classify(args)
    assert form.bypass_reason and expected in form.bypass_reason
    assert "do-not-echo" not in form.bypass_reason
    assert form.error is None


@pytest.mark.parametrize("args, expected", [
    (["-p", "--settings", "file name.json", "a prompt"], (1, 3)),
    (["--settings={}", "-p", "a prompt"], (0, 1)),
    (["--model=--settings", "--settings={}", "--", "--settings=x"], (1, 2)),
])
def test_settings_span(args, expected):
    form = classify(args)
    assert form.settings == expected
    assert form.error is form.bypass_reason is None


@pytest.mark.parametrize("prefix", [[], ["auth", "status"], ["future-command"]])
def test_two_settings_options_are_an_error_not_a_bypass(prefix):
    form = classify([*prefix, "--settings", "file.json", "--settings={}"])
    assert form.error and "--settings" in form.error
    assert form.bypass_reason is None


def test_unknown_option_with_settings_is_ambiguous_not_a_bypass():
    form = classify(["--future-option", "--settings", "file.json"])
    assert form.error and "--future-option" in form.error
    assert "--settings" in form.error
    assert form.bypass_reason is None


def test_subcommand_does_not_count_option_values_or_text_after_separator():
    form = classify(["auth", "--model=--settings", "--settings={}", "--", "--settings=ignored"])
    assert form.error is None
    assert form.bypass_reason and "auth" in form.bypass_reason
    assert form.settings == (2, 3)

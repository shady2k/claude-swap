"""Conservative Claude invocation forms from design r14 §3.4 (F22).

This is the specified subset, not an admission table for a production Claude
build. A lone bare word without ``-p`` or ``--`` is conservatively treated
as a new subcommand. Known subcommands are route exceptions, not commands
that are guaranteed to run without network access.
"""

from __future__ import annotations

from dataclasses import dataclass


_ACCOUNTLESS = frozenset({
    "auth", "config", "doctor", "install", "mcp", "migrate-installer", "update",
})
# Canonical option name (shared by aliases) and operand arity.
_OPTIONS = {
    "-p": ("--print", "none"),
    "--print": ("--print", "none"),
    "-c": ("--continue", "none"),
    "--continue": ("--continue", "none"),
    "--resume": ("--resume", "optional"),
    "--model": ("--model", "required"),
    "--output-format": ("--output-format", "required"),
    "--settings": ("--settings", "required"),
    "--setting-sources": ("--setting-sources", "required"),
}


@dataclass(frozen=True)
class InvocationForm:
    """Indices into the original argv; `settings` is a half-open slice."""

    settings: tuple[int, int] | None = None
    bypass_reason: str | None = None
    error: str | None = None
    setting_sources: bool = False


def classify(args: list[str]) -> InvocationForm:
    """Identify the main form without rewriting or reordering arguments."""
    seen: set[str] = set()
    settings = None
    reason = None
    first_positional = None
    i = 0

    while i < len(args):
        arg = args[i]
        if arg == "--":
            break
        if not arg.startswith("-") or arg == "-":
            if first_positional is None:
                first_positional = arg
            elif reason is None:
                reason = f"unexpected positional argument {arg!r}"
            i += 1
            continue

        option, equals, value = arg.partition("=")
        rule = _OPTIONS.get(option)
        if rule is None:
            # We don't know the arity of this option. A later --settings
            # token may be an option or an operand, so don't bypass it.
            for later in args[i + 1:]:
                if later == "--":
                    break
                if later.partition("=")[0] == "--settings":
                    return InvocationForm(error=f"cannot safely parse --settings after unknown option {option!r}")
            reason = reason or f"unknown option {option!r}"
            break
        name, arity = rule
        if name in seen:
            if name == "--settings":
                return InvocationForm(error="duplicate --settings options are forbidden")
            reason = reason or f"repeated option {option!r}"
        seen.add(name)

        stop = i + 1
        if arity == "none":
            if equals:
                reason = reason or f"option {option!r} does not accept a value"
        elif not equals and stop < len(args) and not args[stop].startswith("-"):
            value = args[stop]
            stop += 1
        if arity == "required" and not value:
            reason = reason or f"option {option!r} needs a value"
        elif name == "--output-format" and value not in {"text", "json", "stream-json"}:
            reason = reason or f"unsupported value for {option!r}"
        if name == "--settings":
            settings = (i, stop)
        i = stop

    if first_positional in _ACCOUNTLESS:
        reason = f"subcommand {first_positional!r} is outside the profile route"
    elif (
        first_positional not in {None, "-"}
        and len(first_positional.split()) == 1
        and "--print" not in seen
    ):
        reason = f"unknown subcommand {first_positional!r}"
    return InvocationForm(settings, reason, setting_sources="--setting-sources" in seen)

"""Command-line interface for Claude Swap."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import re
import shlex
import sys

from claude_swap import __version__, account_proxy, launch_agent, paths, printer
from claude_swap.exceptions import (
    ClaudeSwitchError,
    EgressCheckError,
    SessionError,
)
from claude_swap.json_output import error_envelope
from claude_swap.models import (
    ACCOUNT_PRIORITY_MAX,
    ACCOUNT_THRESHOLD_MAX,
    ACCOUNT_THRESHOLD_MIN,
)
from claude_swap.printer import (
    accent,
    bolded,
    dimmed,
    error,
    force_utf8_output,
    muted,
    warning,
)
from claude_swap.settings import (
    AUTOSWITCH_STRATEGIES,
    load_ui_settings,
    load_update_settings,
)
from claude_swap.switcher import ClaudeAccountSwitcher


def _prog_name() -> str:
    """The command name to show in usage/help.

    argparse otherwise defaults to ``os.path.basename(sys.argv[0])``, which for
    an installed entry-point shim renders as an ugly absolute path (e.g.
    ``python.exe C:\\Users\\me\\.local\\bin\\cswap``). We strip that down to the
    bare command the user typed (``cswap`` / ``claude-swap``), falling back to
    ``cswap`` for ``python -m claude_swap`` and odd launchers.
    """
    name = os.path.basename(sys.argv[0] or "")
    for ext in (".exe", ".pyw", ".py"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    if not name or name in {"__main__", "python", "python3", "py"}:
        return "cswap"
    return name


# Memorable subcommand aliases → the long-standing flags they expand to. Lets
# users type `cswap list`, `cswap status`, `cswap add`, etc. instead of `--list`
# / `--status` / `--add-account`, which all still work. `switch` is special-cased
# below (a bare `switch` rotates; `switch <target>` jumps to one account) and
# `run`/`auto` keep their own pre-dispatch parsers, so none of those are listed here.
_SUBCOMMAND_FLAGS = {
    "help": "--help",
    "list": "--list",
    "ls": "--list",
    "status": "--status",
    "current": "--status",
    "add": "--add-account",
    "add-token": "--add-token",
    "remove": "--remove-account",
    "rm": "--remove-account",
    "disable": "--disable-account",
    "enable": "--enable-account",
    "export": "--export",
    "import": "--import",
    "import-usage": "--import-usage",
    "purge": "--purge",
    "upgrade": "--upgrade",
    "update": "--upgrade",
    "tui": "--tui",
    "watch": "--watch",
    "menubar": "--menubar",
}


def _translate_subcommand(argv: list[str]) -> list[str]:
    """Rewrite a leading memorable subcommand into the equivalent flag argv.

    ``argv`` is the args after the program name. The rewrite only fires when the
    first token is a recognized verb (which never starts with '-'), so the
    established ``--flag`` interface — and every existing test that drives it —
    is left untouched. Tokens after the verb pass through verbatim, so flags
    like ``--json``, ``--strategy``, ``--slot``, and ``--force`` keep combining
    exactly as before (e.g. ``cswap switch --strategy best``, ``cswap list --json``).
    """
    if not argv:
        return argv

    verb, rest = argv[0], argv[1:]

    if verb == "switch":
        # Bare `switch` rotates; `switch <num|email>` jumps to that account.
        if rest and not rest[0].startswith("-"):
            return ["--switch-to", *rest]
        return ["--switch", *rest]

    # `next`/`prev` are the two directions of that rotation.
    if verb == "next":
        return ["--switch", *rest]
    if verb == "prev":
        return ["--switch", "--previous", *rest]

    flag = _SUBCOMMAND_FLAGS.get(verb)
    if flag is not None:
        return [flag, *rest]

    return argv


#: Claude Code's own local commands: they answer a property of the installed
#: binary, so `cswap run --auto` runs them without an account, a profile or a
#: proxy.
_LOCAL_COMMANDS = frozenset({"--version", "-v", "--help", "-h"})

#: Claude Code's commands that write the user's SHARED profile rather than a
#: session copy. Every session profile mirrors that profile
#: (``_sync_mcp_servers``), so a write into a session copy is deleted by the
#: next launch.
_PROFILE_COMMANDS = frozenset({"mcp"})


def _run_command(argv: list[str]) -> None:
    """Handle `cswap run NUM|EMAIL [--no-share] [-- <claude args>]`.

    Pre-dispatched before the main parser is built: a positional subcommand
    can't coexist with main()'s mutually-exclusive flag group, and this keeps
    the existing parser untouched. Limitation: `run` must be the
    first argument (`cswap --debug run 2` is not supported; use
    `cswap run 2 --debug`).

    On POSIX this execs claude and never returns; on Windows it exits with
    claude's return code. Either way the post-dispatch update check in
    main() is unreachable, which is intended.
    """
    # Everything after the first `--` is forwarded to claude verbatim.
    if "--" in argv:
        split = argv.index("--")
        head, tail = argv[:split], argv[split + 1 :]
    else:
        head, tail = argv, []

    parser = argparse.ArgumentParser(
        prog=f"{_prog_name()} run",
        description=(
            "[EXPERIMENTAL] Launch Claude Code as a stored account in this "
            "terminal only (the default login and other terminals are "
            "unaffected)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cswap run 2
  cswap run user@example.com
  cswap run 2 --no-share
  cswap run 2 --no-share-history
  cswap run 2 --require-session
  cswap run --auto -- --resume
  cswap run 2 -- --resume
        """,
    )
    parser.add_argument(
        "account",
        nargs="?",
        metavar="NUM|EMAIL",
        help="Account to run (number or email). Omit to run the current "
        "directory's mapping (see `cswap map`), or the active slot when "
        "nothing is mapped.",
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help=(
            "Launch the active account — sequence.json's activeAccountNumber — "
            "in its own profile, with its proxy. This is what the thin "
            "`claude` wrapper runs. Refuses when no account is active or the "
            "slot has no stored credentials; never falls back to a plain "
            "claude on ~/.claude."
        ),
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help=(
            "Launch the managed account with the most remaining quota "
            "instead of a named or mapped one, without switching the default "
            "login. The account is chosen by the same comparison `cswap "
            "switch --strategy best` makes; no account with quota left is a "
            "refusal, not a fallback."
        ),
    )
    parser.add_argument(
        "--no-share",
        action="store_true",
        help=(
            "Don't share settings/keybindings/CLAUDE.md/skills/commands/agents/rules "
            "from ~/.claude into the session profile (and remove previously "
            "shared items). Chat history is not affected: see "
            "--no-share-history"
        ),
    )
    parser.add_argument(
        "--share-history",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Share conversation history (projects/ and history.jsonl) from "
            "~/.claude into the session profile, so every account sees one "
            "unified history. This is the default; history the profile "
            "already accumulated is merged into ~/.claude first. "
            "--no-share-history keeps this account's history separate for "
            "this launch, `cswap config set run.shareHistory false` for "
            "every launch. On Windows, projects/ is shared either way and "
            "history.jsonl only when symlinks are allowed (Developer Mode, "
            "or an elevated terminal)."
        ),
    )
    parser.add_argument(
        "--require-session",
        action="store_true",
        help=(
            "Refuse to launch when the account is already the active default "
            "login, instead of running plain claude on that login (which a "
            "later switch could pull out from under the session)"
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args(head)
    if args.auto and args.account is not None:
        parser.error("--auto chooses the account itself: give no NUM|EMAIL with it")
    if args.active and (args.account is not None or args.auto):
        parser.error("--active launches the recorded active account: give no "
                     "NUM|EMAIL and not --auto with it")

    # The parser's --help belongs on stdout. Nothing printed after it does:
    # see _run_launch.
    with contextlib.redirect_stdout(sys.stderr):
        _run_launch(args, tail)


def _active_account(
    switcher: ClaudeAccountSwitcher,
) -> tuple[str, tuple[str, str, str]]:
    """The slot and account triple `cswap run --active` hands to a launch.

    ``isolated_mode.require_active_slot`` refuses — with the remedy in the
    message — when no slot is recorded or the recorded one lost its stored
    credential or config. The triple then pins the launch to the account that
    was resolved, so a ``swap``/``move`` in between refuses instead of running
    the account that took the number.
    """
    from claude_swap import isolated_mode

    num = isolated_mode.require_active_slot(switcher)
    return num, switcher.resolve_account(num)


def _run_launch(args: argparse.Namespace, tail: list[str]) -> None:
    """Resolve the account for `cswap run` and hand the terminal to claude.

    Runs with stdout redirected to stderr. Stdout belongs to claude, and a
    caller may be reading it as data (`cswap run 2 -- -p ... --output-format
    stream-json`), so a notice printed there lands in that stream: ahead of
    claude's output when stdout is unbuffered, after it on Windows, where
    cswap stays resident and flushes its buffer at exit. On a POSIX pipe it
    is lost instead, because the exec discards what is still buffered.

    The redirect covers every print on the way to the launch, the session
    bootstrap's included, and rebinds only Python's ``sys.stdout``: claude
    inherits the real stream.
    """
    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)

        from claude_swap.session import SessionManager

        manager = SessionManager(switcher)

        # `claude mcp …` manages the user's shared server list, which every
        # session profile mirrors: a write into a session copy would be
        # deleted by the next launch. It goes to the primary profile whichever
        # launch form named an account.
        if tail and tail[0] in _PROFILE_COMMANDS:
            manager.exec_default(tail, primary_profile=True)
            return  # only reachable in tests where exec/exit is mocked

        # share_history goes through as given: None (neither flag) leaves it
        # to run.shareHistory, which SessionManager.run resolves.
        if args.auto:
            # `--version`/`--help` answer without an account: an SDK or a
            # package manager asking must get an answer while no slot is
            # recorded. Nothing else is answered here: `auth`, `update` and
            # `doctor` need the login the launch chose, and must not run in
            # the global profile outside that account's proxy — so `--auto`
            # walks its plan for them like any other command.
            if tail and tail[0] in _LOCAL_COMMANDS:
                manager.exec_local(tail)
                return  # only reachable in tests where exec/exit is mocked

            # Walk the ranked candidates of ONE capture (``auto_run_plan``):
            # an account whose proxy or exit check refuses is reported and the
            # next one in that order is tried. The plan holds the roster and
            # the readings, so a rejected slot costs one row of the order, not
            # a second list capture, config probe and quota pass.
            plan = switcher.auto_run_plan()
            rejected: list[str] = []
            chosen = 0
            while (row := plan.next()) is not None:
                # The choice is the (slot, email, organization) triple of ONE
                # capture, not a number to resolve again: verify it just before
                # the launch so a `swap`/`move` in between refuses instead of
                # running the account that took the number.
                account = (str(row[0]), row[1], row[3])
                chosen += 1
                if chosen == 1:
                    print(
                        dimmed(
                            f"Account-{account[0]} has the most remaining "
                            "quota — launching it."
                        )
                    )
                else:
                    print(
                        dimmed(
                            f"Account-{account[0]} is the next available "
                            "account — launching it."
                        )
                    )
                try:
                    manager.run(
                        account[0],
                        _rate_limit_hook(tail, account),
                        share=not args.no_share,
                        share_history=args.share_history,
                        require_session=args.require_session,
                        account=account,
                    )
                except EgressCheckError as e:
                    # Raised before any profile work or claude start, so
                    # trying the next candidate changes nothing on disk.
                    rejected.append(str(e))
                    warning(
                        f"Account-{account[0]} was rejected: {e} "
                        "Trying the next account."
                    )
                    continue
                return  # only reachable in tests where exec/exit is mocked
            why = plan.why()
            if rejected:
                # ``why`` keeps what the remaining candidates answered — the
                # reset time of an exhausted account, or the unreadable
                # reading — instead of claiming every slot failed the check.
                raise SessionError(
                    "No account passed its exit check: "
                    + "; ".join(rejected)
                    + (f". {why}" if why else ". Nothing was launched.")
                )
            raise SessionError(why or "Nothing was launched.")

        if args.active:
            slot, account = _active_account(switcher)
            manager.run(
                slot,
                _rate_limit_hook(tail, account),
                share=not args.no_share,
                share_history=args.share_history,
                require_session=args.require_session,
                account=account,
            )
            return  # only reachable in tests where exec/exit is mocked

        if args.account is not None:
            manager.run(
                args.account,
                tail,
                share=not args.no_share,
                share_history=args.share_history,
                require_session=args.require_session,
            )
            return  # only reachable in tests where exec/exit is mocked

        # No account given: resolve from the current directory's mapping.
        slot, email = switcher.slot_for_directory(os.getcwd())
        if slot is not None:
            manager.run(
                slot,
                tail,
                share=not args.no_share,
                share_history=args.share_history,
                require_session=args.require_session,
            )
            return  # only reachable in tests
        # Nothing mapped, or the mapped account is gone: launch the active
        # slot. Never a plain claude on the global profile — this fork keeps
        # no login there (``isolated_mode``), so a fallback would silently run
        # an account cswap does not manage.
        if email is not None:
            warning(
                f"Mapped account {email} no longer exists — launching the "
                "active account."
            )
        else:
            print(
                dimmed(
                    f"No account mapped for {os.getcwd()} — launching the "
                    "active account."
                )
            )
        slot, account = _active_account(switcher)
        manager.run(
            slot,
            _rate_limit_hook(tail, account),
            share=not args.no_share,
            share_history=args.share_history,
            require_session=args.require_session,
            account=account,
        )
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _wrapper_command(argv: list[str]) -> None:
    """Handle `cswap wrapper`: print the thin `claude` wrapper's path.

    The install itself is a symlink the user makes, because the wrapper has to
    sit in a directory ahead of the real Claude Code in ``PATH`` and only they
    know which one that is. Pre-dispatched before the main parser for the same
    reason as `run`: the main parser's required mutually-exclusive group can't
    hold a positional subcommand. Rules: ``docs/auto-launch.md``.
    """
    parser = argparse.ArgumentParser(
        prog="cswap wrapper",
        description=(
            "Print the path of claude-swap's thin `claude` wrapper: a symlink "
            "to it, ahead of the real Claude Code in PATH, makes every "
            "`claude` launch the account recorded in cswap's state "
            "(`cswap run --active`) in that account's own profile."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  mkdir -p ~/.local/claude-swap/bin
  ln -s "$(cswap wrapper)" ~/.local/claude-swap/bin/claude
  export PATH="$HOME/.local/claude-swap/bin:$PATH"
        """,
    )
    parser.parse_args(argv)

    from claude_swap import wrapper

    print(wrapper.WRAPPER_PATH)


def _rate_limit_hook(tail: list[str], account: tuple[str, str, str]) -> list[str]:
    """``tail`` with the ``StopFailure`` hook that marks an exhausted account.

    Claude Code reports a turn it gave up on to a ``StopFailure`` hook, with
    ``error: rate_limit`` for a 429 (measured on 2.1.329, interactive and
    ``-p``: see ``docs/auto-launch.md``). The hook runs ``cswap rate-limited
    <email> <organization>``, so the next launch knows this account's usage
    reading predates a real refusal (``record_stop_failure``).

    It travels as ``--settings``, which ADDS a settings source: the hooks in
    the user's own ``settings.json`` still run (measured on 2.1.329). A
    command line that already carries the user's ``--settings`` gets none of
    this — cswap will not compete for that switch.

    Neither does Claude Code's own housekeeping: a first argument that reads as
    one of its subcommands (``attach``, ``logs``, ``stop``, ``remote-control``)
    gets no hook. In front of a subcommand ``--settings`` turns the whole line
    into a prompt instead of running it (measured on 2.1.329), so the rule is
    "looks like a subcommand" rather than a list that a later release would
    outdate. The cost is a one-word prompt (``claude hello``), which goes
    without a mark; a repeat of it inside the serve window is answered from the
    cache and may choose the same slot (``docs/auto-launch.md``).
    """
    if "--settings" in tail:
        return tail
    if tail and re.fullmatch(r"[a-z][a-z-]*", tail[0]):
        return tail
    program = launch_agent.resolve_program()
    command = " ".join(
        shlex.quote(part)
        for part in (*program, "rate-limited", account[1], account[2])
    )
    settings = {
        "hooks": {
            "StopFailure": [
                {
                    "matcher": "rate_limit",
                    "hooks": [{"type": "command", "command": command}],
                }
            ]
        }
    }
    return ["--settings", json.dumps(settings), *tail]


def _rate_limited_command(argv: list[str]) -> None:
    """Handle `cswap rate-limited EMAIL [ORG]`: the StopFailure hook's target.

    Not a user command. Every launch that runs the recorded active account —
    `cswap run --active` (what the thin `claude` wrapper runs) and the
    fallback launch when the directory has no `cswap map` — passes the
    `StopFailure` hook through `--settings` the same way (`--auto` already
    did, via ``_rate_limit_hook``). It records that the server refused this
    account on its rate limit, which is what makes the next launch prefer
    another one: ``ClaudeAccountSwitcher.record_stop_failure`` stamps
    `cache/stop-failure.json` and delegates to
    ``isolated_mode.switch_active_after_rate_limit`` to move the recorded
    active slot off the refused account in `sequence.json` (only while that
    account is still the recorded slot; `activeAccountNumber`/`lastUpdated`
    only). Silent: a hook's output is not the user's.
    """
    parser = argparse.ArgumentParser(prog="cswap rate-limited", add_help=False)
    parser.add_argument("email")
    parser.add_argument("organization", nargs="?", default="")
    args = parser.parse_args(argv)
    ClaudeAccountSwitcher().record_stop_failure(args.email, args.organization)


def _guard_root(switcher: ClaudeAccountSwitcher) -> None:
    """Refuse to run as root outside a container (shared by run/map/unmap)."""
    if sys.platform != "win32":
        if os.geteuid() == 0 and not switcher._is_running_in_container():
            error("Error: Do not run this script as root (unless running in a container)")
            sys.exit(1)


def _person_at_terminal(args: argparse.Namespace) -> bool:
    """Whether a person is running this command and can answer a system prompt.

    The switcher's ``interactive`` flag: it lets the macOS Keychain migration
    wait for the permission window. False for ``--json`` (a program reads the
    result, even from a terminal) and for the menu bar app (launchd runs it),
    and otherwise true only when stdin and stderr are both terminals: stderr
    carries the notice that says what the window is for.
    """
    if args.json or args.menubar:
        return False
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):  # a closed or replaced stream
        return False


def _map_command(argv: list[str]) -> None:
    """Handle `cswap map [NUM|EMAIL] [PATH]`.

    With no NUM|EMAIL, lists all mappings. Otherwise maps PATH (default: the
    current directory) to the given account. Pre-dispatched before the main
    parser for the same reason as `run` (the main parser's required
    mutually-exclusive group can't hold a positional subcommand).
    """
    parser = argparse.ArgumentParser(
        prog="cswap map",
        description=(
            "Map a stored account to a directory so `cswap run` (with no "
            "account) auto-launches it there. With no arguments, lists all "
            "mappings."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cswap map 2 ~/work/client-app
  cswap map user@example.com          # map the current directory
  cswap map                           # list all mappings
        """,
    )
    parser.add_argument(
        "account",
        nargs="?",
        metavar="NUM|EMAIL",
        help="Account to map (number or email). Omit to list mappings.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        metavar="PATH",
        help="Directory to map (default: current directory)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)

        if args.account is None:
            switcher.list_mappings()
            return

        from claude_swap.mappings import MappingStore, normalize_path

        store = MappingStore(switcher.backup_dir)
        account_num, email, org_uuid = switcher.resolve_account(args.account)
        target = args.path or os.getcwd()
        if not os.path.isdir(target):
            warning(f"Warning: {target} is not an existing directory (mapping it anyway)")
        previous = store.get(target)
        store.set(target, email, org_uuid)

        shown = normalize_path(target)
        if previous and previous.get("email") != email:
            prev_email = previous.get("email")
            print(
                f"{accent('Mapped')} {shown} → Account-{account_num} ({email}) "
                f"{muted(f'(was {prev_email})')}"
            )
        else:
            print(f"{accent('Mapped')} {shown} → Account-{account_num} ({email})")
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _unmap_command(argv: list[str]) -> None:
    """Handle `cswap unmap [PATH]` — remove a directory→account mapping."""
    parser = argparse.ArgumentParser(
        prog="cswap unmap",
        description="Remove a directory → account mapping (default: current directory).",
    )
    parser.add_argument(
        "path",
        nargs="?",
        metavar="PATH",
        help="Directory to unmap (default: current directory)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)

        from claude_swap.mappings import MappingStore, normalize_path

        store = MappingStore(switcher.backup_dir)
        target = args.path or os.getcwd()
        shown = normalize_path(target)
        if store.remove(target):
            print(f"{accent('Unmapped')} {shown}")
        else:
            print(dimmed(f"No mapping for {shown}"))
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _unclaimed_command(argv: list[str]) -> None:
    """Handle `cswap unclaimed [--purge ID]` — inspect or drop a stash row.

    The stash holds credential bytes a switch or a consume gate could not
    attribute to a slot. Rows normally clear themselves (the next gate pass
    adopts or retires them), but two states need a human: a row whose bytes
    are unreadable until a keychain is unlocked or a mode is fixed, and one
    whose metadata was lost, which no pass can ever adopt. ``--json`` lists
    only bare ids, so without this there is nothing to look at and nothing to
    drop short of hand-editing the manifest.
    """
    parser = argparse.ArgumentParser(
        prog=f"{_prog_name()} unclaimed",
        description=(
            "List stashed credential entries, or purge one by id. "
            "Purging deletes the bytes — recovery is /login + `cswap add`."
        ),
    )
    parser.add_argument(
        "--purge",
        metavar="ID",
        help="Delete this entry's bytes and manifest row",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)
        entries = switcher.list_unclaimed_credentials()

        if args.purge:
            if args.purge not in entries:
                error(f"Error: no unclaimed entry {args.purge}")
                sys.exit(1)
            switcher._store._remove_unclaimed_credential(args.purge)
            print(f"{accent('Purged')} {args.purge}")
            return

        if not entries:
            print(dimmed("No unclaimed credential entries"))
            return
        for entry_id, meta in sorted(entries.items()):
            slot = meta.get("configSlot") or "?"
            reason = meta.get("reason") or "orphaned (no manifest row)"
            print(f"{entry_id}  slot {slot}  {reason}")
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _swap_command(argv: list[str]) -> None:
    """Handle `cswap swap NUM|EMAIL|ALIAS NUM|EMAIL|ALIAS`.

    Exchanges the two accounts' slot numbers (list order and numeric
    targets). Pre-dispatched before the main parser for the same reason as
    `alias` (the main parser's required mutually-exclusive group can't hold
    a positional subcommand).
    """
    parser = argparse.ArgumentParser(
        prog=f"{_prog_name()} swap",
        description=(
            "Exchange two accounts' slot numbers, so they trade places in "
            "`cswap list` and as numeric targets. Aliases, backups, and "
            "session history move with their account."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cswap swap 1 2
  cswap swap dev user@example.com
        """,
    )
    parser.add_argument("first", metavar="NUM|EMAIL|ALIAS", help="One account")
    parser.add_argument("second", metavar="NUM|EMAIL|ALIAS", help="The other account")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)
        num_a, num_b = switcher.swap_accounts(args.first, args.second)
        print(f"{accent('Swapped')} Account {num_a} and Account {num_b}:")
        data = switcher._get_sequence_data() or {}
        accounts = data.get("accounts", {})
        for num in sorted((num_a, num_b), key=int):
            email = accounts.get(num, {}).get("email", "")
            print(f"  {num}: {email}")
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _move_command(argv: list[str]) -> None:
    """Handle `cswap move NUM|EMAIL|ALIAS SLOT`.

    Assigns an account to a specific slot number. If the slot is empty the
    account is relocated there (its old slot is freed); if it is occupied the
    two accounts trade places. `swap a b` is exactly `move a <b's slot>`.
    Pre-dispatched before the main parser for the same reason as `alias`.
    """
    parser = argparse.ArgumentParser(
        prog=f"{_prog_name()} move",
        description=(
            "Assign an account to a slot number. An empty slot relocates the "
            "account there and frees its old slot; an occupied slot swaps the "
            "two. Aliases, backups, and session history move with the account."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cswap move user@example.com 1   move an account onto shortcut 1
  cswap move dev 1                by alias
  cswap move 2 1                  by number (swaps if slot 1 is taken)
        """,
    )
    parser.add_argument("account", metavar="NUM|EMAIL|ALIAS", help="Account to move")
    parser.add_argument("slot", metavar="SLOT", help="Destination slot number")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)
        num_src, num_target, swapped = switcher.move_account(args.account, args.slot)
        data = switcher._get_sequence_data() or {}
        accounts = data.get("accounts", {})
        if num_src == num_target:
            email = accounts.get(num_target, {}).get("email", "")
            print(f"{dimmed('Already in')} slot {num_target}: {email}")
        elif swapped:
            print(f"{accent('Swapped')} Account {num_src} and Account {num_target}:")
            for num in sorted((num_src, num_target), key=int):
                email = accounts.get(num, {}).get("email", "")
                print(f"  {num}: {email}")
        else:
            email = accounts.get(num_target, {}).get("email", "")
            print(f"{accent('Moved')} {email} to slot {num_target}")
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _alias_command(argv: list[str]) -> None:
    """Handle `cswap alias [NUM|EMAIL] [NAME] [--unset]`.

    With no arguments, lists all aliases. Otherwise sets (or, with --unset,
    removes) the alias for the given account. Pre-dispatched before the main
    parser for the same reason as `map` (the main parser's required
    mutually-exclusive group can't hold a positional subcommand).
    """
    parser = argparse.ArgumentParser(
        prog="cswap alias",
        description=(
            "Set, remove, or list a short display alias for an account. "
            "Once set, the alias can be used anywhere an account number or "
            "email is accepted (switch, remove, run, map)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cswap alias 2 dev
  cswap alias user@example.com dev
  cswap alias 2 --unset
  cswap alias                         # list all aliases
        """,
    )
    parser.add_argument(
        "account",
        nargs="?",
        metavar="NUM|EMAIL",
        help="Account to alias (number or email). Omit to list aliases.",
    )
    parser.add_argument(
        "alias_name",
        nargs="?",
        metavar="NAME",
        help="Alias to set (letters, digits, ., -, _; not purely numeric).",
    )
    parser.add_argument("--unset", action="store_true", help="Remove the account's alias")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    if args.unset and args.alias_name:
        parser.error("--unset does not take a NAME argument")
    if args.unset and args.account is None:
        parser.error("NUM|EMAIL is required with --unset")
    if args.account is not None and not args.unset and not args.alias_name:
        parser.error("NAME is required (or pass --unset to remove the alias)")

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)

        if args.account is None:
            rows = switcher.list_aliases()
            if not rows:
                print(dimmed("No aliases set"))
                return
            print(bolded("Aliases:"))
            for num, alias_name, email in rows:
                print(f"  {num}: {alias_name} {muted(f'({email})')}")
            return

        if args.unset:
            account_num = switcher.unset_alias(args.account)
            print(f"{accent('Removed alias')} for Account {account_num}")
        else:
            account_num, normalized = switcher.set_alias(args.account, args.alias_name)
            print(f"{accent('Set alias')} '{normalized}' for Account {account_num}")
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


class _DiagnosticsParser(argparse.ArgumentParser):
    """A parser whose errors never echo a proxy URL.

    The two commands that take a proxy URL are the only ones whose arguments
    can carry a password, and argparse formats the offending value into every
    shape it refuses: a value attached to a boolean flag
    (``--unset=http://user:pass@host``), a second positional, a ``--slot`` that
    failed its integer conversion, an abbreviated flag. Redacting at ``error``
    covers all of them from one place instead of enumerating the shapes; the
    whole tokens of the command line are dropped too, because a password may
    hold a space and the URL pattern ends at one.
    """

    redact_urls = False
    #: The tokens of this command line, captured by :meth:`parse_args`.
    argv: tuple[str, ...] = ()

    def parse_args(self, args=None, namespace=None):
        self.argv = tuple(sys.argv[1:] if args is None else args)
        return super().parse_args(args, namespace)

    def error(self, message: str) -> None:
        if self.redact_urls:
            message = account_proxy.redact_urls(message, self.argv)
        super().error(message)


#: Every spelling argparse accepts for the main parser's ``--proxy``: it
#: expands any unambiguous prefix of a long option. ``--purge`` is the only
#: other option starting with ``--p``, so ``--p`` alone is refused as
#: ambiguous, while ``--pr``, ``--pro`` and ``--prox`` reach ``--proxy``.
_PROXY_FLAGS = ("--proxy", "--prox", "--pro", "--pr")


def _carries_proxy(argv: list[str]) -> bool:
    """Whether this invocation gives a proxy URL, by flag or ``--proxy=URL``."""
    return any(
        a == flag or a.startswith(flag + "=")
        for a in argv
        for flag in _PROXY_FLAGS
    )


def _proxy_command(argv: list[str]) -> None:
    """Handle `cswap proxy [NUM|EMAIL] [URL] [--expect-country CC]
    [--expect-ip IP] [--unset-expect] [--unset]`.

    With no arguments, lists every account that has a proxy or an egress
    expectation, password masked. Otherwise attaches (or, with --unset,
    removes) one account's HTTP proxy and/or sets what its exit must look
    like. Pre-dispatched before the main parser for the same reason as
    `alias`: the main parser's required mutually-exclusive group can't hold a
    positional subcommand.

    The URL, country and IP are validated inside `update_account_proxy`,
    before any file is touched, so a rejected value leaves `sequence.json`
    byte-identical. What the settings do, and the cases in which a launch
    refuses to send at all, are in `account_proxy` and `egress`.
    """
    parser = _DiagnosticsParser(
        prog="cswap proxy",
        description=(
            "Set, remove, or list the HTTP proxy of an account, and what its "
            "exit must be. Every request cswap makes for that account then "
            "goes through it, and never directly: if the proxy is "
            "unreachable, asks for credentials it rejects, or the stored "
            "value is unusable, the request fails instead of falling back. "
            "With --expect-country/--expect-ip a launch is refused before "
            "Claude Code starts unless the exit matches. The rules are in "
            "`docs/proxy.md` and the module docstrings of `account_proxy` and "
            "`egress`."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cswap proxy 2 http://127.0.0.1:3128
  cswap proxy 2 http://user:pass@proxy.example:3128
  cswap proxy user@example.com http://127.0.0.1:3128
  cswap proxy 2 --expect-country DE --expect-ip 203.0.113.7
  cswap proxy 2 --expect-country de
  cswap proxy 2 --unset-expect        # keep the proxy, drop the expectations
  cswap proxy 2 --unset               # back to a direct connection
  cswap proxy                         # list accounts with a proxy or a rule

URL schemes: http:// (port 80), https:// (443), socks5h:// and socks5://
(1080, remote DNS). http:// is spoken directly; the others run through a
local bridge on 127.0.0.1 that holds the account's URL, so Claude Code gets
no proxy password in its environment.
An expectation needs a proxy on the same account; set one first.
        """,
    )
    parser.add_argument(
        "account",
        nargs="?",
        metavar="NUM|EMAIL",
        help="Account to set (number, email, or alias). Omit to list.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        metavar="URL",
        help="Proxy URL: http://, https://, or socks5h://[user:pass@]host[:port]",
    )
    parser.add_argument(
        "--unset", action="store_true",
        help="Remove the account's proxy (and its egress expectation)",
    )
    parser.add_argument(
        "--expect-country",
        metavar="CC",
        help="The ISO 3166-1 alpha-2 country the account's exit must be",
    )
    parser.add_argument(
        "--expect-ip",
        metavar="IP",
        help="The IPv4/IPv6 address the account's exit must be",
    )
    parser.add_argument(
        "--unset-expect",
        action="store_true",
        help="Remove the account's egress expectation, keeping the proxy",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    # Every shape argparse refuses here — an extra positional, a value attached
    # to a boolean flag, an abbreviated flag — echoes the offending value, and
    # on this command that value may hold a password. One redaction at the
    # parser's ``error`` covers them all; the identifier-resolution errors
    # below go through the same helper.
    parser.redact_urls = True
    args = parser.parse_args(argv)

    wants_expect = (
        args.expect_country is not None
        or args.expect_ip is not None
        or args.unset_expect
    )
    if args.unset and args.url:
        parser.error("--unset does not take a URL argument")
    if args.unset and wants_expect:
        parser.error(
            "--unset already removes the egress expectation; it cannot be "
            "combined with --expect-country, --expect-ip or --unset-expect"
        )
    if args.unset and args.account is None:
        parser.error("NUM|EMAIL is required with --unset")
    if args.unset_expect and args.url:
        parser.error("--unset-expect does not take a URL argument")
    if args.unset_expect and (
        args.expect_country is not None or args.expect_ip is not None
    ):
        parser.error(
            "--unset-expect cannot be combined with --expect-country or "
            "--expect-ip"
        )
    if wants_expect and args.account is None:
        parser.error("NUM|EMAIL is required with --expect-country/--expect-ip")
    if (
        args.account is not None
        and not args.unset
        and not wants_expect
        and args.url is None
    ):
        parser.error(
            "URL is required (or pass --unset to remove the proxy, or "
            "--expect-country/--expect-ip to change the exit expectation)"
        )

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)

        if args.account is None:
            rows = switcher.list_account_proxies()
            if not rows:
                print(dimmed("No account proxies set"))
                return
            print(bolded("Account proxies:"))
            for num, described, email, expectation in rows:
                suffix = f"  {muted(expectation)}" if expectation else ""
                print(f"  {num}: {described} {muted(f'({email})')}{suffix}")
            return

        if args.unset:
            account_num = switcher.clear_account_proxy(args.account)
            print(f"{accent('Cleared')} proxy for Account-{account_num}")
        else:
            update = switcher.update_account_proxy(
                args.account,
                args.url,
                expect_country=args.expect_country,
                expect_ip=args.expect_ip,
                unset_expect=args.unset_expect,
            )
            if args.url is not None:
                print(
                    f"{accent('Set')} proxy {update.proxy} for "
                    f"Account-{update.account_num}"
                )
            if args.unset_expect:
                print(
                    f"{accent('Cleared')} egress expectation for "
                    f"Account-{update.account_num}"
                )
            elif args.expect_country is not None or args.expect_ip is not None:
                print(
                    f"{accent('Set')} egress {update.expectation} for "
                    f"Account-{update.account_num}"
                )
    except ClaudeSwitchError as e:
        error(f"Error: {account_proxy.redact_urls(str(e))}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _threshold_command(argv: list[str]) -> None:
    """Handle `cswap threshold [NUM|EMAIL|ALIAS] [PCT] [--unset]`.

    With no arguments, prints the global `autoswitch.threshold` and every
    per-account override. Otherwise sets (or, with --unset, removes) one
    account's own switch-away threshold. Pre-dispatched before the main parser
    for the same reason as `alias`: the main parser's required
    mutually-exclusive group cannot hold a positional subcommand.

    The value is validated inside `set_account_threshold`, before any file is
    touched, so a rejected value leaves `sequence.json` byte-identical.
    """
    parser = argparse.ArgumentParser(
        prog="cswap threshold",
        description=(
            "Set, remove, or list a per-account switch-away threshold. The "
            "per-account value replaces autoswitch.threshold for that account "
            "only, so one shared account can reserve headroom without capping "
            "the whole fleet."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  cswap threshold 2 85
  cswap threshold user@example.com 99.9
  cswap threshold 2 --unset           # back to the global default
  cswap threshold                     # list the global default and overrides

Valid range: {ACCOUNT_THRESHOLD_MIN:g}-{ACCOUNT_THRESHOLD_MAX:g} (percent used).
        """,
    )
    parser.add_argument(
        "account",
        nargs="?",
        metavar="NUM|EMAIL",
        help="Account to set (number, email, or alias). Omit to list.",
    )
    parser.add_argument(
        "threshold",
        nargs="?",
        metavar="PCT",
        help=(
            f"Percent used at which to switch away "
            f"({ACCOUNT_THRESHOLD_MIN:g}-{ACCOUNT_THRESHOLD_MAX:g})."
        ),
    )
    parser.add_argument(
        "--unset", action="store_true", help="Remove the account's override"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    if args.unset and args.threshold:
        parser.error("--unset does not take a PCT argument")
    if args.unset and args.account is None:
        parser.error("NUM|EMAIL is required with --unset")
    if args.account is not None and not args.unset and args.threshold is None:
        parser.error("PCT is required (or pass --unset to remove the override)")

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)

        if args.account is None:
            _print_threshold_table(switcher)
            return

        switcher.set_account_threshold(
            args.account, None if args.unset else args.threshold
        )
    except ValueError as e:
        # normalize_account_threshold's message; it always names the range.
        error(f"Error: {e}")
        sys.exit(1)
    except ClaudeSwitchError as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{dimmed('Operation cancelled')}")
        sys.exit(130)


def _print_threshold_table(switcher: ClaudeAccountSwitcher) -> None:
    """Print the global switch-away threshold and every per-account override.

    The global line is printed unconditionally: an operator reading a list of
    overrides needs to know what the accounts *without* one are using.
    """
    from claude_swap.settings import load_settings

    default = load_settings(switcher.backup_dir).threshold
    print(bolded("Switch-away thresholds:"))
    print(f"  {dimmed('global default')}  {default:g}%")

    rows = sorted(
        (
            (num, policy.threshold)
            for num, policy in switcher.account_policies().items()
            if policy.threshold is not None
        ),
        key=lambda row: (not row[0].isdigit(), int(row[0]) if row[0].isdigit() else 0),
    )
    if not rows:
        print(dimmed("  No per-account overrides set"))
        return
    for num, value in rows:
        print(f"  Account-{num}  {value:g}%")


def _priority_command(argv: list[str]) -> None:
    """Set, clear, or inspect tiers without enabling the strategy implicitly."""
    parser = argparse.ArgumentParser(
        prog="cswap priority",
        description=(
            "Set or list account priority tiers for the optional "
            "priority-consume-first strategy. Higher numbers are used first; "
            "accounts in the same tier are ordered by soonest weekly reset."
        ),
    )
    parser.add_argument("account", nargs="?", metavar="NUM|EMAIL|ALIAS")
    parser.add_argument(
        "priority", nargs="?", metavar="TIER",
        help=f"Integer from 0 to {ACCOUNT_PRIORITY_MAX} (default 0)",
    )
    parser.add_argument("--unset", action="store_true", help="Return to priority 0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)
    if args.unset and args.priority is not None:
        parser.error("--unset does not take a TIER argument")
    if args.unset and args.account is None:
        parser.error("NUM|EMAIL|ALIAS is required with --unset")
    if args.account is not None and args.priority is None and not args.unset:
        parser.error("TIER is required (or pass --unset)")
    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        _guard_root(switcher)
        if args.account is None:
            print(bolded("Account priorities (higher first; default 0):"))
            for num, policy in switcher.account_policies().items():
                print(f"  Account-{num}  {switcher.account_email(num)}  {policy.priority}")
            print(dimmed("Used only by: cswap auto --strategy priority-consume-first"))
            return
        switcher.set_account_priority(args.account, None if args.unset else args.priority)
    except (ValueError, ClaudeSwitchError) as e:
        error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


def _auto_command(argv: list[str]) -> None:
    """Handle `cswap auto [--once] [--json] [...]`.

    Pre-dispatched before the main parser is built, like `run` (and with the
    same limitation: `auto` must be the first argument). Runs the auto-switch
    engine — a foreground loop by default, or a single evaluate-and-maybe-
    switch tick with --once whose exit code reports the outcome (for cron/
    systemd timers): 0 switched, 1 error, 2 no action needed, 3 blocked
    (no viable target / all accounts exhausted).
    """
    import signal
    import time as _time

    parser = argparse.ArgumentParser(
        prog="cswap auto",
        description=(
            "Automatically switch accounts when the active one nears its "
            "5h/7d rate limit. Runs a foreground polling loop; use --once "
            "for a single tick (cron-friendly)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes with --once:
  0  switched to another account
  1  error (network trouble, lock contention, ...)
  2  no action needed
  3  blocked: wanted to switch but no viable target / all exhausted

Examples:
  cswap auto                       # foreground loop, switch at 90% used
  cswap auto --threshold 80        # switch earlier
  cswap auto --weekly-threshold 97 # let the weekly window run higher before switching
  cswap auto --model Fable         # also switch when the Fable weekly limit is hit
  cswap auto --json                # one JSON event per line (for scripts)
  cswap auto --once; echo $?       # single tick, outcome in exit code
  cswap auto --dry-run             # log decisions, never actually switch

Defaults live in settings.json in the backup root; flags override them.
        """,
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Evaluate once, maybe switch, and exit (exit code = outcome)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit one machine-readable JSON event per line on stdout",
    )
    parser.add_argument(
        "--interval",
        type=float,
        metavar="SECONDS",
        help="Poll interval in loop mode (min 15; default 60)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        metavar="PCT",
        help=(
            "Switch when the active account's 5h window (or any window, "
            "without a weekly line) reaches this utilization (50-99.9; "
            "default 90)"
        ),
    )
    parser.add_argument(
        "--weekly-threshold",
        type=float,
        metavar="PCT",
        help=(
            "Separate switch line for the 7-day and per-model weekly windows "
            "(50-99.9; default: the threshold). A flag cannot unset a "
            "configured value; use 'cswap config unset'"
        ),
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        metavar="SECONDS",
        help="Minimum time between proactive switches (default 300)",
    )
    parser.add_argument(
        "--model",
        metavar="NAMES",
        help=(
            "Also switch when a per-model weekly limit is hit, not just the "
            "account-wide 5h/7d windows. One name or a comma-separated list "
            "(e.g. Fable, Opus, Sonnet, Haiku, or 'Fable,Opus'), or 'all' "
            "for every per-model window an account reports"
        ),
    )
    parser.add_argument(
        "--include-api-key-accounts",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Allow switching onto managed API-key accounts as a last resort "
            "(they bill per token; default: excluded)"
        ),
    )
    parser.add_argument(
        "--strategy",
        choices=AUTOSWITCH_STRATEGIES,
        default=None,
        help=(
            "Target selection: 'best' (most quota left; default), "
            "'weekly-first' (switch at the threshold like best, onto the "
            "account whose weekly window resets soonest), "
            "'consume-first' (proactively use the account whose weekly window "
            "resets soonest), or 'priority-consume-first' (highest account "
            "priority, then soonest weekly reset; only targets below all switch lines)"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Evaluate and report, but never switch or write state",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args(argv)

    from claude_swap.autoswitch import AutoSwitchEngine, AutoSwitchEvent, pct_label
    from claude_swap.printer import accent, yellowed
    from claude_swap.settings import load_settings, merged_with_cli

    def jsonl_emit(event: AutoSwitchEvent) -> None:
        print(json.dumps(event.to_json()), flush=True)

    def human_emit(event: AutoSwitchEvent) -> None:
        stamp = _time.strftime("%H:%M:%S")
        line = event.human()
        if event.kind == "switch":
            line = accent(line)
        elif event.kind in ("error", "account-quarantined"):
            line = yellowed(line)
        elif event.kind in ("poll", "no-switch", "sleep"):
            line = dimmed(line)
        print(f"{stamp}  {line}", flush=True)

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        if sys.platform != "win32":
            if os.geteuid() == 0 and not switcher._is_running_in_container():
                error("Error: Do not run this script as root (unless running in a container)")
                sys.exit(1)

        settings = merged_with_cli(load_settings(switcher.backup_dir), args)
        engine = AutoSwitchEngine(
            switcher,
            settings,
            jsonl_emit if args.json else human_emit,
            dry_run=args.dry_run,
        )

        if args.once:
            sys.exit(engine.tick().value)

        # Loop mode: SIGTERM (systemd stop) exits the loop cleanly.
        signal.signal(signal.SIGTERM, lambda *_: engine.stop())
        if not args.json:
            weekly = (
                f", weekly {pct_label(settings.weekly_threshold)}%"
                if settings.weekly_threshold is not None
                else ""
            )
            print(
                dimmed(
                    f"Auto-switch running: threshold {pct_label(settings.threshold)}%"
                    f"{weekly}, every {settings.interval_seconds:.0f}s"
                    f"{' (dry-run)' if args.dry_run else ''} — Ctrl-C to stop"
                )
            )
        sys.exit(engine.run_loop())
    except ClaudeSwitchError as e:
        if args.json:
            print(json.dumps(error_envelope(e)))
        else:
            error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(
            f"\n{dimmed('Auto-switch stopped')}",
            file=sys.stderr if args.json else sys.stdout,
        )
        sys.exit(130)


def _config_command(argv: list[str]) -> None:
    """Handle `cswap config [list|get KEY|set KEY VALUE|unset KEY|path]`.

    Pre-dispatched before the main parser is built, like `run` and `auto`
    (same limitation: `config` must be the first argument). Edits
    settings.json in the backup root with strict validation — unlike loading,
    which forgivingly clamps — so a typo'd key or out-of-range value errors
    loudly here instead of silently degrading at `cswap auto` time. `list`
    also names the keys a hand edit left in the file that nothing reads.
    """
    from claude_swap.settings import (
        SETTING_SPECS,
        effective_settings,
        format_setting_value,
        load_usage_settings,
        set_setting,
        setting_spec,
        settings_path,
        unrecognized_keys,
        unset_setting,
    )

    key_lines = "\n".join(
        f"  {spec.dotted:<34}{spec.help} (default {format_setting_value(spec.default)})"
        for spec in SETTING_SPECS.values()
    )
    parser = argparse.ArgumentParser(
        prog="cswap config",
        description=(
            "Read and edit claude-swap settings (settings.json in the "
            "backup root)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Keys:
{key_lines}

Examples:
  cswap config                              # list effective settings
  cswap config get autoswitch.threshold
  cswap config set autoswitch.threshold 80
  cswap config set autoswitch.weeklyThreshold 97  # own line for the 7d/per-model windows
  cswap config unset autoswitch.threshold   # back to the default
  cswap config path                         # where settings.json lives
        """,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout (with list or get)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    sub = parser.add_subparsers(dest="action", metavar="{list,get,set,unset,path}")

    p_list = sub.add_parser("list", help="Show all effective settings (the default)")
    p_get = sub.add_parser("get", help="Print one setting's effective value")
    p_get.add_argument("key", metavar="KEY", help="Dotted key, e.g. autoswitch.threshold")
    for p in (p_list, p_get):
        # SUPPRESS: without it the subparser's False default would clobber a
        # pre-verb `cswap config --json` in the shared namespace.
        p.add_argument(
            "--json",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Emit machine-readable JSON to stdout",
        )
    p_set = sub.add_parser("set", help="Validate and persist one setting")
    p_set.add_argument("key", metavar="KEY")
    p_set.add_argument("value", metavar="VALUE")
    p_unset = sub.add_parser("unset", help="Remove one setting (revert to the default)")
    p_unset.add_argument("key", metavar="KEY")
    sub.add_parser("path", help="Print the settings.json location")

    args = parser.parse_args(argv)
    json_mode = bool(getattr(args, "json", False))
    action = args.action or "list"
    if json_mode and action not in ("list", "get"):
        parser.error("--json can only be used with list or get")

    try:
        switcher = ClaudeAccountSwitcher(debug=args.debug)
        if sys.platform != "win32":
            if os.geteuid() == 0 and not switcher._is_running_in_container():
                error("Error: Do not run this script as root (unless running in a container)")
                sys.exit(1)
        root = switcher.backup_dir

        if action == "path":
            print(settings_path(root))
        elif action == "list":
            rows = effective_settings(root)
            ignored = unrecognized_keys(root)
            if json_mode:
                payload = {
                    "schemaVersion": 1,
                    "path": str(settings_path(root)),
                    "settings": [
                        {"key": spec.dotted, "value": value, "isSet": is_set}
                        for spec, value, is_set in rows
                    ],
                    "unrecognized": [
                        {"key": item.dotted, "suggestion": item.suggestion}
                        for item in ignored
                    ],
                }
                print(json.dumps(payload, indent=2))
            else:
                key_w = max(len(spec.dotted) for spec, _, _ in rows)
                val_w = max(len(format_setting_value(v)) for _, v, _ in rows)
                for spec, value, is_set in rows:
                    line = f"{spec.dotted:<{key_w}}  {format_setting_value(value):<{val_w}}"
                    print(line if is_set else f"{line}  {dimmed('(default)')}")
                for item in ignored:
                    warning(
                        f"Warning: settings.json: {item.describe()}",
                        file=sys.stderr,
                    )
        elif action == "get":
            spec = setting_spec(args.key)
            value, is_set = next(
                (v, s) for sp, v, s in effective_settings(root) if sp is spec
            )
            if json_mode:
                payload = {
                    "schemaVersion": 1,
                    "key": spec.dotted,
                    "value": value,
                    "isSet": is_set,
                }
                print(json.dumps(payload, indent=2))
            else:
                print(format_setting_value(value))
        elif action == "set":
            value = set_setting(root, args.key, args.value)
            print(f"{args.key} = {format_setting_value(value)}")
            usage = load_usage_settings(root)
            if (
                args.key.startswith("usage.")
                and usage.fable_probe
                and not usage.header_probe
            ):
                # The Fable probe rides on the header probe's request cycle.
                print(
                    muted(
                        "usage.fableProbe does nothing until "
                        "usage.headerProbe is true"
                    ),
                    file=sys.stderr,
                )
        elif action == "unset":
            if unset_setting(root, args.key):
                default = setting_spec(args.key).default
                print(f"{args.key} unset (default: {format_setting_value(default)})")
            else:
                print(muted(f"{args.key} is not set; nothing to do"), file=sys.stderr)
    except ClaudeSwitchError as e:
        if json_mode:
            print(json.dumps(error_envelope(e), indent=2))
        else:
            error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(
            f"\n{dimmed('Operation cancelled')}",
            file=sys.stderr if json_mode else sys.stdout,
        )
        sys.exit(130)


def _use_native_tls() -> None:
    """Route TLS trust decisions through the OS-native verifier.

    Claude's token endpoint (``platform.claude.com``) serves a Let's Encrypt
    chain. Python's stdlib ``ssl`` uses OpenSSL, which on Windows loads the
    system cert store as a flat set and matches CA certs by *subject name*, so a
    stale, expired duplicate of an intermediate (e.g. an old ``ISRG Root X2``
    left in the user's store) can shadow the valid path and fail verification
    with "certificate has expired" even though the served chain is valid — which
    silently breaks inactive-account token refresh. The OS-native verifiers
    (SChannel on Windows, SecureTransport on macOS) build the chain correctly
    and don't trip on the expired duplicate — the same reason Claude Code (Node,
    with its own bundled roots) is unaffected. ``truststore`` delegates to them.

    Best-effort: on any failure fall back to stdlib ``ssl`` rather than block
    the CLI over a TLS-trust nicety.
    """
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:
        pass


def _menubar_settings_path():
    from claude_swap.paths import get_backup_root

    return get_backup_root() / "menubar_settings.json"


def _set_menubar_auto_switch(enabled: bool) -> bool:
    """Set the menu bar's auto-switch toggle and return its previous value."""
    from claude_swap.menubar import MenuBarSettings

    path = _menubar_settings_path()
    settings = MenuBarSettings.load(path)
    previous = settings.auto_switch_enabled
    settings.auto_switch_enabled = enabled
    settings.save(path)
    return previous


def _print_menubar_auto_switch(*, suggest_flag: bool) -> None:
    """Say whether the menu bar will switch accounts or only show usage.

    The toggle defaults to off and lives only in the menu, so a service
    installed from a terminal can run for weeks as a display while its owner
    believes it is switching (it only shows when an account hits its limit).
    """
    from claude_swap.menubar import MenuBarSettings

    if MenuBarSettings.load(_menubar_settings_path()).auto_switch_enabled:
        print("  auto-switch: on")
        return
    hint = (
        "turn it on from the menu, or re-run with --auto-switch"
        if suggest_flag
        else "turn it on from the menu, or run `cswap menubar --auto-switch`"
    )
    warning(
        f"  auto-switch: off -- the menu bar shows usage but will not switch "
        f"accounts; {hint}",
        file=sys.stderr,
    )


def _menubar_extra_missing() -> str | None:
    """Why the menu bar cannot run here: the optional extra is not installed.

    Checked before anything touches launchd. A worker that exits on ``import
    rumps`` would give launchd a service that crash-loops at every login, which
    is strictly worse than the import error a foreground run shows.
    """
    import importlib.util

    if importlib.util.find_spec("rumps") is not None:
        return None
    from claude_swap.update_check import _detect_install_method

    method = _detect_install_method()
    if method == "uv":
        remedy = "uv tool install --force 'claude-swap[menubar]'"
    elif method == "pipx":
        remedy = "pipx install --force 'claude-swap[menubar]'"
    else:
        remedy = "pip install 'claude-swap[menubar]'"
    return f"The menu bar needs the 'menubar' extra. Install it with: {remedy}"


def _menubar_foreground(switcher, service_pid: int | None, *, worker: bool) -> int:
    """Run the menu bar in this process: launchd's job, or ``--foreground`` from a shell.

    A second instance beside the service would draw a second icon over the same
    accounts, so a shell run refuses while the service has a pid. launchd's own
    job is that pid, which is what ``worker`` says.
    """
    if not worker and service_pid is not None:
        error(
            f"The menu bar is already running as a service (pid {service_pid}). "
            "Quit it from the menu, or run 'cswap menubar --uninstall-service', "
            "before running it in the foreground."
        )
        return 1
    # menubar is import-safe without the extra; a missing rumps surfaces from
    # run() as a ClaudeSwitchError with the install hint.
    from claude_swap.menubar import run as menubar_run

    return menubar_run(switcher)


def _menubar_start(args) -> int:
    """Handle plain ``cswap menubar``: make the service run, say what happened, return.

    First setup registers the menu bar at login and says so, since a command
    that quietly arranged to run at every login would be a surprise. Later runs
    only make sure the service is up: a quit job is kickstarted, a plist pinning
    an old program is repaired, a running one is left alone and reported.
    """
    from claude_swap import launch_agent
    from claude_swap.menubar import framework_build_warning

    missing = _menubar_extra_missing()
    if missing:
        error(missing)
        return 1
    unsupported = framework_build_warning()
    # Before ensure(): the menu bar reads its toggle once at launch, so a
    # changed value needs the write first and a running service restarted.
    previous = None
    if args.auto_switch is not None:
        previous = _set_menubar_auto_switch(args.auto_switch)
    toggled = previous is not None and previous != args.auto_switch
    try:
        result = launch_agent.ensure(restart=toggled)
    except BaseException:
        # Don't leave the toggle changed with no service behind it.
        if toggled:
            _set_menubar_auto_switch(previous)
        raise

    pid = f" (pid {result['pid']})" if result["pid"] else ""
    action = result["action"]
    if action == "already-running":
        print(f"Menu bar is already running{pid}.")
    elif action == "first-setup":
        print(f"Menu bar started{pid}.")
        print(
            dimmed(
                "  It keeps running after you close this terminal and starts at "
                "login. Settings → Start at login in the menu turns that off; "
                "cswap menubar --uninstall-service removes it."
            )
        )
        print(f"  plist: {result['plist']}")
        print(f"  logs:  {result['stderr_log']}")
    elif action == "restarted":
        why = (
            "to apply the auto-switch setting"
            if toggled
            else "so the service runs the current build"
        )
        print(f"Menu bar restarted{pid} {why}.")
    else:
        print(f"Menu bar started{pid}.")
        if not result["start_at_login"]:
            print(dimmed("  Start at login is off, so this lasts until you log out."))
    if result["switched_off"]:
        # macOS allowed this start; the switch only governs the start at login.
        warning(
            f"  Switched off under {launch_agent.SYSTEM_SETTINGS_HINT}: it runs "
            "now because you asked, but macOS will not start it at login until "
            "you turn that back on.",
            file=sys.stderr,
        )
    _print_menubar_auto_switch(suggest_flag=True)
    if unsupported:
        # Said here too, not only at launch: the service survives reboots and
        # shows nothing, which is the worst version of the bug.
        warning(unsupported, file=sys.stderr)
    return 0


def _menubar_service(args) -> int:
    """Handle ``menubar --install-service|--uninstall-service|--service-status``.

    Split out of the dispatch chain because these three share one import and
    one output shape, and because the menu bar branch below them is a
    non-returning call — folding the service paths inline would leave the
    reader tracing which branches fall through to launching the app.
    """
    from claude_swap import launch_agent

    if args.install_service:
        # Installing a service for a menu bar that this interpreter cannot draw
        # is the worst version of the bug: it survives reboots and shows
        # nothing. Say so here too, not only when the menu bar is launched.
        from claude_swap.menubar import framework_build_warning

        missing = _menubar_extra_missing()
        if missing:
            error(missing)
            return 1
        unsupported = framework_build_warning()
        # Before install(): it restarts a running service, and the menu bar
        # reads its toggle once at launch.
        previous = None
        if args.auto_switch is not None:
            previous = _set_menubar_auto_switch(args.auto_switch)
        try:
            result = launch_agent.install()
        except BaseException:
            # Don't leave the toggle changed with no service behind it.
            if previous is not None and previous != args.auto_switch:
                _set_menubar_auto_switch(previous)
            raise
        print(f"Menu bar service installed ({result['label']}).")
        print(f"  plist: {result['plist']}")
        print(f"  logs:  {result['stderr_log']}")
        _print_menubar_auto_switch(suggest_flag=True)
        for key, old, new in result["profile_changes"]:
            warning(
                f"  now follows {key}={new or '(unset)'} (was {old or '(unset)'}); "
                "the service manages that profile from now on",
                file=sys.stderr,
            )
        print(
            dimmed(
                "It starts at login from now on; plain `cswap menubar` is enough "
                "to start it again. Re-run this after a cswap upgrade to point "
                "launchd at the new build."
            )
        )
        if unsupported:
            # The hint printed above is about upgrades. A reinstall does not
            # restart the service that is already running, so say that here.
            warning(
                unsupported + "\n  Then run: cswap menubar --install-service",
                file=sys.stderr,
            )
        return 0

    if args.uninstall_service:
        result = launch_agent.uninstall()
        if result["was_loaded"] or result["removed"]:
            print("Menu bar service removed.")
            for path in result["removed"]:
                print(dimmed(f"  removed {path}"))
            if result["cleared_override"]:
                print(dimmed("  cleared its switch under Login Items & Extensions"))
        else:
            print("Menu bar service was not installed.")
        if result["bundle_error"]:
            warning(
                f"  the wrapper app could not be removed: {result['bundle_error']}",
                file=sys.stderr,
            )
        return 0

    result = launch_agent.status()
    if not result["configured"] and not result["loaded"]:
        print("Menu bar service is not installed.")
        print(dimmed("Start it with: cswap menubar"))
        return 0
    state = result["state"] or ("loaded" if result["loaded"] else "stopped")
    pid = f" (pid {result['pid']})" if result["pid"] else ""
    print(f"Menu bar service: {state}{pid}")
    print(f"  starts at login: {'yes' if result['start_at_login'] else 'no'}")
    plist = result["plist"] if result["start_at_login"] else result["session_plist"]
    print(f"  plist: {plist or result['plist']}")
    if result["running_build"]:
        print(f"  build: {result['running_build']}")
    if result["stale_build"]:
        warning(
            f"  installed build is {result['installed_build']}; plain "
            "`cswap menubar` restarts it onto that",
            file=sys.stderr,
        )
    _print_menubar_auto_switch(suggest_flag=False)
    if result["switched_off"]:
        warning(
            f"  switched off under {launch_agent.SYSTEM_SETTINGS_HINT}; "
            "macOS will not start it at login until you turn that back on",
            file=sys.stderr,
        )
    if not result["configured"]:
        print(dimmed("launchd still has it loaded, but the plist is gone."))
    return 0


def main() -> None:
    """Main entry point for the CLI."""
    force_utf8_output()
    _use_native_tls()
    argv = sys.argv[1:]
    try:
        from claude_swap.appearance import cli_should_probe, cli_theme
        # `run` execs a child that takes over the terminal, and `--json`
        # must stay machine-readable — never probe (and emit the OSC query)
        # in either case.
        probe = cli_should_probe(argv, colors_enabled=printer.colors_enabled())
        name = cli_theme(load_ui_settings(paths.get_backup_root()).theme, colors=probe)
        printer.set_theme(name)
    except Exception:
        pass  # theme is cosmetic; never block the CLI on it

    # `run` and `auto` keep their dedicated pre-dispatch parsers.
    if argv and argv[0] == "run":
        _run_command(argv[1:])
        return  # only reachable in tests where exec/exit is mocked
    if argv and argv[0] == "wrapper":
        _wrapper_command(argv[1:])
        return
    if argv and argv[0] == "rate-limited":
        _rate_limited_command(argv[1:])
        return
    if argv and argv[0] == "auto":
        _auto_command(argv[1:])
        return  # only reachable in tests where sys.exit is mocked
    if len(sys.argv) > 1 and sys.argv[1] == "config":
        _config_command(sys.argv[2:])
        return
    if argv and argv[0] == "map":
        _map_command(argv[1:])
        return
    if argv and argv[0] == "unmap":
        _unmap_command(argv[1:])
        return
    if argv and argv[0] == "unclaimed":
        _unclaimed_command(argv[1:])
        return
    if argv and argv[0] == "alias":
        _alias_command(argv[1:])
        return
    if argv and argv[0] == "threshold":
        _threshold_command(argv[1:])
        return
    if argv and argv[0] == "proxy":
        _proxy_command(argv[1:])
        return
    if argv and argv[0] == "priority":
        _priority_command(argv[1:])
        return
    if argv and argv[0] == "swap":
        _swap_command(argv[1:])
        return
    if argv and argv[0] == "move":
        _move_command(argv[1:])
        return

    # Bare `cswap` in an interactive terminal opens the TUI dashboard (like
    # lazygit/k9s). TTY-gated on both ends so scripts and pipes keep getting
    # the usage error, and `cswap tui` stays the explicit spelling.
    if not argv and sys.stdout.isatty() and sys.stdin.isatty():
        argv = ["--tui"]

    # Memorable subcommands (`cswap switch <email>`, `cswap list`, `cswap help`, ...)
    # are rewritten to the equivalent flags so the original `--flag` interface
    # keeps working unchanged.
    argv = _translate_subcommand(argv)

    parser = _DiagnosticsParser(
        prog=_prog_name(),
        usage="%(prog)s <command> [args] [options]",
        description="""Multi-Account Switcher for Claude Code

Commands:
  %(prog)s help                       show this help
  %(prog)s list                       list managed accounts
  %(prog)s status                     show current account
  %(prog)s switch                     rotate to the next account
  %(prog)s switch <num|email>         switch to a specific account
  %(prog)s add                        add the current account
  %(prog)s add --login                log in a new account in an isolated profile
  %(prog)s add-token [TOKEN|-]        register a setup-token or API key
  %(prog)s remove <num|email>         remove an account
  %(prog)s disable <num|email>        hold an account out of auto-rotation
  %(prog)s enable <num|email>         return a disabled account to rotation
  %(prog)s threshold <num|email> <pct>  set one account's switch-away point
  %(prog)s threshold <num|email> --unset  clear it (use the global default)
  %(prog)s threshold                  list the global default and overrides
  %(prog)s proxy <num|email> <url>    send that account's requests via a proxy
  %(prog)s proxy <num|email> --unset  remove the account's proxy
  %(prog)s proxy                      list the accounts that use a proxy
  %(prog)s priority <num|email> <tier>  set priority (higher first; default 0)
  %(prog)s priority                   list account priorities
  %(prog)s run <num|email> [-- ...]   run as an account, this terminal only
  %(prog)s run                        run the current dir's mapped account
  %(prog)s run --auto [-- ...]        run the account with the most quota left
  %(prog)s wrapper                    print the path of the thin `claude` wrapper
  %(prog)s map <num|email> [path]     map a directory to an account
  %(prog)s map                        list directory mappings
  %(prog)s unmap [path]               remove a directory mapping
  %(prog)s alias <num|email> <name>   set a short alias for an account
  %(prog)s alias <num|email> --unset  remove an account's alias
  %(prog)s alias                      list all aliases
  %(prog)s swap <a> <b>               exchange two accounts' slot numbers
  %(prog)s move <a> <slot>            assign an account to a slot (swaps if taken)
  %(prog)s auto                       auto-switch when nearing rate limits
  %(prog)s config [set KEY VALUE]     show or change settings (settings.json)
  %(prog)s unclaimed [--purge ID]     list or drop stashed credential entries
  %(prog)s export <path>              export accounts
  %(prog)s import <path>              import accounts
  %(prog)s import-usage <path>        adopt usage another machine read (list --json)
  %(prog)s tui                        interactive dashboard (also: bare %(prog)s)
  %(prog)s watch                      dashboard, opened on the live watch page
  %(prog)s menubar                    macOS menu bar app, kept running by launchd
  %(prog)s menubar --service-status   is it running? does it start at login?
  %(prog)s upgrade                    self-upgrade to latest
  %(prog)s purge                      remove all claude-swap data

Aliases: ls=list  rm=remove  update=upgrade""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Flags combine with subcommands:
  %(prog)s switch --strategy best           # pick the account with most quota left
  %(prog)s switch --strategy next-available # rotate, skipping rate-limited accounts
  %(prog)s switch user@example.com
  %(prog)s list --token-status
  %(prog)s list --json
  %(prog)s import-usage usage.json --hold 600  # adopt another machine's list --json
  %(prog)s add --slot 3                      # add to a specific slot
  %(prog)s add --proxy http://127.0.0.1:3128  # add it with its own proxy
  %(prog)s add --login --proxy http://127.0.0.1:3128 --expect-country DE
  %(prog)s add-token sk-ant-oat01-... --email me@example.com
  %(prog)s run 2 -- --resume                 # forward args after '--' to claude
  %(prog)s run --auto -- --resume            # best account, no switch
  %(prog)s auto --once                       # single auto-switch tick (cron-friendly)
  %(prog)s config set autoswitch.threshold 80

The original flag spellings (%(prog)s --switch, %(prog)s --list, ...) keep working.
        """,
    )

    # Version and debug flags (outside mutually exclusive group)
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--token-status",
        action="store_true",
        help="Show source-labelled OAuth token diagnostics (use with 'list')",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit machine-readable JSON to stdout (use with 'list', 'status', "
            "or 'switch'). See README 'JSON output for scripting'."
        ),
    )
    parser.add_argument(
        "--strategy",
        choices=["best", "next-available"],
        metavar="{best,next-available}",
        help=(
            "With bare 'switch': pick the target by remaining 5h/7d quota. "
            "'best' jumps to the account with the most headroom; "
            "'next-available' rotates to the next account, skipping any at their limit"
        ),
    )
    parser.add_argument(
        "--model",
        metavar="NAMES",
        help=(
            "With 'switch --strategy': also count these models' per-model "
            "weekly limits when comparing accounts (comma-separated display "
            "names, or 'all'). Defaults to the autoswitch.model setting"
        ),
    )
    parser.add_argument(
        "--slot",
        type=int,
        metavar="NUM",
        help="Specify slot number when adding account (use with 'add' or 'add-token')",
    )
    parser.add_argument(
        "--email",
        metavar="EMAIL",
        help=(
            "Email address for the account. Optional with 'add-token' and "
            "'add --login'; with add-token it defaults to "
            "setup-token-{slot}@token.local (or api-key-{slot}@token.local "
            "for API keys) since these tokens carry no real email metadata."
        ),
    )
    parser.add_argument(
        "--account",
        metavar="NUM|EMAIL",
        help="Limit export to one account (use with 'export')",
    )
    parser.add_argument(
        "--alias",
        metavar="NAME",
        help="Set a short display alias for the account (use with 'add')",
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help=(
            "Set the account's HTTP proxy, through which every request cswap "
            "makes for it goes (use with 'add'): "
            "http://[user:pass@]host[:port]"
        ),
    )
    parser.add_argument(
        "--login",
        action="store_true",
        help=(
            "With 'add': run Claude Code's own login in an isolated profile, "
            "leaving the current default login and active slot untouched"
        ),
    )
    parser.add_argument(
        "--expect-country",
        metavar="CC",
        help=(
            "With 'add --proxy': the ISO 3166-1 alpha-2 country this account's "
            "exit must be, checked through the proxy before a login or launch"
        ),
    )
    parser.add_argument(
        "--expect-ip",
        metavar="IP",
        help=(
            "With 'add --proxy': the exit IPv4/IPv6 address this account must "
            "have, checked through the proxy before a login or launch"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Overwrite existing accounts during import; with 'switch <num|email>', "
            "activate the stored credentials without backing up the current "
            "login first"
        ),
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Include full ~/.claude.json in export (default: oauthAccount only)",
    )
    parser.add_argument(
        "--hold",
        type=float,
        metavar="SECONDS",
        help=(
            "With 'import-usage': keep this machine from fetching the "
            "imported accounts for this many seconds (0 lifts an earlier hold)"
        ),
    )
    # `cswap menubar` runs the menu bar as a launchd service (launch_agent.py);
    # these pick another operation on that service, so at most one applies.
    service = parser.add_mutually_exclusive_group()
    service.add_argument(
        "--install-service",
        action="store_true",
        help=(
            "With 'menubar': register the menu bar to start at login and "
            "(re)start it now; plain 'cswap menubar' does this on first use (macOS)"
        ),
    )
    service.add_argument(
        "--uninstall-service",
        action="store_true",
        help="With 'menubar': stop the menu bar and remove its LaunchAgent (macOS)",
    )
    service.add_argument(
        "--service-status",
        action="store_true",
        help=(
            "With 'menubar': report whether the menu bar service is installed, "
            "running and set to start at login"
        ),
    )
    service.add_argument(
        "--foreground",
        action="store_true",
        help=(
            "With 'menubar': run the menu bar attached to this terminal instead "
            "of as the background service"
        ),
    )
    parser.add_argument(
        "--auto-switch",
        dest="auto_switch",
        action="store_const",
        const=True,
        default=None,
        help=(
            "With 'menubar' or 'menubar --install-service': turn the menu bar's "
            "auto-switch on (it defaults to off)"
        ),
    )
    parser.add_argument(
        "--no-auto-switch",
        dest="auto_switch",
        action="store_const",
        const=False,
        help=(
            "With 'menubar' or 'menubar --install-service': turn the menu bar's "
            "auto-switch off"
        ),
    )

    # Legacy `--flag` interface. Still fully supported (bare subcommands rewrite
    # into these, see _translate_subcommand), but hidden from --help so the
    # subcommands shown in the description are the one documented interface.
    # The group is not `required` because the "no command" case is handled
    # explicitly below (a required group with every member suppressed prints a
    # broken empty-list error).
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "--add-account",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--remove-account",
        metavar="NUM|EMAIL",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--disable-account",
        metavar="NUM|EMAIL",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--enable-account",
        metavar="NUM|EMAIL",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--list",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--switch",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--switch-to",
        metavar="NUM|EMAIL",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--previous",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--status",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--purge",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--export",
        metavar="PATH",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--import",
        dest="import_",
        metavar="PATH",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--import-usage",
        metavar="PATH",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--tui",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--watch",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--menubar",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--upgrade",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--add-token",
        metavar="TOKEN|-",
        nargs="?",
        const="",
        help=argparse.SUPPRESS,
    )

    # ``add --proxy URL`` takes the only argument of this parser that can
    # carry a password. Every refusal argparse formats for it echoes the
    # value — an extra positional, ``--slot=<URL>``, ``--alias=<URL>`` — so
    # redaction is on for exactly those invocations and off otherwise.
    parser.redact_urls = _carries_proxy(argv)
    args = parser.parse_args(argv)

    # No action selected: emit a clean, subcommand-oriented message rather than
    # the raw argparse "one of the arguments ... is required" (which would list
    # the now-hidden legacy flags). Value actions can be falsy-but-set
    # (--add-token uses const=""), so test those with `is not None`.
    if not (
        args.add_account
        or args.list
        or args.switch
        or args.status
        or args.purge
        or args.tui
        or args.watch
        or args.menubar
        or args.upgrade
        or args.remove_account is not None
        or args.disable_account is not None
        or args.enable_account is not None
        or args.switch_to is not None
        or args.export is not None
        or args.import_ is not None
        or args.import_usage is not None
        or args.add_token is not None
    ):
        parser.error("no command given — try '%(prog)s help'" % {"prog": _prog_name()})

    # An empty value satisfies the guard above (the option *is* set) but matches
    # no truthiness-tested branch of the dispatch chain below, so cswap would
    # fall out of it and exit 0 having done nothing: `cswap export "$DEST"` with
    # an unset DEST must not look like a completed backup. Rejected here, ahead
    # of the modifier guards, so the error names the empty value instead of
    # blaming an --account/--force/--full that was used correctly. --add-token is
    # exempt: its const="" means "prompt me for the token".
    for subcommand, metavar, value in (
        ("remove", "NUM|EMAIL", args.remove_account),
        ("disable", "NUM|EMAIL", args.disable_account),
        ("enable", "NUM|EMAIL", args.enable_account),
        ("switch", "NUM|EMAIL", args.switch_to),
        ("export", "PATH", args.export),
        ("import", "PATH", args.import_),
        ("import-usage", "PATH", args.import_usage),
    ):
        if value is not None and not value:
            parser.error(f"'{subcommand}' requires a non-empty {metavar}")

    if args.token_status and not args.list:
        parser.error("--token-status can only be used with 'list'")

    if args.json and not (args.list or args.status or args.switch or args.switch_to):
        parser.error("--json can only be used with 'list', 'status', or 'switch'")

    if args.json and args.token_status:
        # Token status is not part of the JSON v1 schema; reject rather than
        # silently ignore it (a future additive field can add it).
        parser.error("--token-status cannot be combined with --json")

    if args.strategy is not None and not args.switch:
        parser.error("--strategy can only be used with bare 'switch'")

    if args.previous and not args.switch:
        parser.error("--previous can only be used with bare 'switch'")

    if args.model is not None and args.strategy is None:
        # Meaningless on a direct-target switch or plain rotation — nothing
        # usage-aware reads it there, so reject loudly rather than ignore.
        parser.error(
            "--model can only be used with 'switch --strategy best' or "
            "'switch --strategy next-available'"
        )

    if args.slot is not None and not (args.add_account or args.add_token is not None):
        parser.error("--slot can only be used with 'add' or 'add-token'")

    if args.email is not None and args.add_token is None and not (
        args.add_account and args.login
    ):
        parser.error("--email can only be used with 'add-token' or 'add --login'")

    if args.account is not None and not args.export:
        parser.error("--account can only be used with 'export'")

    if args.alias is not None and not args.add_account:
        parser.error("--alias can only be used with 'add'")

    if args.proxy is not None and not args.add_account:
        parser.error("--proxy can only be used with 'add'")

    if args.login and not args.add_account:
        parser.error("--login can only be used with 'add'")

    for flag, value in (
        ("--expect-country", args.expect_country),
        ("--expect-ip", args.expect_ip),
    ):
        if value is not None and not args.add_account:
            parser.error(f"{flag} can only be used with 'add'")

    if (
        args.expect_country is not None or args.expect_ip is not None
    ) and args.proxy is None:
        parser.error("--expect-country/--expect-ip require --proxy")

    if args.force and not (args.import_ or args.switch_to):
        parser.error("--force can only be used with 'import' or 'switch <num|email>'")

    if args.full and not args.export:
        parser.error("--full can only be used with 'export'")

    if args.hold is not None and args.import_usage is None:
        parser.error("--hold can only be used with 'import-usage'")

    if args.hold is not None and not (math.isfinite(args.hold) and args.hold >= 0):
        parser.error("--hold must be a non-negative number of seconds")

    if (
        args.install_service
        or args.uninstall_service
        or args.service_status
        or args.foreground
    ) and not args.menubar:
        parser.error(
            "--install-service, --uninstall-service, --service-status and "
            "--foreground can only be used with 'menubar'"
        )

    if args.auto_switch is not None and (
        not args.menubar
        or args.uninstall_service
        or args.service_status
        or args.foreground
    ):
        parser.error(
            "--auto-switch/--no-auto-switch can only be used with "
            "'menubar' or 'menubar --install-service'"
        )

    # Self-upgrade runs before switcher init so we don't touch config/keychain
    # just to upgrade the tool itself.
    if args.upgrade:
        from claude_swap.update_check import run_self_upgrade

        try:
            sys.exit(run_self_upgrade())
        except KeyboardInterrupt:
            print(f"\n{dimmed('Upgrade cancelled')}")
            sys.exit(130)

    # Initialize switcher and dispatch under a single error handler so
    # init-time failures (e.g. MigrationError on a backup-dir collision)
    # are presented like every other ClaudeSwitchError: clean stderr line,
    # exit 1, no traceback.
    # JSON-capable commands return a payload; the CLI is the single point that
    # serializes it (so no command writes JSON to stdout itself).
    payload: dict | None = None
    try:
        switcher = ClaudeAccountSwitcher(
            debug=args.debug, interactive=_person_at_terminal(args)
        )

        # Check for root (unless in container) - POSIX only
        if sys.platform != "win32":
            if os.geteuid() == 0 and not switcher._is_running_in_container():
                error("Error: Do not run this script as root (unless running in a container)")
                sys.exit(1)

        if args.add_account:
            if args.login:
                switcher.add_account_via_login(
                    slot=args.slot,
                    alias=args.alias,
                    proxy=args.proxy,
                    expect_country=args.expect_country,
                    expect_ip=args.expect_ip,
                    email=args.email,
                )
            else:
                switcher.add_account(
                    slot=args.slot,
                    alias=args.alias,
                    proxy=args.proxy,
                    expect_country=args.expect_country,
                    expect_ip=args.expect_ip,
                )
        elif args.add_token is not None:
            switcher.add_account_from_token(
                token=args.add_token,
                email=args.email,
                slot=args.slot,
            )
        elif args.remove_account:
            switcher.remove_account(args.remove_account)
        elif args.disable_account is not None:
            switcher.set_account_disabled(args.disable_account, True)
        elif args.enable_account is not None:
            switcher.set_account_disabled(args.enable_account, False)
        elif args.list:
            payload = switcher.list_accounts(
                show_token_status=args.token_status,
                json_output=args.json,
            )
        elif args.switch:
            from claude_swap.settings import load_settings, parse_model_names

            # Only the usage-aware strategies read model limits: --model wins;
            # otherwise the persistent autoswitch.model setting applies
            # (announced by switch(), never silently).
            if args.strategy is None:
                models, model_source = (), None
            elif args.model is not None:
                models, model_source = parse_model_names(args.model), "cli"
            else:
                models = parse_model_names(load_settings(switcher.backup_dir).model)
                model_source = "autoswitch.model" if models else None
            payload = switcher.switch(
                strategy=args.strategy,
                json_output=args.json,
                models=models,
                model_source=model_source,
                previous=args.previous,
            )
            if payload is not None and models:
                payload["models"] = list(models)
                payload["modelSource"] = model_source
        elif args.switch_to:
            payload = switcher.switch_to(
                args.switch_to, json_output=args.json, force=args.force
            )
        elif args.status:
            payload = switcher.status(json_output=args.json)
        elif args.purge:
            switcher.purge()
            if sys.platform == "darwin":
                # The menu bar's LaunchAgent, wrapper app and logs live outside
                # the directory purge just removed; "all traces" means them too.
                # After purge() so a refused purge leaves the menu bar alone.
                from claude_swap import launch_agent

                try:
                    gone = launch_agent.uninstall(backup_dir=switcher.backup_dir)
                except ClaudeSwitchError as e:
                    warning(f"Menu bar service not removed: {e}", file=sys.stderr)
                else:
                    if gone["was_loaded"] or gone["removed"]:
                        print("Removed the menu bar service, its app bundle and logs.")
        elif args.export:
            from claude_swap.transfer import export_accounts

            export_accounts(switcher, args.export, account=args.account, full=args.full)
        elif args.import_:
            from claude_swap.transfer import import_accounts

            import_accounts(switcher, args.import_, force=args.force)
        elif args.import_usage:
            from claude_swap.transfer import import_usage

            import_usage(switcher, args.import_usage, hold_s=args.hold)
        elif args.tui:
            from claude_swap.tui import run as tui_run

            sys.exit(tui_run(switcher))
        elif args.watch:
            from claude_swap.tui import run as tui_run

            sys.exit(tui_run(switcher, start="watch"))
        elif args.menubar:
            if sys.platform != "darwin":
                error("The menu bar is only available on macOS.")
                sys.exit(1)
            if args.install_service or args.uninstall_service or args.service_status:
                sys.exit(_menubar_service(args))
            from claude_swap import launch_agent

            # launchd's own job runs the menu bar here (recognised by pid, so a
            # plist from before the --foreground flag still works); everything
            # else asks launchd to run it and returns.
            service_pid = launch_agent.service_pid()
            worker = service_pid is not None and service_pid == os.getpid()
            if args.foreground or worker:
                sys.exit(_menubar_foreground(switcher, service_pid, worker=worker))
            sys.exit(_menubar_start(args))
    except ClaudeSwitchError as e:
        # `add --proxy` is the one path through this handler whose error may
        # name a URL (an identifier that is one, a slot conflict): the same
        # redaction the parser uses, so the value never reaches stderr or a
        # log line.
        message = (
            account_proxy.redact_urls(str(e))
            if _carries_proxy(argv)
            else str(e)
        )
        # In JSON mode keep stdout pure JSON: emit the structured error envelope
        # there (exit 1) instead of a red stderr line.
        if args.json:
            print(json.dumps(error_envelope(e), indent=2))
        else:
            error(f"Error: {message}")
        sys.exit(1)
    except KeyboardInterrupt:
        # Route the cancellation note to stderr in JSON mode so stdout stays
        # parseable (the guarantee covers completion / handled errors, not Ctrl-C).
        print(
            f"\n{dimmed('Operation cancelled')}",
            file=sys.stderr if args.json else sys.stdout,
        )
        sys.exit(130)

    if args.json and payload is not None:
        print(json.dumps(payload, indent=2))

    # Passive update notification (never fails). Skipped after --purge so we
    # don't immediately recreate <backup_root>/cache/update_check.json inside
    # the directory we just deleted. Skipped after --upgrade as a safety guard
    # in case the dispatch is later refactored to fall through. Skipped when
    # `updates.check` is false, so no request goes to PyPI at all.
    if (
        not args.purge
        and not args.upgrade
        and not args.json
        and load_update_settings(paths.get_backup_root()).check
    ):
        from claude_swap.update_check import check_for_update

        msg = check_for_update(__version__)
        if msg:
            print(f"\n{muted(msg)}", file=sys.stderr)


if __name__ == "__main__":
    main()

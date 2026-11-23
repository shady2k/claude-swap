"""Multi-account switcher for Claude Code."""

from importlib.metadata import version
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from claude_swap.switcher import ClaudeAccountSwitcher

__version__ = version("claude-swap")
__all__ = ["ClaudeAccountSwitcher", "__version__"]


def __getattr__(name: str):
    # The PATH shim needs launch policy, not the account switcher's imports.
    if name == "ClaudeAccountSwitcher":
        from claude_swap.switcher import ClaudeAccountSwitcher

        return ClaudeAccountSwitcher
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

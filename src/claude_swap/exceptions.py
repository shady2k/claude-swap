"""Custom exceptions for Claude Switch."""


class ClaudeSwitchError(Exception):
    """Base exception for Claude Switch errors."""

    pass


class CredentialError(ClaudeSwitchError):
    """Error related to credential operations."""

    pass


class CredentialReadError(CredentialError):
    """Failed to read credentials."""

    pass


class CredentialWriteError(CredentialError):
    """Failed to write credentials."""

    pass


class ConfigError(ClaudeSwitchError):
    """Error related to configuration operations."""

    pass


class SwitchError(ClaudeSwitchError):
    """Error during account switch operation."""

    pass


class SessionError(ClaudeSwitchError):
    """Error setting up or launching a session-mode profile."""

    pass


class LockError(ClaudeSwitchError):
    """Error acquiring lock."""

    pass


class ClaudeCodeLockTimeout(LockError):
    """Timed out acquiring one of Claude Code's own advisory locks.

    Raised when ``~/.claude.lock`` / ``~/.claude.json.lock`` stays held past
    our bounded wait — usually Claude Code mid-token-refresh. Nothing has been
    mutated when this raises; the operation is safe to retry.
    """

    pass


class EgressCheckError(SessionError):
    """An account's expected exit IP/country could not be confirmed.

    Raised before Claude Code starts. An explicit launch reports it and
    stops; ``cswap run --auto`` takes it as a reason to try the next ranked
    account. The message names the slot, the expected and measured values
    (or why nothing could be measured), and never the proxy URL or its
    credentials.
    """

    pass


class AccountNotFoundError(ClaudeSwitchError):
    """Account not found."""

    pass


class ValidationError(ClaudeSwitchError):
    """Validation error."""

    pass


class TransferError(ClaudeSwitchError):
    """Error during account export or import."""

    pass


class MigrationError(ClaudeSwitchError):
    """Error migrating the backup directory between layouts (e.g. legacy → XDG)."""

    pass


class MigrationIncomplete(ClaudeSwitchError):
    """A one-time data migration could not finish for every record.

    Raised by run-once migrations (see ``migrations.py``) when some entries
    failed or the source backend was inaccessible. The migration runner treats
    this as "not applied" so the migration is retried on the next run rather
    than being recorded as done with records left behind.
    """

    pass

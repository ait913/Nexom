from __future__ import annotations
from typing import Any


class NexomError(Exception):
    """
    Base exception class for all Nexom errors.

    Attributes:
        code: Stable error code for programmatic handling.
        message: Human-readable error message.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code: str = code
        self.message: str = message
        super().__init__(message)

    def __str__(self) -> str:
        return f"{self.code} -> {self.message}"


# =========================
# Command / CLI
# =========================

class CommandArgumentsError(NexomError):
    """Raised when required CLI arguments are missing."""

    def __init__(self) -> None:
        super().__init__("CS01", "Missing command arguments.")


# =========================
# Path / Routing
# =========================

class PathNotFoundError(NexomError):
    """Raised when no matching route is found."""

    def __init__(self, path: str) -> None:
        super().__init__("P01", f"This path is not found. '{path}'")


class PathInvalidHandlerTypeError(NexomError):
    """Raised when a handler returns an invalid response type."""

    def __init__(self, handler: Any) -> None:
        name = getattr(handler, "__name__", repr(handler))
        super().__init__(
            "P02",
            "This handler returns an invalid type. "
            f"Return value must be Response or dict. '{name}'",
        )


class PathlibTypeError(NexomError):
    """Raised when a non-Path object is added to Pathlib."""

    def __init__(self) -> None:
        super().__init__("P03", "This list only accepts Path objects.")


class PathHandlerMissingArgError(NexomError):
    """Raised when a handler signature is invalid."""

    def __init__(self) -> None:
        super().__init__(
            "P04",
            "Handler must accept 'request' and 'args' as parameters.",
        )


# =========================
# Cookie
# =========================

class CookieInvalidValueError(NexomError):
    """Raised when a cookie value is invalid."""

    def __init__(self, value: str) -> None:
        super().__init__("C01", f"This value is invalid. '{value}'")


# =========================
# Template
# =========================

class TemplateNotFoundError(NexomError):
    """Raised when a template file cannot be found."""

    def __init__(self, name: str) -> None:
        super().__init__("T01", f"This template is not found. '{name}'")

class TemplateInvalidNameError(NexomError):
    """Raised when a template file/dir name violates Nexom template naming rules."""

    def __init__(self, key: str) -> None:
        super().__init__(
            "T02",
            f"This template name is invalid. '{key}'",
        )

class TemplatesNotDirError(NexomError):
    """Raised when the base templates directory is not a directory."""

    def __init__(self, path: str) -> None:
        super().__init__(
            "T03",
            f"This base path is not a directory. '{path}'"
        )


# =========================
# ObjectHTML
# =========================
class HTMLDocLibNotFoundError(NexomError):
    """Raised when an HTML document is not found in the library."""

    def __init__(self, name: str) -> None:
        super().__init__(
            "HD01",
            f"This HTML document is not found in the library. '{name}'",
        )

class ObjectHTMLInsertValueError(NexomError):
    """Raised when an insert value for ObjectHTML is invalid."""

    def __init__(self, name: str) -> None:
        super().__init__(
            "OH02",
            f"This insert value is invalid. '{name}'",
        )
class ObjectHTMLExtendsError(NexomError):
    """Raised when an extends for ObjectHTML is invalid."""

    def __init__(self, name: str) -> None:
        super().__init__(
            "OH03",
            f"This extends is invalid. '{name}'",
        )
class ObjectHTMLImportError(NexomError):
    """Raised when an import for ObjectHTML is invalid."""

    def __init__(self, name: str) -> None:
        super().__init__(
            "OH04",
            f"This import is invalid. '{name}'",
        )
class ObjectHTMLTypeError(NexomError):
    """Raised when an set HTMLDoc for type is valid."""

    def __init__(self) -> None:
        super().__init__(
            "OH05",
            f"This doc is not HTMLDoc'",
        )


# =========================
# DatabaseManager
# =========================
class DBError(NexomError):
    """
    Base class for database-related errors.

    This error represents a generic database failure that does not fall into
    a more specific category such as connection, integrity, operational, or
    programming errors.

    It is typically used as a catch-all or wrapper error when the underlying
    database exception cannot be safely or clearly classified.
    """

class DBMConnectionInvalidError(DBError):
    """
    Raised when the database manager connection is invalid or not initialized.

    This error indicates that the database manager (DBM) is in an unusable state,
    such as:
    - the database connection has not been established yet
    - the connection was already closed
    - the DBM was accessed before proper initialization

    This is typically a lifecycle or configuration error.
    """
    def __init__(self, message: str = "Not started") -> None:
        super().__init__(
            "DBM01",
            f"DBM connection is invalid. -> {message}",
        )


class DBOperationalError(DBError):
    """
    Raised when a database operational error occurs.

    This error represents failures related to the database runtime environment,
    such as:
    - inability to open or connect to the database file
    - database being locked
    - I/O errors during a query
    - transaction failures caused by the database state

    Typically maps to sqlite3.OperationalError.
    """
    def __init__(self, message: str) -> None:
        super().__init__(
            "DBM02",
            f"Database operational error. -> {message}",
        )


class DBIntegrityError(DBError):
    """
    Raised when a database integrity constraint is violated.

    This error indicates that a database constraint has been broken, such as:
    - UNIQUE constraint violations
    - FOREIGN KEY constraint failures
    - NOT NULL constraint violations
    - CHECK constraint failures

    Typically maps to sqlite3.IntegrityError.
    """
    def __init__(self, message: str) -> None:
        super().__init__(
            "DBM03",
            f"Database integrity constraint violated. -> {message}",
        )


class DBProgrammingError(DBError):
    """
    Raised when a database programming or SQL syntax error occurs.

    This error indicates a bug in application code or query construction, such as:
    - malformed SQL statements
    - referencing non-existent tables or columns
    - incorrect parameter binding
    - misuse of the database API

    Typically maps to sqlite3.ProgrammingError.
    """
    def __init__(self, message: str) -> None:
        super().__init__(
            "DBM04",
            f"Database programming error. -> {message}",
        )


# =========================
# Auth
# =========================

class AuthMissingFieldError(NexomError):
    """Required auth fields are missing."""
    def __init__(self, key: str) -> None:
        super().__init__("A01", f"Missing field. '{key}'")


class AuthUserIdAlreadyExistsError(NexomError):
    """user_id already exists (signup conflict)."""
    def __init__(self) -> None:
        super().__init__("A02", "This user_id is already in use.")


class AuthInvalidCredentialsError(NexomError):
    """user_id or password is invalid (login)."""
    def __init__(self) -> None:
        super().__init__("A03", "Invalid credentials.")


class AuthUserDisabledError(NexomError):
    """User is inactive/disabled."""
    def __init__(self) -> None:
        super().__init__("A04", "This user is disabled.")


class AuthTokenMissingError(NexomError):
    """Token is missing."""
    def __init__(self) -> None:
        super().__init__("A05", "Token is missing.")


class AuthTokenInvalidError(NexomError):
    """Token is invalid (malformed / not found)."""
    def __init__(self) -> None:
        super().__init__("A06", "This token is invalid.")


class AuthTokenExpiredError(NexomError):
    """Token is expired."""
    def __init__(self) -> None:
        super().__init__("A07", "This token has expired.")


class AuthTokenRevokedError(NexomError):
    """Token is revoked (logout etc)."""
    def __init__(self) -> None:
        super().__init__("A08", "This token is revoked.")


class AuthServiceUnavailableError(NexomError):
    """AuthService is unreachable / timed out / invalid response."""
    def __init__(self) -> None:
        super().__init__("A09", "Authentication service is currently unavailable.")

def _status_for_auth_error(code: str) -> int:
    return {
        "A01": 400,  # missing field
        "A02": 409,  # user_id already exists
        "A03": 401,  # invalid credentials
        "A04": 403,  # user disabled
        "A05": 401,  # token missing
        "A06": 401,  # token invalid
        "A07": 401,  # token expired
        "A08": 401,  # token revoked
        "A09": 503,  # auth service unavailable
    }.get(code, 400)
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
            "OH01",
            f"This insert value is invalid. '{name}'",
        )
class ObjectHTMLExtendsError(NexomError):
    """Raised when an extends for ObjectHTML is invalid."""

    def __init__(self, name: str) -> None:
        super().__init__(
            "OH02",
            f"This extends is invalid. '{name}'",
        )
class ObjectHTMLImportError(NexomError):
    """Raised when an import for ObjectHTML is invalid."""

    def __init__(self, name: str) -> None:
        super().__init__(
            "OH03",
            f"This import is invalid. '{name}'",
        )
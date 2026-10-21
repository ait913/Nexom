"""Logging utilities."""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock


__all__ = ["sanitize_log_field", "AppLogger", "AuthLogger"]

_handler_lock = Lock()


def sanitize_log_field(s: str) -> str:
    """Escape control characters in a log field."""
    if s is None:
        return "-"
    escapes = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}
    result = []
    for char in str(s):
        code = ord(char)
        if char in escapes:
            result.append(escapes[char])
        elif code < 0x20 or code == 0x7f:
            result.append(f"\\x{code:02x}")
        elif 0x80 <= code <= 0x9f or code in (0x2028, 0x2029):
            result.append(f"\\u{code:04x}")
        else:
            result.append(char)
    return "".join(result)


def _file_logger(path: Path, max_bytes: int, backup_count: int) -> logging.Logger:
    """Reuse a rotating handler for each resolved path."""
    resolved_path = path.resolve()
    logger = logging.getLogger(f"nexom.log.{resolved_path}")
    with _handler_lock:
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not any(
            getattr(handler, "baseFilename", None) == str(resolved_path)
            for handler in logger.handlers
        ):
            handler = RotatingFileHandler(
                resolved_path, maxBytes=max_bytes, backupCount=backup_count,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
    return logger


# =========================
# App Logger
# =========================

class AppLogger:
    """
    Application-level logger.

    Used for:
    - info
    - warn
    - error
    - access
    """

    def __init__(
        self,
        *,
        info: str | Path | None = None,
        warn: str | Path | None = None,
        error: str | Path | None = None,
        access: str | Path | None = None,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
    ) -> None:
        self.info_path = self._norm(info)
        self.warn_path = self._norm(warn)
        self.error_path = self._norm(error)
        self.access_path = self._norm(access)
        self._loggers = {
            path: _file_logger(path, max_bytes, backup_count)
            for path in (self.info_path, self.warn_path, self.error_path, self.access_path)
            if path is not None
        }

    def info(self, msg: str) -> None:
        """Write an INFO log line."""
        self._write(self.info_path, "INFO", msg)

    def warn(self, msg: str) -> None:
        """Write a WARN log line."""
        self._write(self.warn_path, "WARN", msg)

    def error(self, err: Exception | str) -> None:
        """Write an ERROR log line (with traceback if Exception)."""
        if self.error_path is None:
            return
        trace = "".join(traceback.format_exception(err)) if isinstance(err, Exception) else None
        self._write(self.error_path, "ERROR", str(err), trace=trace)

    def access(self, msg: str) -> None:
        """Write an ACCESS log line."""
        self._write(self.access_path, "ACCESS", msg)

    # ---------- internal ----------

    def _norm(self, path: str | Path | None) -> Path | None:
        if not path:
            return None
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _write(
        self, path: Path | None, level: str, msg: str, *, trace: str | None = None,
    ) -> None:
        if path is None:
            return

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{level}] {sanitize_log_field(msg)}"
        if trace:
            line += "".join(
                f"\n    {sanitize_log_field(part)}" for part in trace.splitlines()
            )
        self._loggers[path].log(logging.INFO, line)


# =========================
# Auth Logger
# =========================

class AuthLogger:
    """
    Authentication / Security logger.

    Used for:
    - login success / failure
    - signup
    - token verification failure
    """

    def __init__(
        self, path: str | Path, *, max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = _file_logger(self.path, max_bytes, backup_count)

    def login_success(self, *, user_id: str, ip: str | None = None) -> None:
        """Log a successful login."""
        self._write("LOGIN_OK", user_id, ip)

    def login_failed(self, *, user_id: str, ip: str | None = None) -> None:
        """Log a failed login."""
        self._write("LOGIN_NG", user_id, ip)

    def signup(self, *, user_id: str, ip: str | None = None) -> None:
        """Log a signup event."""
        self._write("SIGNUP", user_id, ip)

    def token_invalid(self, *, token: str | None, ip: str | None = None) -> None:
        """Log an invalid token attempt."""
        t = token[:8] + "..." if token else "none"
        self._write("TOKEN_INVALID", t, ip)

    # ---------- internal ----------

    def _write(
        self, action: str, subject: str, ip: str | None, *,
        detail: str | None = None, include_detail: bool = False,
    ) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        line = (
            f"[{ts}] [{sanitize_log_field(action)}] "
            f"subject={sanitize_log_field(subject)} ip={sanitize_log_field(ip or '-')}"
        )
        if include_detail:
            line += f" detail={sanitize_log_field(detail or '-')}"
        self._logger.log(logging.INFO, line)

    def event(
        self, action: str, *, subject: str, ip: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Log a generic authentication or security event."""
        self._write(action, subject, ip, detail=detail, include_detail=True)

from __future__ import annotations

import traceback
from datetime import datetime
from pathlib import Path


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
    ) -> None:
        self.info_path = self._norm(info)
        self.warn_path = self._norm(warn)
        self.error_path = self._norm(error)
        self.access_path = self._norm(access)

    def info(self, msg: str) -> None:
        self._write(self.info_path, "INFO", msg)

    def warn(self, msg: str) -> None:
        self._write(self.warn_path, "WARN", msg)

    def error(self, err: Exception | str) -> None:
        if isinstance(err, Exception):
            msg = "".join(traceback.format_exception(err))
        else:
            msg = str(err)
        self._write(self.error_path, "ERROR", msg)

    def access(self, msg: str) -> None:
        self._write(self.access_path, "ACCESS", msg)

    # ---------- internal ----------

    def _norm(self, path: str | Path | None) -> Path | None:
        if not path:
            return None
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _write(self, path: Path | None, level: str, msg: str) -> None:
        if path is None:
            return

        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{level}] {msg}\n"

        with path.open("a", encoding="utf-8") as f:
            f.write(line)


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

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def login_success(self, *, user_id: str, ip: str | None = None) -> None:
        self._write("LOGIN_OK", user_id, ip)

    def login_failed(self, *, user_id: str, ip: str | None = None) -> None:
        self._write("LOGIN_NG", user_id, ip)

    def signup(self, *, user_id: str, ip: str | None = None) -> None:
        self._write("SIGNUP", user_id, ip)

    def token_invalid(self, *, token: str | None, ip: str | None = None) -> None:
        t = token[:8] + "..." if token else "none"
        self._write("TOKEN_INVALID", t, ip)

    # ---------- internal ----------

    def _write(self, action: str, subject: str, ip: str | None) -> None:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        ip_txt = ip or "-"
        line = f"[{ts}] [{action}] subject={subject} ip={ip_txt}\n"

        with self.path.open("a", encoding="utf-8") as f:
            f.write(line)
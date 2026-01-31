# src/nexom/app/auth.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import secrets
import time
import hashlib
import hmac
import json
import sqlite3
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import URLError, HTTPError

from .request import Request
from .response import JsonResponse
from .db import DatabaseManager
from .path import Path, Router
from ..core.log import AuthLogger

from ..core.error import (
    NexomError,
    AuthMissingFieldError,          # A01
    AuthUserIdAlreadyExistsError,   # A02
    AuthInvalidCredentialsError,    # A03
    AuthUserDisabledError,          # A04
    AuthTokenMissingError,          # A05
    AuthTokenInvalidError,          # A06
    AuthTokenExpiredError,          # A07
    AuthTokenRevokedError,          # A08
    AuthServiceUnavailableError,    # A09
    _status_for_auth_error,

    DBError,
    DBMConnectionInvalidError,
    DBOperationalError,
    DBIntegrityError,
    DBProgrammingError,
)

# --------------------
# utils
# --------------------

def _now() -> int:
    return int(time.time())


def _rand(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def _make_salt(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)


def _hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return dk.hex()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------
# variables (internal)
# --------------------

KEY_NAME = "_nxt"


# --------------------
# models (internal)
# --------------------

@dataclass
class LocalSession:
    sid: str
    uid: str
    user_id: str
    public_name: str
    token: str
    expires_at: int
    revoked_at: int | None
    user_agent: str | None

@dataclass
class Session:
    pid: str
    user_id: str
    public_name: str
    token: str
    expires_at: int
    user_agent: str | None


# --------------------
# AuthService (API only)
# --------------------

class AuthService:
    """
    Auth API service (JSON only).
    """

    def __init__(
        self,
        db_path: str,
        log_path: str,
        *,
        ttl_sec: int = 60 * 60 * 24 * 7,
        prefix: str = "",
    ) -> None:
        self.dbm = AuthDBM(db_path)
        self.ttl_sec = ttl_sec

        p = prefix.strip("/")

        def _p(x: str) -> str:
            return f"{p}/{x}".strip("/") if p else x

        self.routing = Router(
            Path(_p("signup"), self.signup, "AuthSignup"),
            Path(_p("login"), self.login, "AuthLogin"),
            Path(_p("logout"), self.logout, "AuthLogout"),
            Path(_p("verify"), self.verify, "AuthVerify"),
        )

        self.logger = AuthLogger(log_path)

    def handler(self, environ: dict) -> JsonResponse:
        req = Request(environ)
        try:
            return self.routing.handle(req)

        except NexomError as e:
            # error code -> proper HTTP status
            status = _status_for_auth_error(e.code)
            return JsonResponse({"ok": False, "error": e.code}, status=status)

        except Exception as e:
            return JsonResponse({"ok": False, "error": "InternalError"}, status=500)

    # ---- handlers ----

    def signup(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        user_id = str(data.get("user_id") or "").strip()
        public_name = str(data.get("public_name") or "").strip()
        password = str(data.get("password") or "")

        self.dbm.signup(user_id=user_id, public_name=public_name, password=password)
        return JsonResponse({"ok": True}, status=201)

    def login(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        user_id = str(data.get("user_id") or "").strip()
        password = str(data.get("password") or "")

        lsess = self.dbm.login(
            user_id,
            password,
            user_agent=request.headers.get("user-agent"),
            ttl_sec=self.ttl_sec,
        )

        return JsonResponse(
            {
                "ok": True,
                "pid":lsess.uid,
                "user_id": lsess.user_id,
                "public_name":lsess.public_name,
                "token": lsess.token,
                "expires_at": lsess.expires_at,
                "user_agent": lsess.user_agent
            }
        )

    def logout(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        token = str((request.json() or {}).get("token") or "")
        if token:
            self.dbm.logout(token)
        return JsonResponse({"ok": True})

    def verify(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        token = str((request.json() or {}).get("token") or "")
        lsess = self.dbm.verify(token)
        if not lsess:
            return JsonResponse({"active": False}, status=200)

        return JsonResponse(
            {
                "active": True,
                "pid":lsess.uid,
                "user_id": lsess.user_id,
                "public_name":lsess.public_name,
                "expires_at": lsess.expires_at,
                "user_agent": lsess.user_agent
            },
            status=200,
        )


# --------------------
# AuthClient (App側)
# --------------------

class AuthClient:
    """AuthService を HTTP で叩くクライアント"""

    def __init__(self, auth_url: str, *, timeout: float = 3.0) -> None:
        base = auth_url.rstrip("/")
        self.signup_url = base + "/signup"
        self.login_url = base + "/login"
        self.logout_url = base + "/logout"
        self.verify_url = base + "/verify"
        self.timeout = timeout

    def _post(self, url: str, body: dict) -> dict:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = UrlRequest(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                text = raw.decode("utf-8", errors="replace")
                return json.loads(text) if text else {}

        except HTTPError as e:
            try:
                raw = e.read()
                text = raw.decode("utf-8", errors="replace")
                return json.loads(text) if text else {"ok": False, "error": f"HTTP_{e.code}"}
            except Exception:
                return {"ok": False, "error": f"HTTP_{e.code}"}

        except (URLError, TimeoutError):
            raise AuthServiceUnavailableError()

        except json.JSONDecodeError:
            raise AuthServiceUnavailableError()

    def signup(self, *, user_id: str, public_name: str, password: str) -> None:
        d = self._post(
            self.signup_url,
            {"user_id": user_id, "public_name": public_name, "password": password},
        )
        if d.get("ok"):
            return 
        self._raise_from_error_code(str(d.get("error") or ""))

    def login(self, *, user_id: str, password: str) -> Session:
        d = self._post(self.login_url, {"user_id": user_id, "password": password})
        if not d.get("ok"):
            self._raise_from_error_code(str(d.get("error") or ""))

        return Session(str(d["pid"]), str(d["user_id"]), str(d["public_name"]), str(d["token"]), int(d["expires_at"]), str(d["user_agent"]))

    def verify_token(self, token: str) -> Session | None:
        d = self._post(self.verify_url, {"token": token})

        if d.get("active") is True:
            return Session(str(d["pid"]), str(d["user_id"]), str(d["public_name"]), token, int(d["expires_at"]), str(d["user_agent"]))

        return None

    def logout(self, *, token: str) -> None:
        d = self._post(self.logout_url, {"token": token})
        if d.get("ok"):
            return
        self._raise_from_error_code(str(d.get("error") or ""))

    def _raise_from_error_code(self, code: str) -> None:
        if code == "A01":
            raise AuthMissingFieldError("unknown")
        if code == "A02":
            raise AuthUserIdAlreadyExistsError()
        if code == "A03":
            raise AuthInvalidCredentialsError()
        if code == "A04":
            raise AuthUserDisabledError()
        if code == "A05":
            raise AuthTokenMissingError()
        if code == "A06":
            raise AuthTokenInvalidError()
        if code == "A07":
            raise AuthTokenExpiredError()
        if code == "A08":
            raise AuthTokenRevokedError()
        if code == "A09":
            raise AuthServiceUnavailableError()
    
        # 想定外レスポンス
        raise AuthServiceUnavailableError()


# --------------------
# DB
# --------------------

class AuthDBM(DatabaseManager):
    def _init(self) -> None:
        self.execute_many(
            [
                (
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        uid TEXT PRIMARY KEY,
                        user_id TEXT UNIQUE NOT NULL,
                        public_name TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        password_salt TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active INTEGER NOT NULL DEFAULT 1
                    );
                    """,
                    (),
                ),
                (
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        sid TEXT PRIMARY KEY,
                        uid TEXT NOT NULL REFERENCES users(uid),
                        token_hash TEXT UNIQUE NOT NULL,
                        expires_at INTEGER NOT NULL,
                        revoked_at INTEGER,
                        user_agent TEXT
                    );
                    """,
                    (),
                ),
            ]
        )

    def signup(self, user_id: str, public_name: str, password: str) -> None:
        if not user_id:
            raise AuthMissingFieldError("user_id")
        if not public_name:
            raise AuthMissingFieldError("public_name")
        if not password:
            raise AuthMissingFieldError("password")

        salt = _make_salt()
        uid = _rand()

        try:
            self.execute(
                "INSERT INTO users VALUES(?,?,?,?,?,?,?)",
                uid,
                user_id,
                public_name,
                _hash_password(password, salt),
                salt,
                None,
                1,
            )
        except DBIntegrityError:
            raise AuthUserIdAlreadyExistsError()
        except Exception as e:
            raise AuthServiceUnavailableError()

    def login(self, user_id: str, password: str, *, user_agent: str | None, ttl_sec: int) -> LocalSession:
        if not user_id:
            raise AuthMissingFieldError("user_id")
        if not password:
            raise AuthMissingFieldError("password")

        rows = self.execute(
            "SELECT uid, user_id, public_name, password_hash, password_salt, is_active FROM users WHERE user_id=?",
            user_id,
        )
        if not rows:
            raise AuthInvalidCredentialsError()

        uid, user_id, public_name, pw_hash, salt, active = rows[0]
        if not active:
            raise AuthUserDisabledError()

        if not hmac.compare_digest(_hash_password(password, str(salt)), str(pw_hash)):
            raise AuthInvalidCredentialsError()

        token = _rand()
        exp = _now() + ttl_sec
        sid = _rand()

        self.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
            sid,
            uid,
            _token_hash(token),
            exp,
            None,
            user_agent,
        )

        return LocalSession(sid, uid, user_id, public_name, token, exp, None, user_agent)

    def logout(self, token: str) -> None:
        if not token:
            raise AuthMissingFieldError("token")

        self.execute(
            "UPDATE sessions SET revoked_at=? WHERE token_hash=?",
            _now(),
            _token_hash(token),
        )

    def verify(self, token: str | None) -> LocalSession | None:
        if not token:
            return None

        rows = self.execute(
            """
            SELECT s.sid, s.uid, u.user_id, u.public_name, s.expires_at, s.revoked_at, s.user_agent
            FROM sessions s
            JOIN users u ON u.uid=s.uid
            WHERE s.token_hash=?
            """,
            _token_hash(token),
        )
        if not rows:
            return None

        sid, uid, user_id, public_name, exp, rev, ua = rows[0]
        if rev or int(exp) <= _now():
            return None

        return LocalSession(str(sid), str(uid), str(user_id), str(public_name), str(token), int(exp), None, ua)
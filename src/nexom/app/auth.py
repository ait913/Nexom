# src/nexom/app/auth.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, override
import secrets
import time
import hashlib
import hmac
import json
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import URLError, HTTPError

from .request import Request
from .response import JsonResponse
from .db import DatabaseManager
from .path import Path, Pathlib
from ..core.log import AuthLogger

from ..core.error import (
    NexomError,
    AuthMissingFieldError,
    AuthInvalidCredentialsError,
    AuthUserDisabledError,
    AuthTokenInvalidError,
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
# models (internal)
# --------------------

@dataclass
class Session:
    sid: str
    uid: str
    user_id: str
    token: str
    expires_at: int
    revoked_at: int | None
    user_agent: str | None

# --------------------
# AuthService (API only)
# --------------------

class AuthService:
    """
    Auth API service (JSON only).
    """

    def __init__(self, db_path: str, log_path: str, *, ttl_sec: int = 60 * 60 * 24 * 7, prefix: str = "") -> None:
        self.dbm = AuthDBM(db_path)
        self.ttl_sec = ttl_sec

        p = prefix.strip("/")
        def _p(x: str) -> str:
            return f"{p}/{x}".strip("/") if p else x

        self.routing = Pathlib(
            Path(_p("signup"), self.signup, "AuthSignup"),
            Path(_p("login"), self.login, "AuthLogin"),
            Path(_p("logout"), self.logout, "AuthLogout"),
            Path(_p("verify"), self.verify, "AuthVerify"),
        )

        self.logger = AuthLogger(log_path)

    def handler(self, environ: dict) -> JsonResponse:
        req = Request(environ)
        try:
            route = self.routing.get(req.path)
            return route.call_handler(req)
        except NexomError as e:
            return JsonResponse({"ok": False, "error": e.code}, status=400)
        except Exception:
            return JsonResponse({"ok": False, "error": "InternalError"}, status=500)

    # ---- handlers ----

    def signup(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False}, status=405)

        data = request.json() or {}
        self.dbm.signup(
            user_id=str(data.get("user_id") or "").strip(),
            public_name=str(data.get("public_name") or "").strip(),
            password=str(data.get("password") or ""),
        )
        return JsonResponse({"ok": True}, status=201)

    def login(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False}, status=405)

        data = request.json() or {}
        sess = self.dbm.login(
            str(data.get("user_id") or "").strip(),
            str(data.get("password") or ""),
            user_agent=request.headers.get("user-agent"),
            ttl_sec=self.ttl_sec,
        )

        return JsonResponse({
            "ok": True,
            "user_id": sess.user_id,
            "token": sess.token,
            "expires_at": sess.expires_at,
        })

    def logout(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False}, status=405)

        token = str((request.json() or {}).get("token") or "")
        if token:
            self.dbm.logout(token)
        return JsonResponse({"ok": True})

    def verify(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False}, status=405)

        token = str((request.json() or {}).get("token") or "")
        sess = self.dbm.verify(token)
        if not sess:
            return JsonResponse({"active": False})

        return JsonResponse({
            "active": True,
            "user_id": sess.user_id,
            "expires_at": sess.expires_at,
        })

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
        payload = json.dumps(body).encode("utf-8")
        req = UrlRequest(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode("utf-8"))
        except (HTTPError, URLError, json.JSONDecodeError) as e:
            print(e)
            raise AuthTokenInvalidError()
        return data

    def signup(self, *, user_id: str, public_name: str, password: str) -> bool:
        return bool(self._post(self.signup_url, {
            "user_id": user_id,
            "public_name": public_name,
            "password": password,
        }).get("ok"))

    def login(self, *, user_id: str, password: str) -> tuple[str, str, int]:
        d = self._post(self.login_url, {"user_id": user_id, "password": password})
        return d["token"], d["user_id"], d["expires_at"]

    def verify_token(self, *, token: str) -> tuple[bool, Optional[str], Optional[int]]:
        d = self._post(self.verify_url, {"token": token})
        if not d.get("active"):
            return False, None, None
        return True, d["user_id"], d["expires_at"]

    def logout(self, *, token: str) -> bool:
        return bool(self._post(self.logout_url, {"token": token}).get("ok"))

# --------------------
# DB
# --------------------

class AuthDBM(DatabaseManager):
    @override
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
                )
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
        self.execute(
            "INSERT INTO users VALUES(?,?,?,?,?,?,?)",
            _rand(),
            user_id,
            public_name,
            _hash_password(password, salt),
            salt,
            None,
            1,
        )

    def login(self, user_id: str, password: str, *, user_agent: str | None, ttl_sec: int) -> Session:
        rows = self.execute(
            "SELECT uid, user_id, password_hash, password_salt, is_active FROM users WHERE user_id=?",
            user_id,
        )
        if not rows:
            raise AuthInvalidCredentialsError()

        uid, uid_text, pw_hash, salt, active = rows[0]
        if not active:
            raise AuthUserDisabledError()
        if not hmac.compare_digest(_hash_password(password, salt), pw_hash):
            raise AuthInvalidCredentialsError()

        token = _rand()
        exp = _now() + ttl_sec

        self.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
            _rand(),
            uid,
            _token_hash(token),
            exp,
            None,
            user_agent,
        )

        return Session("", uid, uid_text, token, exp, None, user_agent)

    def logout(self, token: str) -> None:
        self.execute(
            "UPDATE sessions SET revoked_at=? WHERE token_hash=?",
            _now(),
            _token_hash(token),
        )

    def verify(self, token: str | None) -> Session | None:
        if not token:
            return None

        rows = self.execute(
            """
            SELECT s.sid, s.uid, u.user_id, s.expires_at, s.revoked_at, s.user_agent
            FROM sessions s JOIN users u ON u.uid=s.uid
            WHERE s.token_hash=?
            """,
            _token_hash(token),
        )
        if not rows:
            return None

        sid, uid, user_id, exp, rev, ua = rows[0]
        if rev or exp <= _now():
            return None

        return Session(sid, uid, user_id, token, exp, None, ua)
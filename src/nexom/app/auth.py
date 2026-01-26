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
# AuthService (API-only)
# --------------------


class AuthService:
    """
    Auth API service (service-to-service / JS client).

    IMPORTANT:
    - HTTP JSON must NOT include uid.
    - user identification for external use is user_id.
    """

    def __init__(self, db_path: str, *, ttl_sec: int = 60 * 60 * 24 * 7, prefix: str = "") -> None:
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

    def handler(self, environ: dict) -> JsonResponse:
        req = Request(environ)
        try:
            route = self.routing.get(req.path)
            return route.call_handler(req)

        except NexomError as e:
            return JsonResponse({"error": e.code}, status=400)

        except Exception:
            return JsonResponse({"error": "Internal Server Error"}, status=500)

    # ---- handlers (Pathlib signature) ----

    def signup(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        data = request.json() or {}
        user_id = str(data.get("user_id") or "").strip()
        public_name = str(data.get("public_name") or "").strip()
        password = str(data.get("password") or "")

        self.dbm.signup(user_id=user_id, public_name=public_name, password=password)
        return JsonResponse({"ok": True}, status=201)

    def login(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        data = request.json() or {}
        user_id = str(data.get("user_id") or "").strip()
        password = str(data.get("password") or "")

        sess = self.dbm.login(
            user_id,
            password,
            user_agent=request.headers.get("user-agent"),
            ttl_sec=self.ttl_sec,
        )

        # uid は返さない
        return JsonResponse(
            {
                "ok": True,
                "user_id": sess.user_id,
                "token": sess.token,
                "expires_at": sess.expires_at,
            }
        )

    def logout(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "").strip()
        if token:
            self.dbm.logout(token)

        return JsonResponse({"ok": True})

    def verify(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "").strip()

        sess = self.dbm.verify(token)
        if not sess:
            return JsonResponse({"active": False})

        # uid は返さない
        return JsonResponse({"active": True, "user_id": sess.user_id, "expires_at": sess.expires_at})


# --------------------
# AuthClient (HTTP)
# --------------------


class AuthClient:
    """Call the AuthService over HTTP(S) from an app/service."""

    def __init__(
        self,
        auth_url: str,
        *,
        timeout: float = 3.0,
        signup_path: str = "/signup",
        login_path: str = "/login",
        logout_path: str = "/logout",
        verify_path: str = "/verify",
    ) -> None:
        base = auth_url.rstrip("/")
        self._signup_url = f"{base}{signup_path}"
        self._login_url = f"{base}{login_path}"
        self._logout_url = f"{base}{logout_path}"
        self._verify_url = f"{base}{verify_path}"
        self.timeout = timeout

    def _post_json(self, url: str, body: dict) -> dict:
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
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except (HTTPError, URLError) as _:
            raise AuthTokenInvalidError()

        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise AuthTokenInvalidError()

        if not isinstance(data, dict):
            raise AuthTokenInvalidError()

        if data.get("error"):
            raise AuthTokenInvalidError()

        return data

    def signup(self, *, user_id: str, public_name: str, password: str) -> bool:
        data = self._post_json(
            self._signup_url,
            {"user_id": user_id, "public_name": public_name, "password": password},
        )
        return bool(data.get("ok"))

    def login(self, *, user_id: str, password: str) -> tuple[str, str, int]:
        """
        Returns: (token, user_id, expires_at)
        """
        data = self._post_json(self._login_url, {"user_id": user_id, "password": password})

        token = data.get("token")
        uid_text = data.get("user_id")
        exp = data.get("expires_at")

        if not isinstance(token, str) or not isinstance(uid_text, str) or not isinstance(exp, int):
            raise AuthTokenInvalidError()

        return token, uid_text, exp

    def logout(self, *, token: str) -> bool:
        data = self._post_json(self._logout_url, {"token": token})
        return bool(data.get("ok"))

    def verify_token(self, *, token: str) -> tuple[bool, str | None, int | None]:
        """
        Returns: (active, user_id, expires_at)
        """
        data = self._post_json(self._verify_url, {"token": token})

        active = bool(data.get("active"))
        if not active:
            return False, None, None

        user_id = data.get("user_id")
        exp = data.get("expires_at")
        if not isinstance(user_id, str) or not isinstance(exp, int):
            raise AuthTokenInvalidError()

        return True, user_id, exp


# --------------------
# DB layer
# --------------------


class AuthDBM(DatabaseManager):
    @override
    def _init(self) -> None:
        self.execute_many(
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
        )

    def signup(self, user_id: str, public_name: str, password: str) -> None:
        if not user_id:
            raise AuthMissingFieldError("user_id")
        if not public_name:
            raise AuthMissingFieldError("public_name")
        if not password:
            raise AuthMissingFieldError("password")

        salt = _make_salt()
        pw_hash = _hash_password(password, salt)
        uid = _rand()

        self.execute(
            "INSERT INTO users(uid, user_id, public_name, password_hash, password_salt) VALUES(?,?,?,?,?)",
            uid,
            user_id,
            public_name,
            pw_hash,
            salt,
        )

    def login(self, user_id: str, password: str, *, user_agent: str | None, ttl_sec: int) -> Session:
        rows = self.execute(
            "SELECT uid, user_id, password_hash, password_salt, is_active FROM users WHERE user_id = ?",
            user_id,
        )
        if not rows:
            raise AuthInvalidCredentialsError()

        uid, user_id_db, pw_hash, salt, active = rows[0]
        if not active:
            raise AuthUserDisabledError()

        if not hmac.compare_digest(_hash_password(password, salt), pw_hash):
            raise AuthInvalidCredentialsError()

        sid = _rand()
        token = _rand()
        expires = _now() + ttl_sec

        self.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
            sid,
            uid,
            _token_hash(token),
            expires,
            None,
            user_agent,
        )

        return Session(sid=sid, uid=uid, user_id=user_id_db, token=token, expires_at=expires, revoked_at=None, user_agent=user_agent)

    def logout(self, token: str) -> None:
        self.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            _now(),
            _token_hash(token),
        )

    def verify(self, token: str | None) -> Session | None:
        if not token:
            return None

        rows = self.execute(
            """
            SELECT
              s.sid, s.uid, u.user_id, s.expires_at, s.revoked_at, s.user_agent
            FROM sessions s
            JOIN users u ON u.uid = s.uid
            WHERE s.token_hash = ?
            """,
            _token_hash(token),
        )
        if not rows:
            return None

        sid, uid, user_id, exp, rev, ua = rows[0]
        if rev or exp <= _now():
            return None

        return Session(sid=sid, uid=uid, user_id=user_id, token=token, expires_at=exp, revoked_at=None, user_agent=ua)
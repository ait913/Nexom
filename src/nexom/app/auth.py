from __future__ import annotations

from dataclasses import dataclass
from typing import override
import secrets
import time
import hashlib
import hmac

from .request import Request
from .response import JsonResponse
from .db import DatabaseManager


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
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return dk.hex()


def _parse_bearer(value: str | None) -> str | None:
    if not value:
        return None
    if not value.lower().startswith("bearer "):
        return None
    return value.split(" ", 1)[1].strip() or None


def _cookie(name: str, value: str, *, max_age: int) -> str:
    return f"{name}={value}; Path=/; Max-Age={max_age}; HttpOnly"


def _clear_cookie(name: str) -> str:
    return f"{name}=; Path=/; Max-Age=0; HttpOnly"


# --------------------
# models
# --------------------

@dataclass
class User:
    uid: str
    user_id: str
    public_name: str
    password_hash: str
    password_salt: str
    is_active: int


@dataclass
class Session:
    sid: str
    uid: str
    token: str
    expires_at: int
    revoked_at: int | None
    user_agent: str | None


# --------------------
# AuthService (user-facing)
# --------------------

class AuthService:
    COOKIE_NAME = "_nes"

    def __init__(self, db_path: str, *, ttl_sec: int = 60 * 60 * 24 * 7) -> None:
        self.dbm = AuthDBM(db_path)
        self.ttl_sec = ttl_sec

    def handler(self, environ: dict) -> JsonResponse:
        req: Request = Request(environ)
        path: str = req.path
        method: str = req.method
        data: dict = req.json() or {}

        try:
            if method == "POST" and path == "signup":
                self.dbm.signup(
                    user_id=data.get("user_id", ""),
                    public_name=data.get("public_name", ""),
                    password=data.get("password", ""),
                )
                return JsonResponse({"ok": True}, status=201)

            if method == "POST" and path == "login":
                sess = self.dbm.login(
                    data.get("user_id", ""),
                    data.get("password", ""),
                    user_agent=req.headers.get("user-agent"),
                    ttl_sec=self.ttl_sec,
                )
                return JsonResponse(
                    {"ok": True, "expires_at": sess.expires_at},
                    cookie=_cookie(self.COOKIE_NAME, sess.token, max_age=self.ttl_sec),
                )

            if method == "POST" and path == "logout":
                token = getattr(req.cookie, self.COOKIE_NAME, None) if req.cookie else None
                if token:
                    self.dbm.logout(token)
                return JsonResponse(
                    {"ok": True},
                    cookie=_clear_cookie(self.COOKIE_NAME),
                )

            if method == "POST" and path == "verify":
                token = data.get("token") or (
                    getattr(req.cookie, self.COOKIE_NAME, None) if req.cookie else None
                )
                sess = self.dbm.verify(token)
                if not sess:
                    return JsonResponse({"active": False})
                return JsonResponse(
                    {"active": True, "uid": sess.uid, "expires_at": sess.expires_at}
                )

            return JsonResponse({"error": "Not Found"}, status=404)

        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=400)
        except Exception:
            return JsonResponse({"error": "Internal Server Error"}, status=500)


# --------------------
# AuthVerify (service-facing)
# --------------------

class AuthVerify:
    def __init__(self, dbm: AuthDBM) -> None:
        self.dbm = dbm

    def verify_request(self, req: Request) -> Session | None:
        token = _parse_bearer(req.headers.get("authorization"))
        return self.dbm.verify(token)

    def verify_token(self, token: str) -> Session | None:
        return self.dbm.verify(token)


# --------------------
# DB layer
# --------------------

class AuthDBM(DatabaseManager):
    @override
    def _init(self) -> None:
        self.excute_many(
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
                    token TEXT UNIQUE NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    user_agent TEXT
                );
                """,
                (),
            ),
        )

    def signup(self, user_id: str, public_name: str, password: str) -> None:
        if not user_id or not public_name or not password:
            raise ValueError("missing fields")

        salt = _make_salt()
        pw_hash = _hash_password(password, salt)
        uid = _rand()

        self.excute(
            "INSERT INTO users(uid, user_id, public_name, password_hash, password_salt) VALUES(?,?,?,?,?)",
            uid, user_id, public_name, pw_hash, salt
        )

    def login(self, user_id: str, password: str, *, user_agent: str | None, ttl_sec: int) -> Session:
        rows = self.excute(
            "SELECT uid, password_hash, password_salt, is_active FROM users WHERE user_id = ?",
            user_id
        )
        if not rows:
            raise ValueError("invalid credentials")

        uid, pw_hash, salt, active = rows[0]
        if not active:
            raise ValueError("user disabled")

        if not hmac.compare_digest(_hash_password(password, salt), pw_hash):
            raise ValueError("invalid credentials")

        sid = _rand()
        token = _rand()
        expires = _now() + ttl_sec

        self.excute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
            sid, uid, token, expires, None, user_agent
        )

        return Session(sid, uid, token, expires, None, user_agent)

    def logout(self, token: str) -> None:
        self.excute(
            "UPDATE sessions SET revoked_at = ? WHERE token = ?",
            _now(), token
        )

    def verify(self, token: str | None) -> Session | None:
        if not token:
            return None

        rows = self.excute(
            "SELECT sid, uid, token, expires_at, revoked_at, user_agent FROM sessions WHERE token = ?",
            token
        )
        if not rows:
            return None

        sid, uid, tok, exp, rev, ua = rows[0]
        if rev or exp <= _now():
            return None

        return Session(sid, uid, tok, exp, None, ua)
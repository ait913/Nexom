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
from .cookie import Cookie
from .user import User

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
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return dk.hex()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_bearer(value: str | None) -> str | None:
    if not value:
        return None
    if not value.lower().startswith("bearer "):
        return None
    return value.split(" ", 1)[1].strip() or None


# --------------------
# models
# --------------------

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

    def __init__(self, db_path: str, *, ttl_sec: int = 60 * 60 * 24 * 7, prefix: str = "") -> None:
        self.dbm = AuthDBM(db_path)
        self.ttl_sec = ttl_sec

        p = prefix.strip("/")
        def _p(x: str) -> str:
            return f"{p}/{x}".strip("/") if p else x

        # Pathlib routing
        self.routing = Pathlib(
            Path(_p("signup"), self.signup, "AuthSignup"),
            Path(_p("login"), self.login, "AuthLogin"),
            Path(_p("logout"), self.logout, "AuthLogout"),
            Path(_p("verify"), self.verify, "AuthVerify"),
        )

    def handler(self, environ: dict) -> JsonResponse:
        """
        WSGI entry for auth service.
        """
        req = Request(environ)
        try:
            route = self.routing.get(req.path)  # not found -> PathNotFoundError  [oai_citation:6‡GitHub](https://raw.githubusercontent.com/ait913/Nexom/refs/heads/dev/src/nexom/app/path.py)
            return route.call_handler(req)  # handler(request,args)  [oai_citation:7‡GitHub](https://raw.githubusercontent.com/ait913/Nexom/refs/heads/dev/src/nexom/app/path.py)

        except NexomError as e:
            # Show error code only for security.
            return JsonResponse({"error": e.code}, status=400)

        except Exception:
            return JsonResponse({"error": "Internal Server Error"}, status=500)

    # ---- handlers (Pathlib signature) ----

    def signup(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        data = request.json() or {}
        user_id = data.get("user_id", "")
        public_name = data.get("public_name", "")
        password = data.get("password", "")

        self.dbm.signup(user_id=user_id, public_name=public_name, password=password)
        return JsonResponse({"ok": True}, status=201)

    def login(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        data = request.json() or {}
        sess = self.dbm.login(
            data.get("user_id", ""),
            data.get("password", ""),
            user_agent=request.headers.get("user-agent"),
            ttl_sec=self.ttl_sec,
        )

        ck = Cookie(self.COOKIE_NAME, sess.token, secure=False, MaxAge=self.ttl_sec, Path="/")
        return JsonResponse({"ok": True}, cookie=str(ck))

    def logout(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        token = None
        if request.cookie:
            token = request.cookie.get(self.COOKIE_NAME)  # type: ignore[attr-defined]

        if token:
            self.dbm.logout(token)

        ck = Cookie(self.COOKIE_NAME, "", secure=False, MaxAge=0, Path="/")
        return JsonResponse({"ok": True}, cookie=str(ck))

    def verify(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"error": "Method Not Allowed"}, status=405)

        data = request.json() or {}

        token = data.get("token")
        if not token and request.cookie:
            token = request.cookie.get(self.COOKIE_NAME)  # type: ignore[attr-defined]

        sess = self.dbm.verify(token)
        if not sess:
            return JsonResponse({"active": False})

        return JsonResponse({"active": True, "uid": sess.uid, "expires_at": sess.expires_at})


# --------------------
# AuthVerify (service-facing)
# --------------------

class AuthVerifyLocal:
    """Verify using a local AuthDBM instance (same process)."""

    def __init__(self, dbm: "AuthDBM") -> None:
        self.dbm = dbm

    def verify_request(self, req: Request) -> Session | None:
        token = _parse_bearer(req.headers.get("authorization"))
        return self.dbm.verify(token)

    def verify_token(self, token: str) -> Session | None:
        return self.dbm.verify(token)


class AuthVerify:
    """Verify by calling the Auth Service over HTTP(S)."""

    def __init__(
        self,
        auth_url: str,
        *,
        cookie_name: str = AuthService.COOKIE_NAME,
        timeout: float = 3.0,
        verify_path: str = "/verify",
    ) -> None:
        self.auth_url = auth_url.rstrip("/")
        self.cookie_name = cookie_name
        self.timeout = timeout
        self.verify_url = f"{self.auth_url}{verify_path}"

    def _extract_token(self, req: Request) -> str | None:
        #　Cookie
        if req.cookie:
            # RequestCookies.get() already handles default
            token = req.cookie.get(self.cookie_name)  # type: ignore[attr-defined]
            if token:
                return token

        return None

    def verify_request(self, req: Request) -> Session | None:
        token = self._extract_token(req)
        if not token:
            return None
        return self.verify_token(token)

    def verify_token(self, token: str) -> Session | None:
        if not token:
            return None

        payload = json.dumps({"token": token}, ensure_ascii=False).encode("utf-8")
        http_req = UrlRequest(
            self.verify_url,
            data=payload,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(http_req, timeout=self.timeout) as resp:
                body = resp.read()
        except (HTTPError, URLError):
            # auth service unreachable or returned non-2xx
            raise AuthTokenInvalidError()

        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            raise AuthTokenInvalidError()

        if not data.get("active"):
            return None

        uid = data.get("uid")
        exp = data.get("expires_at")
        if not isinstance(uid, str) or not isinstance(exp, int):
            raise AuthTokenInvalidError()

        # sid/user_agent are not provided by verify endpoint; keep minimal.
        return Session(sid="", uid=uid, token=token, expires_at=exp, revoked_at=None, user_agent=None)


# --------------------
# DB layer
# --------------------

class AuthDBM(DatabaseManager):
    @override
    def _init(self) -> None:
        # NOTE:
        # 既存DBが token カラムのままだと CREATE TABLE は更新されない。
        # 途中から token_hash 化するなら migration が必要。
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
            uid, user_id, public_name, pw_hash, salt
        )

    def login(self, user_id: str, password: str, *, user_agent: str | None, ttl_sec: int) -> Session:
        rows = self.execute(
            "SELECT uid, password_hash, password_salt, is_active FROM users WHERE user_id = ?",
            user_id
        )
        if not rows:
            raise AuthInvalidCredentialsError()

        uid, pw_hash, salt, active = rows[0]
        if not active:
            raise AuthUserDisabledError()

        if not hmac.compare_digest(_hash_password(password, salt), pw_hash):
            raise AuthInvalidCredentialsError()

        sid = _rand()
        token = _rand()
        expires = _now() + ttl_sec

        self.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?)",
            sid, uid, _token_hash(token), expires, None, user_agent
        )

        return Session(sid, uid, token, expires, None, user_agent)

    def logout(self, token: str) -> None:
        self.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            _now(), _token_hash(token)
        )

    def verify(self, token: str | None) -> Session | None:
        if not token:
            return None

        rows = self.execute(
            "SELECT sid, uid, token_hash, expires_at, revoked_at, user_agent FROM sessions WHERE token_hash = ?",
            _token_hash(token)
        )
        if not rows:
            return None

        sid, uid, _th, exp, rev, ua = rows[0]
        if rev or exp <= _now():
            return None

        # token はDBに無いので、返すなら引数 token をそのまま入れる
        return Session(sid, uid, token, exp, None, ua)
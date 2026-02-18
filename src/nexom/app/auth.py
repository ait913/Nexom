"""Authentication service, client, and storage."""

# src/nexom/app/auth.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
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


class Permissions:
    """
    Group-scoped permissions helper for AuthClient.

    Usage:
        perms = client.permissions("group-a", token=token)
        level = perms.auth(pid)
        perms.upsert(pid, 10)
    """

    def __init__(self, client: "AuthClient", group_id: str, token: str):
        self._client = client
        self.group_id = group_id
        self.token = token

    def auth(self, pid: str) -> int:
        d = self._client._post(
            self._client.permissions_group_auth_url,
            {"token": self.token, "group_id": self.group_id, "pid": pid},
        )
        if not d.get("ok"):
            self._client._raise_from_error_code(str(d.get("error") or ""))
        return int(d.get("level") or 0)

    def upsert(self, pid: str, level: int) -> None:
        d = self._client._post(
            self._client.permissions_group_member_upsert_url,
            {"token": self.token, "group_id": self.group_id, "pid": pid, "level": level},
        )
        if d.get("ok"):
            return
        self._client._raise_from_error_code(str(d.get("error") or ""))

    def delete(self, pid: str) -> None:
        d = self._client._post(
            self._client.permissions_group_member_delete_url,
            {"token": self.token, "group_id": self.group_id, "pid": pid},
        )
        if d.get("ok"):
            return
        self._client._raise_from_error_code(str(d.get("error") or ""))


# --------------------
# AuthService (API only)
# --------------------

class AuthService:
    """
    Auth API service (JSON only).

    Exposes signup/login/logout/verify via a Router.
    Intended to run as a standalone auth server.
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
            Path(_p("update/public-name"), self.update_public_name, "AuthUpdatePublicName"),
            Path(_p("update/password"), self.update_password, "AuthUpdatePassword"),
            Path(_p("permissions/group/create"), self.permissions_group_create, "PermissionsGroupCreate"),
            Path(_p("permissions/group/member/upsert"), self.permissions_group_member_upsert, "PermissionsMemberUpsert"),
            Path(_p("permissions/group/member/delete"), self.permissions_group_member_delete, "PermissionsMemberDelete"),
            Path(_p("permissions/group/auth"), self.permissions_group_auth, "PermissionsGroupAuth"),
        )

        self.logger = AuthLogger(log_path)

    def handler(self, environ: dict) -> JsonResponse:
        """
        WSGI entrypoint for the auth API.

        Returns JsonResponse with proper status codes for NexomError.
        """
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
        """
        Create a new user.

        Expected JSON: {user_id, public_name, password}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        user_id = str(data.get("user_id") or "").strip()
        public_name = str(data.get("public_name") or "").strip()
        password = str(data.get("password") or "")

        self.dbm.signup(user_id=user_id, public_name=public_name, password=password)
        return JsonResponse({"ok": True}, status=201)

    def login(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Authenticate and return a session token.

        Expected JSON: {user_id, password}
        """
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
        """
        Revoke a session token.

        Expected JSON: {token}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        token = str((request.json() or {}).get("token") or "")
        if token:
            self.dbm.logout(token)
        return JsonResponse({"ok": True})

    def verify(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Verify a session token.

        Expected JSON: {token}
        Returns {active: bool, ...} when active.
        """
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

    def update_public_name(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Update public_name for the authenticated user.

        Expected JSON: {token, public_name}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "")
        public_name = str(data.get("public_name") or "").strip()
        if not token:
            raise AuthTokenMissingError()
        if not public_name:
            raise AuthMissingFieldError("public_name")

        lsess = self.dbm.verify(token)
        if not lsess:
            raise AuthTokenInvalidError()

        self.dbm.update_public_name(uid=lsess.uid, public_name=public_name)
        return JsonResponse({"ok": True, "public_name": public_name})

    def update_password(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Update password for the authenticated user.

        Expected JSON: {token, current_password, new_password}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "")
        current_password = str(data.get("current_password") or "")
        new_password = str(data.get("new_password") or "")
        if not token:
            raise AuthTokenMissingError()
        if not current_password:
            raise AuthMissingFieldError("current_password")
        if not new_password:
            raise AuthMissingFieldError("new_password")

        lsess = self.dbm.verify(token)
        if not lsess:
            raise AuthTokenInvalidError()

        self.dbm.update_password(uid=lsess.uid, current_password=current_password, new_password=new_password)
        return JsonResponse({"ok": True})

    def permissions_group_create(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Create a permission group owned by the authenticated user."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "")
        group_id = str(data.get("group_id") or "").strip()
        name = str(data.get("name") or "").strip()
        if not token:
            raise AuthTokenMissingError()
        if not group_id:
            raise AuthMissingFieldError("group_id")
        if not name:
            raise AuthMissingFieldError("name")

        lsess = self.dbm.verify(token)
        if not lsess:
            raise AuthTokenInvalidError()

        self.dbm.create_permission_group(owner_uid=lsess.uid, group_id=group_id, name=name)
        return JsonResponse({"ok": True, "group_id": group_id})

    def permissions_group_member_upsert(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Upsert a member level in the group (owner only)."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "")
        group_id = str(data.get("group_id") or "").strip()
        pid = str(data.get("pid") or "").strip()
        level_raw = data.get("level")
        if not token:
            raise AuthTokenMissingError()
        if not group_id:
            raise AuthMissingFieldError("group_id")
        if not pid:
            raise AuthMissingFieldError("pid")
        if not isinstance(level_raw, int):
            raise AuthMissingFieldError("level")

        lsess = self.dbm.verify(token)
        if not lsess:
            raise AuthTokenInvalidError()
        self.dbm.assert_permission_group_owner(group_id=group_id, owner_uid=lsess.uid)
        self.dbm.upsert_permission_member_by_pid(group_id=group_id, pid=pid, level=level_raw)
        return JsonResponse({"ok": True})

    def permissions_group_member_delete(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Delete a member from the group (owner only)."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "")
        group_id = str(data.get("group_id") or "").strip()
        pid = str(data.get("pid") or "").strip()
        if not token:
            raise AuthTokenMissingError()
        if not group_id:
            raise AuthMissingFieldError("group_id")
        if not pid:
            raise AuthMissingFieldError("pid")

        lsess = self.dbm.verify(token)
        if not lsess:
            raise AuthTokenInvalidError()
        self.dbm.assert_permission_group_owner(group_id=group_id, owner_uid=lsess.uid)
        self.dbm.delete_permission_member_by_pid(group_id=group_id, pid=pid)
        return JsonResponse({"ok": True})

    def permissions_group_auth(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Resolve permission level for group_id and pid."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = request.json() or {}
        token = str(data.get("token") or "")
        group_id = str(data.get("group_id") or "").strip()
        pid = str(data.get("pid") or "").strip()
        if not token:
            raise AuthTokenMissingError()
        if not group_id:
            raise AuthMissingFieldError("group_id")
        if not pid:
            raise AuthMissingFieldError("pid")

        lsess = self.dbm.verify(token)
        if not lsess:
            raise AuthTokenInvalidError()

        level = self.dbm.auth_permission_level_by_pid(group_id=group_id, pid=pid)
        return JsonResponse({"ok": True, "group_id": group_id, "pid": pid, "level": level})


# --------------------
# AuthClient (App側)
# --------------------

class AuthClient:
    """
    HTTP client for AuthService.

    Provides signup/login/logout/verify helpers.
    """

    def __init__(self, auth_url: str, *, timeout: float = 3.0) -> None:
        base = auth_url.rstrip("/")
        self.signup_url = base + "/signup"
        self.login_url = base + "/login"
        self.logout_url = base + "/logout"
        self.verify_url = base + "/verify"
        self.update_public_name_url = base + "/update/public-name"
        self.update_password_url = base + "/update/password"
        self.permissions_group_create_url = base + "/permissions/group/create"
        self.permissions_group_member_upsert_url = base + "/permissions/group/member/upsert"
        self.permissions_group_member_delete_url = base + "/permissions/group/member/delete"
        self.permissions_group_auth_url = base + "/permissions/group/auth"
        self.timeout = timeout

    def _post(self, url: str, body: dict) -> dict:
        """POST JSON and return parsed JSON dict."""
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
        """Create a user account on the auth server."""
        d = self._post(
            self.signup_url,
            {"user_id": user_id, "public_name": public_name, "password": password},
        )
        if d.get("ok"):
            return 
        self._raise_from_error_code(str(d.get("error") or ""))

    def login(self, *, user_id: str, password: str) -> Session:
        """Login and return a Session."""
        d = self._post(self.login_url, {"user_id": user_id, "password": password})
        if not d.get("ok"):
            self._raise_from_error_code(str(d.get("error") or ""))

        return Session(str(d["pid"]), str(d["user_id"]), str(d["public_name"]), str(d["token"]), int(d["expires_at"]), str(d["user_agent"]))

    def verify_token(self, token: str) -> Session | None:
        """Verify a token and return Session or None."""
        d = self._post(self.verify_url, {"token": token})

        if d.get("active") is True:
            return Session(str(d["pid"]), str(d["user_id"]), str(d["public_name"]), token, int(d["expires_at"]), str(d["user_agent"]))

        return None

    def logout(self, *, token: str) -> None:
        """Logout (revoke) a session token."""
        d = self._post(self.logout_url, {"token": token})
        if d.get("ok"):
            return
        self._raise_from_error_code(str(d.get("error") or ""))

    def update_public_name(self, *, token: str, public_name: str) -> str:
        """Update public_name and return the updated value."""
        d = self._post(
            self.update_public_name_url,
            {"token": token, "public_name": public_name},
        )
        if not d.get("ok"):
            self._raise_from_error_code(str(d.get("error") or ""))
        return str(d.get("public_name") or "")

    def update_password(self, *, token: str, current_password: str, new_password: str) -> None:
        """Update password for an authenticated user."""
        d = self._post(
            self.update_password_url,
            {
                "token": token,
                "current_password": current_password,
                "new_password": new_password,
            },
        )
        if d.get("ok"):
            return
        self._raise_from_error_code(str(d.get("error") or ""))

    def create_permission_group(self, *, token: str, group_id: str, name: str) -> str:
        """Create a permission group and return group_id."""
        d = self._post(
            self.permissions_group_create_url,
            {"token": token, "group_id": group_id, "name": name},
        )
        if not d.get("ok"):
            self._raise_from_error_code(str(d.get("error") or ""))
        return str(d.get("group_id") or group_id)

    def permissions(self, group_id: str, *, token: str) -> Permissions:
        """Return a group-scoped permissions helper."""
        return Permissions(self, group_id, token)

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
    """
    Auth database manager.

    Manages users and sessions in a SQLite DB.
    """
    def _init(self) -> None:
        """Create auth tables if they do not exist."""
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
                (
                    """
                    CREATE TABLE IF NOT EXISTS permission_groups (
                        group_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        owner_uid TEXT NOT NULL REFERENCES users(uid),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """,
                    (),
                ),
                (
                    """
                    CREATE TABLE IF NOT EXISTS permission_group_members (
                        group_id TEXT NOT NULL REFERENCES permission_groups(group_id) ON DELETE CASCADE,
                        uid TEXT NOT NULL REFERENCES users(uid),
                        level INTEGER NOT NULL DEFAULT 0,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (group_id, uid)
                    );
                    """,
                    (),
                ),
            ]
        )

    def signup(self, user_id: str, public_name: str, password: str) -> None:
        """Create a new user record."""
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
        """Validate credentials and create a new session."""
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
        """Revoke a session token."""
        if not token:
            raise AuthMissingFieldError("token")

        self.execute(
            "UPDATE sessions SET revoked_at=? WHERE token_hash=?",
            _now(),
            _token_hash(token),
        )

    def verify(self, token: str | None) -> LocalSession | None:
        """Return LocalSession if token is valid and active, else None."""
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

    def update_public_name(self, *, uid: str, public_name: str) -> None:
        """Update the user's public_name."""
        if not public_name:
            raise AuthMissingFieldError("public_name")
        self.execute(
            "UPDATE users SET public_name=? WHERE uid=?",
            public_name,
            uid,
        )

    def update_password(self, *, uid: str, current_password: str, new_password: str) -> None:
        """Change password after validating the current password."""
        if not current_password:
            raise AuthMissingFieldError("current_password")
        if not new_password:
            raise AuthMissingFieldError("new_password")

        rows = self.execute(
            "SELECT password_hash, password_salt FROM users WHERE uid=?",
            uid,
        )
        if not rows:
            raise AuthInvalidCredentialsError()

        pw_hash, salt = rows[0]
        if not hmac.compare_digest(_hash_password(current_password, str(salt)), str(pw_hash)):
            raise AuthInvalidCredentialsError()

        new_salt = _make_salt()
        self.execute(
            "UPDATE users SET password_hash=?, password_salt=? WHERE uid=?",
            _hash_password(new_password, new_salt),
            new_salt,
            uid,
        )

        # Revoke all existing sessions for this user after password change.
        self.execute(
            "UPDATE sessions SET revoked_at=? WHERE uid=? AND revoked_at IS NULL",
            _now(),
            uid,
        )

    def get_uid_by_pid(self, pid: str) -> str | None:
        """Resolve uid from pid (pid is treated as uid in current auth model)."""
        if not pid:
            return None
        rows = self.execute("SELECT uid FROM users WHERE uid=?", pid)
        if not rows:
            return None
        return str(rows[0][0])

    def create_permission_group(self, *, owner_uid: str, group_id: str, name: str) -> None:
        """Create a permission group."""
        try:
            self.execute(
                "INSERT INTO permission_groups(group_id, name, owner_uid) VALUES(?,?,?)",
                group_id,
                name,
                owner_uid,
            )
        except DBIntegrityError:
            raise AuthUserIdAlreadyExistsError()

    def assert_permission_group_owner(self, *, group_id: str, owner_uid: str) -> None:
        """Ensure owner_uid owns group_id."""
        rows = self.execute(
            "SELECT owner_uid FROM permission_groups WHERE group_id=?",
            group_id,
        )
        if not rows:
            raise AuthInvalidCredentialsError()
        if str(rows[0][0]) != owner_uid:
            raise AuthInvalidCredentialsError()

    def upsert_permission_member_by_pid(self, *, group_id: str, pid: str, level: int) -> None:
        """Upsert member level by pid."""
        if level < 0:
            raise AuthMissingFieldError("level")
        uid = self.get_uid_by_pid(pid)
        if uid is None:
            raise AuthInvalidCredentialsError()

        self.execute(
            """
            INSERT INTO permission_group_members(group_id, uid, level, updated_at)
            VALUES(?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(group_id, uid) DO UPDATE SET
                level=excluded.level,
                updated_at=CURRENT_TIMESTAMP
            """,
            group_id,
            uid,
            level,
        )

    def delete_permission_member_by_pid(self, *, group_id: str, pid: str) -> None:
        """Delete a member by pid from a group."""
        uid = self.get_uid_by_pid(pid)
        if uid is None:
            return
        self.execute(
            "DELETE FROM permission_group_members WHERE group_id=? AND uid=?",
            group_id,
            uid,
        )

    def auth_permission_level_by_pid(self, *, group_id: str, pid: str) -> int:
        """Return permission level for group_id and pid, default 0."""
        uid = self.get_uid_by_pid(pid)
        if uid is None:
            return 0
        rows = self.execute(
            "SELECT level FROM permission_group_members WHERE group_id=? AND uid=?",
            group_id,
            uid,
        )
        if not rows:
            return 0
        return int(rows[0][0])

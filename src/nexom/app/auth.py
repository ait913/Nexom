"""Authentication service, client, and storage."""

# src/nexom/app/auth.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Callable, TypeVar, NoReturn
from collections import deque
from contextlib import contextmanager
from ipaddress import ip_address
from urllib.parse import urlsplit
import re
import unicodedata
import secrets
import time
import hashlib
import hmac
import json
from urllib.request import Request as UrlRequest, HTTPRedirectHandler, build_opener
from urllib.error import URLError, HTTPError
from http.client import HTTPException

from .request import Request
from .response import JsonResponse
from .db import DatabaseManager
from .path import Path, Router
from ..core.log import AuthLogger, sanitize_log_field

from ..core.error import (
    NexomError,
    PathNotFoundError,
    RequestParseError,
    RequestEntityTooLargeError,
    AuthMissingFieldError,          # A01
    AuthUserIdAlreadyExistsError,   # A02
    AuthInvalidCredentialsError,    # A03
    AuthUserDisabledError,          # A04
    AuthTokenMissingError,          # A05
    AuthTokenInvalidError,          # A06
    AuthTokenExpiredError,          # A07
    AuthTokenRevokedError,          # A08
    AuthServiceUnavailableError,    # A09
    AuthPermissionGroupAlreadyExistsError,  # A10
    AuthTooManyAttemptsError,       # A11
    AuthInvalidFieldError,          # A12
    AuthForbiddenError,             # A13
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


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthPolicy:
    pbkdf2_iterations: int = 600_000
    user_id_pattern: str = r"[a-z0-9][a-z0-9_.-]{2,31}"
    public_name_max_len: int = 64
    password_min_len: int = 8
    password_max_bytes: int = 256
    group_id_pattern: str = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}"
    account_lock_threshold: int = 5
    account_window_sec: int = 900
    account_lock_sec: int = 900
    ip_fail_threshold: int = 30
    ip_window_sec: int = 900
    ip_lock_sec: int = 900
    signup_ip_threshold: int = 10
    signup_window_sec: int = 3600
    signup_lock_sec: int = 3600
    hash_busy_ratio: float | None = 0.5
    hash_window_sec: float = 1.0
    max_sessions_per_user: int = 20


def _required_text(value: str, field: str) -> str:
    if value is None or value == "":
        raise AuthMissingFieldError(field)
    if not isinstance(value, str):
        raise AuthInvalidFieldError(field)
    return value


def validate_user_id(user_id: str, policy: AuthPolicy) -> str:
    value = _required_text(user_id, "user_id").strip()
    if not re.fullmatch(policy.user_id_pattern, value):
        raise AuthInvalidFieldError("user_id")
    return value


def validate_public_name(name: str, policy: AuthPolicy) -> str:
    value = unicodedata.normalize("NFC", _required_text(name, "public_name")).strip()
    if not value:
        raise AuthMissingFieldError("public_name")
    if len(value) > policy.public_name_max_len or any(
        c in "<>" or unicodedata.category(c) in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
        for c in value
    ):
        raise AuthInvalidFieldError("public_name")
    return value


def _password_limit(password: str, policy: AuthPolicy, field: str) -> str:
    value = _required_text(password, field)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise AuthInvalidFieldError(field) from None
    if size > policy.password_max_bytes:
        raise AuthInvalidFieldError(field)
    return value


def validate_password(password: str, policy: AuthPolicy, *, field: str = "password") -> str:
    value = _password_limit(password, policy, field)
    if len(value) < policy.password_min_len:
        raise AuthInvalidFieldError(field)
    return value


def validate_group_id(group_id: str, policy: AuthPolicy) -> str:
    value = _required_text(group_id, "group_id").strip()
    if not re.fullmatch(policy.group_id_pattern, value):
        raise AuthInvalidFieldError("group_id")
    return value


def normalize_ip(value: str) -> str:
    value = _required_text(value, "client_ip")
    try:
        return str(ip_address(value))
    except ValueError:
        raise AuthInvalidFieldError("client_ip") from None


def is_same_origin(request: Request) -> bool:
    headers = request.headers
    site = headers.get("sec-fetch-site")
    if site in {"same-origin", "same-site", "none"}:
        return True
    if site == "cross-site":
        return False
    source = headers.get("origin") if "origin" in headers else headers.get("referer")
    if source is None:
        return True
    host = headers.get("host", "")
    if not host or source == "null":
        return False
    try:
        parsed = urlsplit(source)
        return bool(parsed.netloc) and parsed.netloc.lower() == host.lower()
    except ValueError:
        return False


_DUMMY_SALT = secrets.token_bytes(16)
_T = TypeVar("_T")


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
        if d.get("ok") is not True:
            self._client._raise_from_error_code(str(d.get("error") or ""), d.get("field"))
        return self._client._value(d, "level", int)

    def upsert(self, user_id: str, level: int) -> None:
        d = self._client._post(
            self._client.permissions_group_member_upsert_url,
            {"token": self.token, "group_id": self.group_id, "user_id": user_id, "level": level},
        )
        if d.get("ok") is True:
            return
        self._client._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def delete(self, user_id: str) -> None:
        d = self._client._post(
            self._client.permissions_group_member_delete_url,
            {"token": self.token, "group_id": self.group_id, "user_id": user_id},
        )
        if d.get("ok") is True:
            return
        self._client._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def delete_group(self) -> None:
        d = self._client._post(
            self._client.permissions_group_delete_url,
            {"token": self.token, "group_id": self.group_id},
        )
        if d.get("ok") is True:
            return
        self._client._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def groups_mine(self) -> list[dict]:
        d = self._client._post(
            self._client.permissions_groups_mine_url,
            {"token": self.token},
        )
        if d.get("ok") is not True:
            self._client._raise_from_error_code(str(d.get("error") or ""), d.get("field"))
        return self._client._rows(d, "groups")


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
        master_user: str = "master_user",
        master_login_password: str = "",
        prefix: str = "",
        allowed_clients: tuple[str, ...] | None = ("127.0.0.1", "::1"),
        policy: AuthPolicy = AuthPolicy(),
        clock: Callable[[], int] = _now,
    ) -> None:
        self.logger = AuthLogger(log_path)
        self.policy = policy
        self.allowed_clients = (None if allowed_clients is None else
                                frozenset(normalize_ip(ip) for ip in allowed_clients))
        self.dbm = AuthDBM(db_path, policy=policy, clock=clock, logger=self.logger)
        self.ttl_sec = ttl_sec
        self.master_user = master_user
        self.dbm.ensure_master_user(
            user_id=master_user,
            login_password=master_login_password,
        )
        # 起動時の master 作成ハッシュは要求駆動でないのでゲージに数えない (L-17: 初回要求は通る)
        self.dbm._hash_log.clear()

        p = prefix.strip("/")

        def _p(x: str) -> str:
            return f"{p}/{x}".strip("/") if p else x

        self.routing = Router(
            Path(_p("signup"), self.signup, "AuthSignup"),
            Path(_p("login"), self.login, "AuthLogin"),
            Path(_p("logout"), self.logout, "AuthLogout"),
            Path(_p("verify"), self.verify, "AuthVerify"),
            Path(_p("convert/pid"), self.convert_pid, "AuthConvertPid"),
            Path(_p("convert/user-id"), self.convert_user_id, "AuthConvertUserId"),
            Path(_p("update/public-name"), self.update_public_name, "AuthUpdatePublicName"),
            Path(_p("update/password"), self.update_password, "AuthUpdatePassword"),
            Path(_p("permissions/group/create"), self.permissions_group_create, "PermissionsGroupCreate"),
            Path(_p("permissions/group/delete"), self.permissions_group_delete, "PermissionsGroupDelete"),
            Path(_p("permissions/group/member/upsert"), self.permissions_group_member_upsert, "PermissionsMemberUpsert"),
            Path(_p("permissions/group/member/delete"), self.permissions_group_member_delete, "PermissionsMemberDelete"),
            Path(_p("permissions/group/auth"), self.permissions_group_auth, "PermissionsGroupAuth"),
            Path(_p("permissions/groups/mine"), self.permissions_groups_mine, "PermissionsGroupsMine"),
            Path(_p("master/users/list"), self.master_users_list, "MasterUsersList"),
            Path(_p("master/users/deactivate"), self.master_users_deactivate, "MasterUsersDeactivate"),
            Path(_p("master/users/activate"), self.master_users_activate, "MasterUsersActivate"),
        )

    def _event(self, action: str, *, subject: str, detail: str | None = None) -> None:
        self.logger.event(action, subject=sanitize_log_field(subject),
                          detail=sanitize_log_field(detail) if detail is not None else None)

    def handler(self, environ: dict) -> JsonResponse:
        """Apply the caller guard before routing and contain all request errors."""
        try:
            if self.allowed_clients is not None:
                remote = environ.get("REMOTE_ADDR")
                try:
                    allowed = normalize_ip(remote) in self.allowed_clients
                except (AuthMissingFieldError, AuthInvalidFieldError):
                    allowed = False
                if not allowed:
                    self._event("FORBIDDEN_CLIENT", subject=str(remote or "-"))
                    raise AuthForbiddenError()
            try:
                req = Request(environ)
            except ValueError:
                raise AuthMissingFieldError("body") from None
            return self.routing.handle(req)
        except PathNotFoundError:
            return JsonResponse({"ok": False, "error": "NotFound"}, status=404)
        except (RequestParseError, RequestEntityTooLargeError):
            return JsonResponse({"ok": False, "error": "A01", "field": "body"}, status=400)
        except Exception as e:
            if isinstance(e, NexomError) and e.code.startswith("A"):
                body = {"ok": False, "error": e.code}
                if hasattr(e, "field"):
                    body["field"] = e.field
                return JsonResponse(body, status=_status_for_auth_error(e.code))
            self._event("INTERNAL_ERROR", subject=str(environ.get("PATH_INFO", "")),
                        detail=type(e).__name__)
            return JsonResponse({"ok": False, "error": "InternalError"}, status=500)

    @staticmethod
    def _body(request: Request) -> dict:
        try:
            data = request.json()
        except (ValueError, RequestParseError, RequestEntityTooLargeError):
            raise AuthMissingFieldError("body") from None
        if not isinstance(data, dict):
            raise AuthMissingFieldError("body")
        return data

    def _session(self, token: str) -> LocalSession:
        if token is None or token == "":
            raise AuthTokenMissingError()
        session = self.dbm.verify(token) if isinstance(token, str) else None
        if session is None:
            self._event("TOKEN_INVALID", subject=str(token)[:8] + "...")
            raise AuthTokenInvalidError()
        return session

    # ---- handlers ----

    def signup(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Create a new user.

        Expected JSON: {user_id, public_name, password, client_ip}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        user_id = data.get("user_id")
        public_name = data.get("public_name")
        password = data.get("password")

        client_ip = normalize_ip(data.get("client_ip"))
        self.dbm.signup(user_id=user_id, public_name=public_name, password=password, client_ip=client_ip)
        return JsonResponse({"ok": True}, status=201)

    def login(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Authenticate and return a session token.

        Expected JSON: {user_id, password, client_ip, user_agent?}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        user_id = data.get("user_id")
        password = data.get("password")

        lsess = self.dbm.login(
            user_id,
            password,
            client_ip=normalize_ip(data.get("client_ip")),
            user_agent=data.get("user_agent", request.headers.get("user-agent")),
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

        data = self._body(request)
        token = str(data.get("token") or "")
        if token:
            self.dbm.logout(token, client_ip=data.get("client_ip"))
        return JsonResponse({"ok": True})

    def verify(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Verify a session token.

        Expected JSON: {token}
        Returns {active: bool, ...} when active.
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        token = str(self._body(request).get("token") or "")
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

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        public_name = data.get("public_name")

        public_name = validate_public_name(public_name, self.policy)
        self.dbm.update_public_name(uid=lsess.uid, public_name=public_name)
        return JsonResponse({"ok": True, "public_name": public_name})

    def convert_pid(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Convert user_id to pid.

        Expected JSON: {token, user_id}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        user_id = str(data.get("user_id") or "").strip()
        if not user_id:
            raise AuthMissingFieldError("user_id")

        pid = self.dbm.get_uid_by_user_id(user_id)
        if not pid:
            raise AuthInvalidCredentialsError()
        return JsonResponse({"ok": True, "user_id": user_id, "pid": pid})

    def convert_user_id(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """
        Convert pid to user_id.

        Expected JSON: {token, pid}
        """
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        pid = str(data.get("pid") or "").strip()
        if not pid:
            raise AuthMissingFieldError("pid")

        user_id = self.dbm.get_user_id_by_pid(pid)
        if not user_id:
            raise AuthInvalidCredentialsError()
        return JsonResponse({"ok": True, "pid": pid, "user_id": user_id})

    def update_password(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)
        data = self._body(request)
        client_ip = normalize_ip(data.get("client_ip"))
        session = self._session(data.get("token"))
        self.dbm.update_password(uid=session.uid,
                                 current_password=data.get("current_password"),
                                 new_password=data.get("new_password"), client_ip=client_ip)
        return JsonResponse({"ok": True})

    def permissions_group_create(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Create a permission group owned by the authenticated user."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        group_id = validate_group_id(data.get("group_id"), self.policy)
        name = data.get("name")

        self.dbm.create_permission_group(owner_uid=lsess.uid, group_id=group_id, name=name)
        return JsonResponse({"ok": True, "group_id": group_id})

    def permissions_group_delete(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Delete group if requester has level 100 in that group."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        group_id = validate_group_id(data.get("group_id"), self.policy)

        self.dbm.delete_permission_group_by_uid(group_id=group_id, uid=lsess.uid)
        return JsonResponse({"ok": True})

    def permissions_group_member_upsert(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Upsert a member level in the group (owner only)."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        group_id = validate_group_id(data.get("group_id"), self.policy)
        user_id = _required_text(data.get("user_id"), "user_id").strip()
        level_raw = data.get("level")
        if not user_id:
            raise AuthMissingFieldError("user_id")
        self.dbm._validate_level(level_raw)

        self.dbm.assert_permission_group_owner(group_id=group_id, owner_uid=lsess.uid)
        self.dbm.upsert_permission_member_by_user_id(group_id=group_id, user_id=user_id, level=level_raw)
        return JsonResponse({"ok": True})

    def permissions_group_member_delete(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Delete a member from the group (owner only)."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        group_id = validate_group_id(data.get("group_id"), self.policy)
        user_id = _required_text(data.get("user_id"), "user_id").strip()
        if not user_id:
            raise AuthMissingFieldError("user_id")

        self.dbm.assert_permission_group_owner(group_id=group_id, owner_uid=lsess.uid)
        self.dbm.delete_permission_member_by_user_id(group_id=group_id, user_id=user_id)
        return JsonResponse({"ok": True})

    def permissions_group_auth(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        """Resolve permission level for group_id and pid."""
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)

        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        group_id = validate_group_id(data.get("group_id"), self.policy)
        pid = str(data.get("pid") or "").strip()
        if not pid:
            raise AuthMissingFieldError("pid")

        self.dbm.assert_permission_group_visible(group_id=group_id, requester_uid=lsess.uid, pid=pid)
        level = self.dbm.auth_permission_level_by_pid(group_id=group_id, pid=pid)
        return JsonResponse({"ok": True, "group_id": group_id, "pid": pid, "level": level})

    def permissions_groups_mine(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)
        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        groups = self.dbm.permission_groups_by_uid(lsess.uid)
        return JsonResponse({"ok": True, "groups": groups})

    def master_users_list(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)
        data = self._body(request)
        token = data.get("token")
        lsess = self._session(token)
        if not self.dbm.is_master_uid(lsess.uid):
            raise AuthForbiddenError()
        return JsonResponse({"ok": True, "users": self.dbm.list_users()})

    def _master_user_state(self, request: Request, *, active: bool) -> JsonResponse:
        if request.method != "POST":
            return JsonResponse({"ok": False, "error": "MethodNotAllowed"}, status=405)
        data = self._body(request)
        session = self._session(data.get("token"))
        target = _required_text(data.get("target_user_id"), "target_user_id").strip()
        if not target:
            raise AuthMissingFieldError("target_user_id")
        password = _password_limit(data.get("login_password"), self.policy, "login_password")
        client_ip = normalize_ip(data.get("client_ip"))
        if not self.dbm.is_master_uid(session.uid):
            raise AuthForbiddenError()
        # Reject self-targeting before reauth can change attempt counters.
        if target == session.user_id:
            raise AuthForbiddenError()
        self.dbm.reauth(uid=session.uid, password=password, client_ip=client_ip)
        if active:
            self.dbm.activate_user(target)
        else:
            self.dbm.deactivate_user(target)
        self._event("MASTER_ACTIVATE" if active else "MASTER_DEACTIVATE",
                    subject=target, detail=f"by={session.user_id}")
        return JsonResponse({"ok": True})

    def master_users_deactivate(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        return self._master_user_state(request, active=False)

    def master_users_activate(self, request: Request, args: dict[str, Optional[str]]) -> JsonResponse:
        return self._master_user_state(request, active=True)


# --------------------
# AuthClient (App側)
# --------------------

class _NoAuthRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
        self.convert_pid_url = base + "/convert/pid"
        self.convert_user_id_url = base + "/convert/user-id"
        self.update_public_name_url = base + "/update/public-name"
        self.update_password_url = base + "/update/password"
        self.permissions_group_create_url = base + "/permissions/group/create"
        self.permissions_group_delete_url = base + "/permissions/group/delete"
        self.permissions_group_member_upsert_url = base + "/permissions/group/member/upsert"
        self.permissions_group_member_delete_url = base + "/permissions/group/member/delete"
        self.permissions_group_auth_url = base + "/permissions/group/auth"
        self.permissions_groups_mine_url = base + "/permissions/groups/mine"
        self.master_users_list_url = base + "/master/users/list"
        self.master_users_deactivate_url = base + "/master/users/deactivate"
        self.master_users_activate_url = base + "/master/users/activate"
        self.timeout = timeout
        self._opener = build_opener(_NoAuthRedirect())

    def _post(self, url: str, body: dict) -> dict:
        """POST without redirects; reject malformed or contradictory responses."""
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = UrlRequest(url, data=payload, method="POST", headers={
            "Content-Type": "application/json; charset=utf-8", "Accept": "application/json",
        })
        try:
            try:
                response = self._opener.open(req, timeout=self.timeout)
            except HTTPError as e:
                response = e
            with response as r:
                status = r.code
                if 300 <= status < 400:
                    raise AuthServiceUnavailableError()
                d = json.loads(r.read().decode("utf-8"))
        except (URLError, OSError, ValueError, HTTPException):
            raise AuthServiceUnavailableError() from None
        if not isinstance(d, dict):
            raise AuthServiceUnavailableError()
        if d.get("ok") is False:
            if not isinstance(d.get("error"), str):
                raise AuthServiceUnavailableError()
            if "field" in d and not isinstance(d["field"], str):
                raise AuthServiceUnavailableError()
            return d
        if not 200 <= status < 300:
            raise AuthServiceUnavailableError()
        if url == self.verify_url:
            if type(d.get("active")) is not bool:
                raise AuthServiceUnavailableError()
        elif d.get("ok") is not True:
            raise AuthServiceUnavailableError()
        if url == self.login_url:
            self._session_response(d)
        elif url == self.verify_url and d["active"]:
            self._session_response(d, token=body.get("token", ""))
        elif url in (self.convert_pid_url, self.convert_user_id_url):
            self._value(d, "pid", str)
            self._value(d, "user_id", str)
        elif url == self.update_public_name_url:
            self._value(d, "public_name", str)
        elif url == self.permissions_group_create_url:
            self._value(d, "group_id", str)
        elif url == self.permissions_group_auth_url:
            self._value(d, "group_id", str)
            self._value(d, "pid", str)
            self._value(d, "level", int)
        elif url == self.permissions_groups_mine_url:
            self._rows(d, "groups")
        elif url == self.master_users_list_url:
            self._rows(d, "users")
        return d

    @staticmethod
    def _value(d: dict, key: str, kind: type):
        value = d.get(key)
        if type(value) is not kind:
            raise AuthServiceUnavailableError()
        return value

    def _session_response(self, d: dict, *, token: str | None = None) -> Session:
        pid = self._value(d, "pid", str)
        user_id = self._value(d, "user_id", str)
        public_name = self._value(d, "public_name", str)
        expires_at = self._value(d, "expires_at", int)
        if "user_agent" not in d or (d["user_agent"] is not None and not isinstance(d["user_agent"], str)):
            raise AuthServiceUnavailableError()
        if token is None:
            token = self._value(d, "token", str)
        return Session(pid, user_id, public_name, token, expires_at, d["user_agent"])

    def _rows(self, d: dict, key: str) -> list[dict]:
        rows = self._value(d, key, list)
        for row in rows:
            if not isinstance(row, dict):
                raise AuthServiceUnavailableError()
            fields = ({"group_id": str, "name": str, "level": int} if key == "groups" else
                      {"pid": str, "user_id": str, "public_name": str,
                       "is_active": int, "is_master": int, "created_at": str})
            for field, kind in fields.items():
                self._value(row, field, kind)
        return rows

    def signup(self, *, user_id: str, public_name: str, password: str, client_ip: str) -> None:
        """Create a user account on the auth server."""
        d = self._post(
            self.signup_url,
            {"user_id": user_id, "public_name": public_name, "password": password, "client_ip": client_ip},
        )
        if d.get("ok") is True:
            return
        self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def login(self, *, user_id: str, password: str, client_ip: str, user_agent: str | None = None) -> Session:
        """Login and return a Session."""
        d = self._post(self.login_url, {"user_id": user_id, "password": password,
                                             "client_ip": client_ip, "user_agent": user_agent})
        if d.get("ok") is not True:
            self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

        return self._session_response(d)

    def verify_token(self, token: str) -> Session | None:
        """Verify a token and return Session or None."""
        d = self._post(self.verify_url, {"token": token})

        if d.get("ok") is False:
            self._raise_from_error_code(d.get("error"), d.get("field"))
        if self._value(d, "active", bool):
            return self._session_response(d, token=token)
        return None

    def logout(self, *, token: str, client_ip: str | None = None) -> None:
        """Logout (revoke) a session token."""
        d = self._post(self.logout_url, {"token": token, "client_ip": client_ip})
        if d.get("ok") is True:
            return
        self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def update_public_name(self, *, token: str, public_name: str) -> str:
        """Update public_name and return the updated value."""
        d = self._post(
            self.update_public_name_url,
            {"token": token, "public_name": public_name},
        )
        if d.get("ok") is not True:
            self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))
        return self._value(d, "public_name", str)

    def update_password(self, *, token: str, current_password: str, new_password: str, client_ip: str) -> None:
        """Update password for an authenticated user."""
        d = self._post(
            self.update_password_url,
            {
                "token": token,
                "current_password": current_password,
                "new_password": new_password,
                "client_ip": client_ip,
            },
        )
        if d.get("ok") is True:
            return
        self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def convert_pid(self, *, token: str, user_id: str) -> str:
        """Convert user_id to pid."""
        d = self._post(self.convert_pid_url, {"token": token, "user_id": user_id})
        if d.get("ok") is not True:
            self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))
        return self._value(d, "pid", str)

    def convert_user_id(self, *, token: str, pid: str) -> str:
        """Convert pid to user_id."""
        d = self._post(self.convert_user_id_url, {"token": token, "pid": pid})
        if d.get("ok") is not True:
            self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))
        return self._value(d, "user_id", str)

    def create_permission_group(self, *, token: str, group_id: str, name: str) -> str:
        """Create a permission group and return group_id."""
        d = self._post(
            self.permissions_group_create_url,
            {"token": token, "group_id": group_id, "name": name},
        )
        if d.get("ok") is not True:
            self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))
        return self._value(d, "group_id", str)

    def delete_permission_group(self, *, token: str, group_id: str) -> None:
        """Delete a permission group (requires level 100)."""
        d = self._post(
            self.permissions_group_delete_url,
            {"token": token, "group_id": group_id},
        )
        if d.get("ok") is True:
            return
        self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def permissions(self, group_id: str, *, token: str) -> Permissions:
        """Return a group-scoped permissions helper."""
        return Permissions(self, group_id, token)

    def master_users_list(self, *, token: str) -> list[dict]:
        d = self._post(self.master_users_list_url, {"token": token})
        if d.get("ok") is not True:
            self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))
        return self._rows(d, "users")

    def master_users_deactivate(self, *, token: str, target_user_id: str, login_password: str, client_ip: str) -> None:
        d = self._post(
            self.master_users_deactivate_url,
            {
                "token": token,
                "target_user_id": target_user_id,
                "login_password": login_password,
                "client_ip": client_ip,
            },
        )
        if d.get("ok") is True:
            return
        self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def master_users_activate(self, *, token: str, target_user_id: str, login_password: str, client_ip: str) -> None:
        d = self._post(
            self.master_users_activate_url,
            {
                "token": token,
                "target_user_id": target_user_id,
                "login_password": login_password,
                "client_ip": client_ip,
            },
        )
        if d.get("ok") is True:
            return
        self._raise_from_error_code(str(d.get("error") or ""), d.get("field"))

    def _raise_from_error_code(self, code: str, field: str | None = None) -> NoReturn:
        if code == "A01":
            raise AuthMissingFieldError(field if field is not None else "unknown")
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
        if code == "A10":
            raise AuthPermissionGroupAlreadyExistsError()
    
        if code == "A11":
            raise AuthTooManyAttemptsError()
        if code == "A12":
            raise AuthInvalidFieldError(field if field is not None else "unknown")
        if code == "A13":
            raise AuthForbiddenError()

        # 想定外レスポンス
        raise AuthServiceUnavailableError()


# --------------------
# DB
# --------------------

class AuthDBM(DatabaseManager):
    """Auth storage, password verification, and shared attempt budgets."""

    SCHEMA_VERSION = 2

    def __init__(self, db_path: str, *, policy: AuthPolicy = AuthPolicy(),
                 clock: Callable[[], int] = _now, logger: AuthLogger | None = None) -> None:
        self.policy = policy
        self.clock = clock
        self._logger = logger
        self._hash_log: deque[tuple[float, float]] = deque()
        super().__init__(db_path)

    @contextmanager
    def _transaction(self):
        """Serialize read/write sequences across SQLite connections."""
        auto_commit = self.auto_commit
        self.auto_commit = False
        try:
            self.execute("BEGIN IMMEDIATE")
            yield
            self.commit()
        except Exception:
            if self._conn is not None:
                self._conn.rollback()
            raise
        finally:
            self.auto_commit = auto_commit

    def _init(self) -> None:
        self._migrate()

    def _migrate(self) -> None:
        with self._transaction():
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
                            is_active INTEGER NOT NULL DEFAULT 1,
                            is_master INTEGER NOT NULL DEFAULT 0
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
                            user_agent TEXT,
                            created_at INTEGER NOT NULL DEFAULT 0
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

            self.execute("CREATE TABLE IF NOT EXISTS auth_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            self.execute("""CREATE TABLE IF NOT EXISTS auth_attempts (
                key TEXT PRIMARY KEY, count INTEGER NOT NULL,
                window_start INTEGER NOT NULL, locked_until INTEGER)""")
            rows = self.execute("SELECT value FROM auth_meta WHERE key='schema_version'")
            version = int(rows[0][0]) if rows else 1
            if version < self.SCHEMA_VERSION:
                columns = self.execute("SELECT name FROM pragma_table_info('sessions')") or []
                if not any(row[0] == "created_at" for row in columns):
                    self.execute("ALTER TABLE sessions ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")
                self.execute("CREATE INDEX IF NOT EXISTS idx_users_user_id_nocase ON users(user_id COLLATE NOCASE)")
                self.execute("CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid)")
                self.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_window ON auth_attempts(window_start)")
                self.execute("""INSERT INTO auth_meta(key,value) VALUES('schema_version','2')
                    ON CONFLICT(key) DO UPDATE SET value='2'""")

    def _log_event(self, action: str, *, subject: str, ip: str | None = None,
                   detail: str | None = None) -> None:
        if self._logger is None:
            return
        self._logger.event(action, subject=sanitize_log_field(subject), ip=ip,
                           detail=sanitize_log_field(detail) if detail is not None else None)

    def _timed_hash(self, fn: Callable[[], _T]) -> _T:
        start = time.perf_counter()
        try:
            return fn()
        finally:
            end = time.perf_counter()
            self._hash_log.append((end, end - start))
            self._prune_hash_log(end)

    def _prune_hash_log(self, now: float) -> None:
        while self._hash_log and self._hash_log[0][0] <= now - self.policy.hash_window_sec:
            self._hash_log.popleft()

    def _gauge_check(self) -> None:
        self._prune_hash_log(time.perf_counter())
        ratio = self.policy.hash_busy_ratio
        if ratio is not None and sum(duration for _, duration in self._hash_log) > ratio * self.policy.hash_window_sec:
            raise AuthTooManyAttemptsError()

    def _hash_password(self, password: str) -> str:
        salt = secrets.token_hex(16)
        iterations = self.policy.pbkdf2_iterations
        dk = self._timed_hash(lambda: hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations))
        return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"

    def _verify_password(self, password: str, password_hash: str, password_salt: str) -> tuple[bool, bool]:
        legacy = "$" not in password_hash
        try:
            if legacy:
                iterations, salt, expected = 200_000, bytes.fromhex(password_salt), bytes.fromhex(password_hash)
            else:
                algorithm, rounds, salt_hex, dk_hex = password_hash.split("$")
                if algorithm != "pbkdf2_sha256":
                    raise ValueError("Unknown password hash")
                iterations, salt, expected = int(rounds), bytes.fromhex(salt_hex), bytes.fromhex(dk_hex)
                if iterations <= 0:
                    raise ValueError("Invalid iteration count")
        except (ValueError, TypeError):
            self._dummy_verify(password)
            return False, False
        actual = self._timed_hash(lambda: hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations))
        return hmac.compare_digest(actual, expected), legacy or iterations != self.policy.pbkdf2_iterations

    def _dummy_verify(self, password: str) -> None:
        self._timed_hash(lambda: hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _DUMMY_SALT, self.policy.pbkdf2_iterations))

    def _check_locked(self, key: str) -> None:
        rows = self.execute("SELECT locked_until FROM auth_attempts WHERE key=?", key)
        if rows and rows[0][0] is not None and rows[0][0] > self.clock():
            raise AuthTooManyAttemptsError()

    def _reserve(self, key: str, *, threshold: int, window_sec: int) -> int:
        now = self.clock()
        with self._transaction():
            self.execute("""INSERT INTO auth_attempts(key,count,window_start,locked_until)
                VALUES(?,1,?,NULL) ON CONFLICT(key) DO UPDATE SET
                count = CASE WHEN ? >= window_start + ? THEN 1 ELSE count + 1 END,
                window_start = CASE WHEN ? >= window_start + ? THEN ? ELSE window_start END,
                locked_until = CASE WHEN locked_until <= ? THEN NULL ELSE locked_until END""",
                key, now, now, window_sec, now, window_sec, now, now)
            rows = self.execute("SELECT count FROM auth_attempts WHERE key=?", key)
            return int(rows[0][0])

    def _release(self, key: str) -> None:
        self.execute_many([
            ("UPDATE auth_attempts SET count=count-1 WHERE key=?", (key,)),
            ("DELETE FROM auth_attempts WHERE key=? AND count<=0 AND locked_until IS NULL", (key,)),
        ])

    def _lock(self, key: str, *, lock_sec: int) -> None:
        self.execute("UPDATE auth_attempts SET locked_until=? WHERE key=?", self.clock() + lock_sec, key)

    def _reset(self, key: str) -> None:
        self.execute("DELETE FROM auth_attempts WHERE key=?", key)

    def _sweep_attempts(self) -> None:
        now = self.clock()
        self.execute("""DELETE FROM auth_attempts WHERE window_start + 3600 <= ?
            AND (locked_until IS NULL OR locked_until <= ?)""", now, now)

    def _sweep_sessions(self, uid: str) -> None:
        self.execute("DELETE FROM sessions WHERE uid=? AND (expires_at<=? OR revoked_at IS NOT NULL)", uid, self.clock())
        self.execute("""DELETE FROM sessions WHERE sid IN (
            SELECT sid FROM sessions WHERE uid=? ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?)
            """, uid, self.policy.max_sessions_per_user)

    def _locked_check_logged(self, key: str, ip: str) -> None:
        try:
            self._check_locked(key)
        except AuthTooManyAttemptsError:
            self._log_event("RATE_LIMITED", subject=key, ip=ip, detail="reason=locked")
            raise

    def _gauge_check_logged(self, ip: str) -> None:
        try:
            self._gauge_check()
        except AuthTooManyAttemptsError:
            self._log_event("RATE_LIMITED", subject="gauge", ip=ip, detail="reason=busy")
            raise

    def _lock_logged(self, key: str, lock_sec: int, ip: str) -> None:
        self._lock(key, lock_sec=lock_sec)
        rows = self.execute("SELECT locked_until FROM auth_attempts WHERE key=?", key)
        self._log_event("LOCKOUT", subject=key, ip=ip, detail=f"until={rows[0][0]}")

    def signup(self, user_id: str, public_name: str, password: str, *, client_ip: str) -> None:
        ip = normalize_ip(client_ip)
        key = f"signup_ip:{ip}"
        self._locked_check_logged(key, ip)
        try:
            user_id = validate_user_id(user_id, self.policy)
            public_name = validate_public_name(public_name, self.policy)
            password = validate_password(password, self.policy)
        except AuthInvalidFieldError as e:
            self._log_event("SIGNUP_NG", subject=str(user_id or "-"), ip=ip, detail=f"reason=A12:{e.field}")
            raise
        self._gauge_check_logged(ip)
        n = self._reserve(key, threshold=self.policy.signup_ip_threshold, window_sec=self.policy.signup_window_sec)
        if n > self.policy.signup_ip_threshold:
            self._release(key)
            self._log_event("RATE_LIMITED", subject=key, ip=ip, detail="reason=reserved")
            raise AuthTooManyAttemptsError()
        try:
            if n >= self.policy.signup_ip_threshold:
                self._lock_logged(key, self.policy.signup_lock_sec, ip)
            password_hash = self._hash_password(password)
            try:
                with self._transaction():
                    if self.execute("SELECT uid FROM users WHERE user_id=? COLLATE NOCASE", user_id):
                        raise AuthUserIdAlreadyExistsError()
                    self.execute("""INSERT INTO users(uid,user_id,public_name,password_hash,password_salt)
                        VALUES(?,?,?,?,'')""", _rand(), user_id, public_name, password_hash)
            except (DBIntegrityError, AuthUserIdAlreadyExistsError):
                self._log_event("SIGNUP_NG", subject=user_id, ip=ip, detail="reason=A02")
                raise AuthUserIdAlreadyExistsError() from None
            self._log_event("SIGNUP", subject=user_id, ip=ip)
        finally:
            self._sweep_attempts()

    def _authenticate(self, user_id: str, password: str, ip: str, *, reauth: bool = False):
        user_id = _required_text(user_id, "user_id")
        if len(user_id) > 256:
            raise AuthInvalidFieldError("user_id")
        password = _password_limit(password, self.policy, "password")
        user_key, ip_key = f"login_user:{user_id}", f"login_ip:{ip}"
        self._locked_check_logged(ip_key, ip)
        self._locked_check_logged(user_key, ip)
        self._gauge_check_logged(ip)
        n_user = self._reserve(user_key, threshold=self.policy.account_lock_threshold, window_sec=self.policy.account_window_sec)
        n_ip = self._reserve(ip_key, threshold=self.policy.ip_fail_threshold, window_sec=self.policy.ip_window_sec)
        if n_user > self.policy.account_lock_threshold or n_ip > self.policy.ip_fail_threshold:
            self._release(user_key)
            self._release(ip_key)
            key = user_key if n_user > self.policy.account_lock_threshold else ip_key
            self._log_event("RATE_LIMITED", subject=key, ip=ip, detail="reason=reserved")
            raise AuthTooManyAttemptsError()
        try:
            rows = self.execute("""SELECT uid,user_id,public_name,password_hash,password_salt,is_active
                FROM users WHERE user_id=?""", user_id)
            ok, needs_rehash = False, False
            if rows:
                ok, needs_rehash = self._verify_password(password, rows[0][3], rows[0][4])
            else:
                self._dummy_verify(password)
            if not ok or not rows[0][5]:
                if n_user >= self.policy.account_lock_threshold:
                    self._lock_logged(user_key, self.policy.account_lock_sec, ip)
                if n_ip >= self.policy.ip_fail_threshold:
                    self._lock_logged(ip_key, self.policy.ip_lock_sec, ip)
                reason = "reauth" if reauth else ("disabled" if ok else "invalid")
                self._log_event("LOGIN_NG", subject=user_id, ip=ip, detail=f"reason={reason}")
                if ok:
                    raise AuthUserDisabledError()
                raise AuthInvalidCredentialsError()
            self._reset(user_key)
            self._release(ip_key)
            return rows[0], needs_rehash
        except Exception:
            self._sweep_attempts()
            raise

    def login(self, user_id: str, password: str, *, client_ip: str,
              user_agent: str | None, ttl_sec: int) -> LocalSession:
        ip = normalize_ip(client_ip)
        row, needs_rehash = self._authenticate(user_id, password, ip)
        uid, user_id, public_name = row[:3]
        if needs_rehash:
            self.execute("UPDATE users SET password_hash=?,password_salt='' WHERE uid=?", self._hash_password(password), uid)
        token, sid, now = _rand(32), _rand(), self.clock()
        exp = now + ttl_sec
        with self._transaction():
            self.execute("""INSERT INTO sessions(sid,uid,token_hash,expires_at,user_agent,created_at)
                VALUES(?,?,?,?,?,?)""", sid, uid, _token_hash(token), exp, user_agent, now)
            self._sweep_sessions(uid)
        self._log_event("LOGIN_OK", subject=user_id, ip=ip)
        self._sweep_attempts()
        return LocalSession(sid, uid, user_id, public_name, token, exp, None, user_agent)

    def logout(self, token: str, *, client_ip: str | None = None) -> None:
        ip = normalize_ip(client_ip) if client_ip is not None else None
        session = self.verify(token)
        if session is None:
            return
        self.execute("UPDATE sessions SET revoked_at=? WHERE sid=?", self.clock(), session.sid)
        self._log_event("LOGOUT", subject=session.user_id, ip=ip)

    def verify(self, token: str | None) -> LocalSession | None:
        if not token:
            return None
        rows = self.execute("""SELECT s.sid,s.uid,u.user_id,u.public_name,s.expires_at,s.user_agent
            FROM sessions s JOIN users u ON u.uid=s.uid
            WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.is_active=1""",
            _token_hash(token), self.clock())
        if not rows:
            return None
        sid, uid, user_id, public_name, exp, ua = rows[0]
        return LocalSession(sid, uid, user_id, public_name, token, int(exp), None, ua)

    def ensure_master_user(self, *, user_id: str, login_password: str) -> None:
        with self._transaction():
            rows = self.execute("SELECT uid FROM users WHERE user_id=?", user_id)
            if not rows:
                if not login_password:
                    raise AuthServiceUnavailableError()
                validate_password(login_password, self.policy, field="master_login_password")
                self.execute("""INSERT INTO users(uid,user_id,public_name,password_hash,password_salt,is_master)
                    VALUES(?,?,'Master User',?,'',1)""", _rand(), user_id, self._hash_password(login_password))
            self.execute("UPDATE users SET is_active=1,is_master=1 WHERE user_id=?", user_id)
            self.execute("UPDATE users SET is_master=0 WHERE is_master=1 AND user_id!=?", user_id)

    def is_master_uid(self, uid: str) -> bool:
        return bool(self.execute("SELECT uid FROM users WHERE uid=? AND is_master=1", uid))

    def update_public_name(self, *, uid: str, public_name: str) -> None:
        public_name = validate_public_name(public_name, self.policy)
        self.execute("UPDATE users SET public_name=? WHERE uid=?", public_name, uid)
        self._log_event("PUBLIC_NAME_CHANGE", subject=self.get_user_id_by_pid(uid) or "-")

    def reauth(self, *, uid: str, password: str, client_ip: str) -> None:
        _password_limit(password, self.policy, "password")
        ip = normalize_ip(client_ip)
        user_id = self.get_user_id_by_pid(uid)
        if user_id is None:
            raise AuthInvalidCredentialsError()
        self._authenticate(user_id, password, ip, reauth=True)
        self._sweep_attempts()

    def update_password(self, *, uid: str, current_password: str, new_password: str, client_ip: str) -> None:
        ip = normalize_ip(client_ip)
        validate_password(new_password, self.policy, field="new_password")
        _password_limit(current_password, self.policy, "current_password")
        self.reauth(uid=uid, password=current_password, client_ip=ip)
        password_hash = self._hash_password(new_password)
        self.execute_many([
            ("UPDATE users SET password_hash=?,password_salt='' WHERE uid=?", (password_hash, uid)),
            ("UPDATE sessions SET revoked_at=? WHERE uid=? AND revoked_at IS NULL", (self.clock(), uid)),
        ])
        self._log_event("PASSWORD_CHANGE", subject=self.get_user_id_by_pid(uid) or "-")

    def get_uid_by_pid(self, pid: str) -> str | None:
        """Resolve uid from pid (pid is treated as uid in current auth model)."""
        if not pid:
            return None
        rows = self.execute("SELECT uid FROM users WHERE uid=?", pid)
        if not rows:
            return None
        return str(rows[0][0])

    def get_user_id_by_pid(self, pid: str) -> str | None:
        """Resolve user_id from pid."""
        if not pid:
            return None
        rows = self.execute("SELECT user_id FROM users WHERE uid=?", pid)
        if not rows:
            return None
        return str(rows[0][0])

    def _permission_group_owner(self, group_id: str) -> str:
        rows = self.execute("SELECT owner_uid FROM permission_groups WHERE group_id=?", group_id)
        if not rows:
            raise AuthInvalidFieldError("group_id")
        return str(rows[0][0])

    @staticmethod
    def _validate_level(level: int) -> None:
        if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 100:
            raise AuthInvalidFieldError("level")

    def create_permission_group(self, *, owner_uid: str, group_id: str, name: str) -> None:
        """Create a group with its owner's initial permission."""
        group_id = validate_group_id(group_id, self.policy)
        try:
            name = validate_public_name(name, self.policy)
        except AuthMissingFieldError:
            raise AuthMissingFieldError("name") from None
        except AuthInvalidFieldError:
            raise AuthInvalidFieldError("name") from None
        try:
            self.execute_many([
                ("INSERT INTO permission_groups(group_id,name,owner_uid) VALUES(?,?,?)", (group_id, name, owner_uid)),
                ("INSERT INTO permission_group_members(group_id,uid,level) VALUES(?,?,100)", (group_id, owner_uid)),
            ])
        except DBIntegrityError:
            raise AuthPermissionGroupAlreadyExistsError() from None
        self._log_event("GROUP_CREATE", subject=group_id, detail=f"by={self.get_user_id_by_pid(owner_uid)}")

    def assert_permission_group_owner(self, *, group_id: str, owner_uid: str) -> None:
        if self._permission_group_owner(group_id) != owner_uid:
            raise AuthForbiddenError()

    def assert_permission_group_visible(self, *, group_id: str, requester_uid: str, pid: str) -> None:
        """Service-side guard for group/auth, including nonexistent groups."""
        if requester_uid != pid and self.auth_permission_level_by_uid(group_id=group_id, uid=requester_uid) < 1:
            raise AuthForbiddenError()

    def get_uid_by_user_id(self, user_id: str) -> str | None:
        if not user_id:
            return None
        rows = self.execute("SELECT uid FROM users WHERE user_id=?", user_id)
        return str(rows[0][0]) if rows else None

    def upsert_permission_member_by_pid(self, *, group_id: str, pid: str, level: int) -> None:
        self._validate_level(level)
        self._permission_group_owner(group_id)
        uid = self.get_uid_by_pid(pid)
        if uid is None:
            raise AuthInvalidCredentialsError()
        self.upsert_permission_member_by_uid(group_id=group_id, uid=uid, level=level)

    def upsert_permission_member_by_user_id(self, *, group_id: str, user_id: str, level: int) -> None:
        self._validate_level(level)
        self._permission_group_owner(group_id)
        uid = self.get_uid_by_user_id(user_id)
        if uid is None:
            raise AuthInvalidCredentialsError()
        self.upsert_permission_member_by_uid(group_id=group_id, uid=uid, level=level)

    def upsert_permission_member_by_uid(self, *, group_id: str, uid: str, level: int) -> None:
        self._validate_level(level)
        owner = self._permission_group_owner(group_id)
        self.execute("""INSERT INTO permission_group_members(group_id,uid,level,updated_at)
            VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(group_id,uid) DO UPDATE SET
            level=excluded.level,updated_at=CURRENT_TIMESTAMP""", group_id, uid, level)
        self._log_event("PERM_UPSERT", subject=group_id,
                        detail=f"by={self.get_user_id_by_pid(owner)} target={self.get_user_id_by_pid(uid)} level={level}")

    def delete_permission_member_by_pid(self, *, group_id: str, pid: str) -> None:
        self._permission_group_owner(group_id)
        uid = self.get_uid_by_pid(pid)
        if uid is not None:
            self._delete_permission_member(group_id, uid)

    def delete_permission_member_by_user_id(self, *, group_id: str, user_id: str) -> None:
        self._permission_group_owner(group_id)
        uid = self.get_uid_by_user_id(user_id)
        if uid is not None:
            self._delete_permission_member(group_id, uid)

    def _delete_permission_member(self, group_id: str, uid: str) -> None:
        owner = self._permission_group_owner(group_id)
        self.execute("DELETE FROM permission_group_members WHERE group_id=? AND uid=?", group_id, uid)
        self._log_event("PERM_DELETE", subject=group_id,
                        detail=f"by={self.get_user_id_by_pid(owner)} target={self.get_user_id_by_pid(uid)}")

    def auth_permission_level_by_pid(self, *, group_id: str, pid: str) -> int:
        uid = self.get_uid_by_pid(pid)
        if uid is None:
            return 0
        return self.auth_permission_level_by_uid(group_id=group_id, uid=uid)

    def auth_permission_level_by_uid(self, *, group_id: str, uid: str) -> int:
        rows = self.execute("SELECT level FROM permission_group_members WHERE group_id=? AND uid=?", group_id, uid)
        return int(rows[0][0]) if rows else 0

    def delete_permission_group_by_uid(self, *, group_id: str, uid: str) -> None:
        self._permission_group_owner(group_id)
        if self.auth_permission_level_by_uid(group_id=group_id, uid=uid) != 100:
            raise AuthForbiddenError()
        self.execute("DELETE FROM permission_groups WHERE group_id=?", group_id)
        self._log_event("GROUP_DELETE", subject=group_id, detail=f"by={self.get_user_id_by_pid(uid)}")

    def permission_groups_by_uid(self, uid: str) -> list[dict]:
        """List groups and levels for uid."""
        rows = self.execute(
            """
            SELECT g.group_id, g.name, m.level
            FROM permission_group_members m
            JOIN permission_groups g ON g.group_id=m.group_id
            WHERE m.uid=?
            ORDER BY g.group_id
            """,
            uid,
        ) or []
        out: list[dict] = []
        for group_id, name, level in rows:
            out.append({"group_id": str(group_id), "name": str(name), "level": int(level)})
        return out

    def list_users(self) -> list[dict]:
        """List all users."""
        rows = self.execute(
            """
            SELECT uid, user_id, public_name, is_active, is_master, created_at
            FROM users
            ORDER BY user_id
            """
        ) or []
        out: list[dict] = []
        for uid, user_id, public_name, is_active, is_master, created_at in rows:
            out.append(
                {
                    "pid": str(uid),
                    "user_id": str(user_id),
                    "public_name": str(public_name),
                    "is_active": int(is_active),
                    "is_master": int(is_master),
                    "created_at": str(created_at),
                }
            )
        return out

    def deactivate_user(self, user_id: str) -> None:
        """Called after the service has authorized and reauthenticated master."""
        uid = self.get_uid_by_user_id(user_id)
        if uid is None:
            raise AuthInvalidFieldError("target_user_id")
        if self.is_master_uid(uid):
            raise AuthForbiddenError()
        self.execute_many([
            ("UPDATE users SET is_active=0 WHERE uid=?", (uid,)),
            ("UPDATE sessions SET revoked_at=? WHERE uid=? AND revoked_at IS NULL", (self.clock(), uid)),
        ])

    def activate_user(self, user_id: str) -> None:
        """Called after the service has authorized and reauthenticated master."""
        uid = self.get_uid_by_user_id(user_id)
        if uid is None:
            raise AuthInvalidFieldError("target_user_id")
        self.execute("UPDATE users SET is_active=1 WHERE uid=?", uid)

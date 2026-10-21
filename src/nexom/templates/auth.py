"""Auth HTML pages and handlers."""

# src/nexom/templates/auth.py
from __future__ import annotations

from importlib import resources
import pathlib as plb
import time
from typing import Callable

from nexom.app.auth import AuthClient, KEY_NAME, is_same_origin
from ..app.request import Request
from ..app.response import HtmlResponse, JsonResponse, Redirect, Response
from ..app.cookie import Cookie
from ..app.path import Path, Router
from ..core.object_html_render import HTMLDoc, ObjectHTML
from ..core.log import AppLogger
from ..core.error import (
    NexomError, PathNotFoundError, RequestParseError, RequestEntityTooLargeError,
    AuthMissingFieldError, _status_for_auth_error,
)


# --------------------
# Object HTML
# --------------------

_OHTML: ObjectHTML = ObjectHTML(
    HTMLDoc(
        "signup",
        resources.files("nexom.assets.auth_page").joinpath("signup.html").read_text(encoding="utf-8"),
    ),
    HTMLDoc(
        "login",
        resources.files("nexom.assets.auth_page").joinpath("login.html").read_text(encoding="utf-8"),
    ),
)


# --------------------
# Pages
# --------------------

def _auth_error(error: NexomError, *, cookie: Cookie | None = None) -> JsonResponse:
    body = {"ok": False, "error": error.code}
    if hasattr(error, "field"):
        body["field"] = error.field
    return JsonResponse(body, status=_status_for_auth_error(error.code), cookie=cookie)


def _json_body(req: Request) -> dict:
    if req.content_type != "application/json":
        raise AuthMissingFieldError("body")
    try:
        data = req.json()
    except (ValueError, RequestParseError, RequestEntityTooLargeError) as e:
        raise AuthMissingFieldError("body") from e
    if not isinstance(data, dict):
        raise AuthMissingFieldError("body")
    return data


class AuthPages(Path):
    def __init__(self,
        path: str,
        auth_server: str,
        *,
        login_path: str = "login/",
        signup_path: str = "signup/",
        logout_path: str = "logout/",
        client_ip: Callable[[Request], str] | None = None,
        logger: AppLogger | None = None,
    ) -> None:
        self.auth_server = auth_server
        root = plb.Path(path)
        self.routing = Router(
            LoginPage(str(root / login_path), auth_server, client_ip=client_ip),
            SignupPage(str(root / signup_path), auth_server, client_ip=client_ip),
            LogoutPage(str(root / logout_path), auth_server, client_ip=client_ip, logger=logger),
        )
        base = path.strip("/")
        route = '{"*"}' if not base else f'{base}/{{"*"}}'
        super().__init__(route, self._handler, "UserAuthPage")

    def _handler(self, req: Request, args: dict) -> Response:
        p = self.routing.get(req.path)
        if p is None:
            raise PathNotFoundError(req.path)
        return p.call_handler(req)


class LoginPage(Path):
    def __init__(self, path: str, auth_server: str, *,
                 client_ip: Callable[[Request], str] | None = None) -> None:
        super().__init__(path, self._handler, "LoginPage")
        self.client = AuthClient(auth_server)
        self.client_ip = client_ip

    def _handler(self, req: Request, args: dict) -> Response:
        if req.method == "GET":
            return HtmlResponse(_OHTML.render("login", page_path=req.path))
        if not is_same_origin(req):
            return JsonResponse({"ok": False, "error": "A13"}, status=403)
        try:
            data = _json_body(req)
            sess = self.client.login(
                user_id=data.get("user_id", ""),
                password=data.get("password", ""),
                client_ip=req.client_ip if self.client_ip is None else self.client_ip(req),
                user_agent=req.headers.get("user-agent"),
            )
            set_cookie = Cookie(
                KEY_NAME, sess.token, max_age=sess.expires_at - int(time.time()),
                same_site="Lax", secure=True, http_only=True, path="/",
            )
            return JsonResponse({
                "ok": True, "user_id": sess.user_id,
                "public_name": sess.public_name, "expires_at": sess.expires_at,
            }, cookie=set_cookie)
        except NexomError as e:
            return _auth_error(e)


class SignupPage(Path):
    def __init__(self, path: str, auth_server: str, *,
                 client_ip: Callable[[Request], str] | None = None) -> None:
        super().__init__(path, self._handler, "SignupPage")
        self.client = AuthClient(auth_server)
        self.client_ip = client_ip

    def _handler(self, req: Request, args: dict) -> Response:
        if req.method == "GET":
            return HtmlResponse(_OHTML.render("signup", page_path=req.path))
        if not is_same_origin(req):
            return JsonResponse({"ok": False, "error": "A13"}, status=403)
        try:
            data = _json_body(req)
            self.client.signup(
                user_id=data.get("user_id", ""),
                public_name=data.get("public_name", ""),
                password=data.get("password", ""),
                client_ip=req.client_ip if self.client_ip is None else self.client_ip(req),
            )
            return JsonResponse({"ok": True}, status=201)
        except NexomError as e:
            return _auth_error(e)


class LogoutPage(Path):
    def __init__(self, path: str, auth_server: str, *,
                 client_ip: Callable[[Request], str] | None = None,
                 logger: AppLogger | None = None) -> None:
        super().__init__(path, self._handler, "LogoutPage", methods={"POST"})
        self.client = AuthClient(auth_server)
        self.client_ip = client_ip
        self.logger = logger

    def _handler(self, req: Request, args: dict) -> Response:
        # AuthPages dispatches by path; retain the JSON contract on that route.
        if req.method != "POST":
            return JsonResponse(
                {"ok": False, "error": "MethodNotAllowed"}, status=405,
                headers=[("Allow", "POST")],
            )
        if not is_same_origin(req):
            return JsonResponse({"ok": False, "error": "A13"}, status=403)
        token = req.cookie.get(KEY_NAME) if req.cookie else None
        set_cookie = Cookie.delete(KEY_NAME, path="/")
        is_form = req.content_type == "application/x-www-form-urlencoded"
        if token:
            try:
                self.client.logout(
                    token=token,
                    client_ip=req.client_ip if self.client_ip is None else self.client_ip(req),
                )
            except NexomError as e:
                if not is_form:
                    return _auth_error(e, cookie=set_cookie)
                # K-6b: form POST never answers JSON; the browser cookie is cleared
                # regardless and the failed revoke is logged on the app side.
                if self.logger is not None:
                    self.logger.warn(f"logout revoke failed: {e.code}")
        if is_form:
            return Redirect("/", cookie=set_cookie)
        return JsonResponse({"ok": True}, cookie=set_cookie)

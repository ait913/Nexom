# src/nexom/templates/auth.py
from __future__ import annotations

from importlib import resources
import pathlib as plb

from ..app.auth import AuthClient, KEY_NAME
from ..app.request import Request
from ..app.response import HtmlResponse, JsonResponse, Redirect, ErrorResponse
from ..app.cookie import Cookie
from ..app.path import Path, Router
from ..core.object_html_render import HTMLDoc, ObjectHTML
from ..core.error import NexomError, _status_for_auth_error


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

class AuthPages(Path):
    def __init__(self,
        path: str,
        auth_server: str,
        *,
        login_path: str = "login/",
        signup_path: str = "signup/",
        logout_path: str = "logout/"
    ):
        self.auth_server = auth_server

        root = plb.Path(path)
        self.routing = Router(
            LoginPage(str(root / login_path), self.auth_server),
            SignupPage(str(root / signup_path), self.auth_server),
            LogoutPage(str(root / logout_path), self.auth_server),
        )

        super().__init__(path, self._handler, "UserAuthPage")

    def _handler(self, req: Request, args: dict) -> JsonResponse:

        p = self.routing.get(req.path)
        return p.call_handler(req)


class LoginPage(Path):
    def __init__(self, path: str, auth_server: str) -> None:
        super().__init__(path, self._handler, "LoginPage")

        self.client = AuthClient(auth_server)

    def _handler(self, req: Request, args: dict) -> JsonResponse:
        if req.method == "GET":
            return HtmlResponse(_OHTML.render("login", page_path=req.path))

        try:
            data = req.json() or {}
            sess = self.client.login(
                user_id=str(data.get("user_id") or ""),
                password=str(data.get("password") or ""),
            )

            set_cookie = Cookie(KEY_NAME, sess.token, Path="/", MaxAge=sess.expires_at)
            return JsonResponse({"ok": True, "user_id": sess.user_id, "token": sess.token, "expires_at": sess.expires_at}, cookie=str(set_cookie))
        except NexomError as e:
            return JsonResponse({"ok": False, "error": e.code}, status=_status_for_auth_error(e.code))

        except Exception:
            return JsonResponse({"ok": False, "error": "InternalError"}, status=500)
        
class SignupPage(Path):
    def __init__(self, path: str, auth_server: str) -> None:
        super().__init__(path, self._handler, "SignupPage")

        self.client = AuthClient(auth_server)

    def _handler(self, req: Request, args: dict) -> JsonResponse:
        if req.method == "GET":
            return HtmlResponse(_OHTML.render("signup", page_path=req.path))

        try:
            data = req.json() or {}
            self.client.signup(
                user_id=str(data.get("user_id") or ""),
                public_name=str(data.get("public_name") or ""),
                password=str(data.get("password") or ""),
            )
            return JsonResponse({"ok": True}, status=201)

        except NexomError as e:
            return JsonResponse({"ok": False, "error": e.code}, status=_status_for_auth_error(e.code))

        except Exception:
            return JsonResponse({"ok": False, "error": "InternalError"}, status=500)
        

class LogoutPage(Path):
    def __init__(self, path: str, auth_server: str) -> None:
        super().__init__(path, self._handler, "LogoutPage")
        self.client = AuthClient(auth_server)

    def _handler(self, req: Request, args: dict) -> Redirect | ErrorResponse:
        if req.method != "GET":
            return ErrorResponse(405, "Please make a GET request")

        token = req.cookie.get(KEY_NAME) if req.cookie else None

        redirect_url = req.headers.get("referer") or "/"
        if not redirect_url.startswith("/"):
            redirect_url = "/"

        if token:
            try:
                self.client.logout(token=token)
            except NexomError as e:
                return ErrorResponse(500, e.code)
            except Exception as e:
                return ErrorResponse(500, str(e))

        set_cookie = Cookie(KEY_NAME, "", Path="/", MaxAge=0)
        return Redirect(redirect_url, cookie=str(set_cookie))


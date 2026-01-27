# src/nexom/templates/auth.py
from __future__ import annotations

from importlib import resources

from ..app.auth import AuthClient
from ..app.request import Request
from ..app.response import HtmlResponse, JsonResponse
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

class LoginPage:
    def __init__(self, auth_server: str) -> None:
        self.client = AuthClient(auth_server)

    def page(self, req: Request, args: dict) -> HtmlResponse | JsonResponse:
        if req.method == "GET":
            return HtmlResponse(_OHTML.render("login"))

        try:
            data = req.json() or {}
            token, user_id, exp = self.client.login(
                user_id=str(data.get("user_id") or ""),
                password=str(data.get("password") or ""),
            )
            return JsonResponse({"ok": True, "user_id": user_id, "token": token, "expires_at": exp})

        except NexomError as e:
            return JsonResponse({"ok": False, "error": e.code}, status=_status_for_auth_error(e.code))

        except Exception:
            return JsonResponse({"ok": False, "error": "InternalError"}, status=500)


class SignupPage:
    def __init__(self, auth_server: str) -> None:
        self.client = AuthClient(auth_server)

    def page(self, req: Request, args: dict) -> HtmlResponse | JsonResponse:
        if req.method == "GET":
            return HtmlResponse(_OHTML.render("signup"))

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
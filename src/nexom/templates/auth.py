# src/nexom/templates/auth.py
from __future__ import annotations

from importlib import resources

from ..app.auth import AuthClient
from ..app.request import Request
from ..app.response import HtmlResponse, JsonResponse
from ..core.object_html_render import HTMLDoc, ObjectHTML

from ..core.error import NexomError

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
                user_id=data.get("user_id", ""),
                password=data.get("password", ""),
            )
            return JsonResponse({"ok": True, "user_id": user_id, "token": token, "expires_at": exp})
        except NexomError as e:
            return JsonResponse({"error": e.code}, status=401)
        except Exception:
            return JsonResponse({"error": "Internal Server Error"}, status=401)

class SignupPage:
    def __init__(self, auth_server: str) -> None:
        self.client = AuthClient(auth_server)

    def page(self, req: Request, args: dict) -> HtmlResponse | JsonResponse:
        if req.method == "GET":
            return HtmlResponse(_OHTML.render("signup"))

        try:
            data = req.json() or {}
            ok = self.client.signup(
                user_id=data.get("user_id", ""),
                public_name=data.get("public_name", ""),
                password=data.get("password", ""),
            )
            return JsonResponse({"ok": ok})
        except NexomError as e:
            return JsonResponse({"error": e.code}, status=401)
        except Exception:
            return JsonResponse({"error": "Internal Server Error"}, status=401)
# src/nexom/templates/auth.py
from __future__ import annotations

from importlib import resources

from ..app.response import HtmlResponse
from ..core.object_html_render import HTMLDoc, ObjectHTML

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


class SignupPage:
    def __init__(self, auth_server: str) -> None:
        self.auth_server = auth_server.rstrip("/")
        self._doc = _OHTML.render("signup", auth_server=self.auth_server)

    def page(self, *_args, **_kwargs) -> HtmlResponse:
        return HtmlResponse(self._doc)


class LoginPage:
    def __init__(self, auth_server: str) -> None:
        self.auth_server = auth_server.rstrip("/")
        self._doc = _OHTML.render("login", auth_server=self.auth_server)

    def page(self, *_args, **_kwargs) -> HtmlResponse:
        return HtmlResponse(self._doc)
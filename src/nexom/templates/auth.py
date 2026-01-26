from __future__ import annotations
from importlib import resources

from ..app.auth import AuthVerify
from ..app.response import HtmlResponse
from ..core.object_html_render import HTMLDoc, ObjectHTML

# --------------------
# Object HTML
# --------------------

OHTML: ObjectHTML = ObjectHTML(
    HTMLDoc(
        "signup",
        (
            resources.files("nexom.assets.auth_page")
            .joinpath("signup.html")
            .read_text(encoding="utf-8")
        )
    ),
    HTMLDoc(
        "login",
            (
            resources.files("nexom.assets.auth_page")
            .joinpath("login.html")
            .read_text(encoding="utf-8")
        )
    )
)


# --------------------
# SignupPage
# --------------------

class SignupPage:
    def __init__(self, auth_server: str) -> None:
        self.auth_server: str = auth_server
        self._doc: str = OHTML.render("signup", auth_server=self.auth_server)
        self._verify: AuthVerify = AuthVerify()


    def page(self, _, *args) -> HtmlResponse:
        return HtmlResponse(self._doc)
    

# --------------------
# LoginPage
# --------------------

class LoginPage:
    def __init__(self, auth_server: str) -> None:
        self.auth_server: str = auth_server
        self._doc: str = OHTML.render("login", auth_server=self.auth_server)


    def page(self, _, *args :str) -> HtmlResponse:
        return HtmlResponse(self._doc)
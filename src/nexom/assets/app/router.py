from __future__ import annotations

from nexom.app.path import Get, Static, Router
from nexom.templates.auth import AuthPages

from .config import APP_DIR, AUTH_SERVER
from .pages import default, document

routing = Router(
    Get("", default.main, "DefaultPage"),
    Get("doc/", document.main, "DocumentPage"),
    Static("static/", APP_DIR + "/static", "StaticFiles"),

    AuthPages("user/", AUTH_SERVER),
)
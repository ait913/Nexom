from __future__ import annotations

from nexom.app.path import Get, Static, Router

from .config import APP_DIR
from .pages import default, document

routing = Router(
    Get("", default.main, "DefaultPage"),
    Get("doc/", document.main, "DocumentPage"),
    Static("static/", APP_DIR + "/static", "StaticFiles"),
)
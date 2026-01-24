from __future__ import annotations

from nexom.app.path import Path, Static, Pathlib

from .config import APP_DIR
from .pages import default, document

routing = Pathlib(
    Path("", default.main, "DefaultPage"),
    Path("doc/", document.main, "DocumentPage"),
    Static("static/", APP_DIR + "/static", "StaticFiles"),
)
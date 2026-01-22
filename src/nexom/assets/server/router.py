from __future__ import annotations

from pathlib import Path

from nexom.web.path import Path as Route, Static, Pathlib

from pages import default, document


# Project root directory (where this file exists)
ROOT = Path(__file__).resolve().parent


routing = Pathlib(
    Route("", default.main, "DefaultPage"),
    Route("doc/", document.main, "DocumentPage"),
    Static("static/", str(ROOT / "static"), "StaticFiles"),
)
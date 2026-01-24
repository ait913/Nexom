from __future__ import annotations

import pathlib as plib

from nexom.app.path import Path, Static, Pathlib

from pages import default, document


# Project root directory (where this file exists)
ROOT = plib.Path(__file__).resolve().parent


routing = Pathlib(
    Path("", default.main, "DefaultPage"),
    Path("doc/", document.main, "DocumentPage"),
    Static("static/", str(ROOT / "static"), "StaticFiles"),
)
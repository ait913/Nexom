from __future__ import annotations

from pathlib import Path

from nexom.web.template import Templates


# templates/ directory is located at: <project_root>/templates
TEMPLATES_DIR = (Path(__file__).resolve().parent.parent / "templates").resolve()

templates = Templates(
    str(TEMPLATES_DIR),
    "default",
    "document",
)
from __future__ import annotations

from pathlib import Path

from nexom.app.template import ObjectHTMLTemplates


# templates/ directory is located at: <project_root>/templates
TEMPLATES_DIR = (Path(__file__).resolve().parent.parent / "templates").resolve()

templates = ObjectHTMLTemplates(base_dir=str(TEMPLATES_DIR))
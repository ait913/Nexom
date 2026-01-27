from __future__ import annotations

from nexom.app.template import ObjectHTMLTemplates

from __app_name__.config import TEMPLATES_DIR, RELOAD

templates = ObjectHTMLTemplates(base_dir=TEMPLATES_DIR, reload=RELOAD)
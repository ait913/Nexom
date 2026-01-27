from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..core.object_html_render import HTMLDoc, HTMLDocLib, ObjectHTML
from ..core.error import TemplateNotFoundError, TemplateInvalidNameError, TemplatesNotDirError

_SEG_RE = re.compile(r"^[A-Za-z0-9_]+$")


@dataclass(frozen=True)
class TemplateEntry:
    name: str
    path: Path


class _TemplateAccessor:
    """
    Callable attribute-chain proxy.

    Examples:
        templates.default(title="x")        -> templates.render("default", title="x")
        templates.layout.base(title="x")    -> templates.render("layout.base", title="x")
    """

    def __init__(self, templates: "ObjectHTMLTemplates", name: str) -> None:
        self._templates = templates
        self._name = name

    def __getattr__(self, part: str) -> "_TemplateAccessor":
        if not _SEG_RE.match(part):
            raise AttributeError(part)
        return _TemplateAccessor(self._templates, f"{self._name}.{part}")

    def __call__(self, **kwargs: str) -> str:
        return self._templates.render(self._name, **kwargs)

    def __repr__(self) -> str:
        return f"<TemplateAccessor name='{self._name}'>"


class ObjectHTMLTemplates:
    """
    Loads all *.html templates under base_dir and renders them using ObjectHTML.

    Public API:
        render("a.b", **kwargs) -> str

    Sugar:
        templates.a.b(**kwargs) -> render("a.b", **kwargs)
    """

    def __init__(self, base_dir: str, reload: bool = False) -> None:
        self.base_dir = str(base_dir)
        self._base_path = Path(self.base_dir).resolve()
        self.reload = reload

        if not self._base_path.exists() or not self._base_path.is_dir():
            raise TemplatesNotDirError(self.base_dir)

        self._rebuild_engine()

    def __getattr__(self, name: str) -> _TemplateAccessor:
        if not _SEG_RE.match(name):
            raise AttributeError(name)
        return _TemplateAccessor(self, name)

    def render(self, name: str, **kwargs: str) -> str:
        if self.reload:
            self._rebuild_engine()

        if not self._engine.lib.get(name):
            raise TemplateNotFoundError(name)

        return self._engine.render(name, **kwargs)

    # -------------------------
    # internal
    # -------------------------

    def _rebuild_engine(self) -> None:
        lib = HTMLDocLib()
        for entry in self._scan_templates(self._base_path):
            html_text = entry.path.read_text(encoding="utf-8")
            lib.append(HTMLDoc(entry.name, html_text))
        self._engine = ObjectHTML(lib=lib)

    def _scan_templates(self, root: Path) -> list[TemplateEntry]:
        entries: list[TemplateEntry] = []
        for path in root.rglob("*.html"):
            if not path.is_file():
                continue
            rel = path.relative_to(root)
            name = self._path_to_template_name(rel)
            entries.append(TemplateEntry(name=name, path=path))
        return entries

    def _path_to_template_name(self, rel_path: Path) -> str:
        parts = list(rel_path.parts)
        if not parts:
            raise TemplateInvalidNameError(str(rel_path))

        filename = parts[-1]
        if not filename.endswith(".html"):
            raise TemplateInvalidNameError(str(rel_path))

        stem = filename[:-5]
        dir_parts = parts[:-1]

        for seg in dir_parts:
            if not _SEG_RE.match(seg):
                raise TemplateInvalidNameError(str(rel_path))

        if not _SEG_RE.match(stem):
            raise TemplateInvalidNameError(str(rel_path))

        return ".".join([*dir_parts, stem])
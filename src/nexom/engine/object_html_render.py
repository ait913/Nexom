"""
Nexom Object HTML (OHTML)

A lightweight HTML composition system that extends plain HTML
with inheritance, insertion, imports, and variable substitution.

HTML is treated as raw input until render time.
"""

import re
from typing import Final

from ..core.error import ObjectHTMLInsertValueError, ObjectHTMLExtendsError, ObjectHTMLImportError

_SLOT_RE: Final = re.compile(r"\{\{\s*(\w+)\s*\}\}")
_EXTENDS_RE: Final = re.compile(r"<Extends\s+([\w\.]+)\s*/>")
_INSERT_RE: Final = re.compile(r"<Insert\s+([\w\.]+)>(.*?)</Insert>", flags=re.DOTALL)
_IMPORT_RE: Final = re.compile(r"<Import\s+(\w+)\s*/>")


class HTMLDoc:
    """
    Raw HTML document container.

    HTMLDoc holds plain HTML only.
    No rendering or interpretation is performed here.
    """

    def __init__(self, name: str, doc: str) -> None:
        """
        Args:
            name: Document name ('.html' extension is optional).
            doc: Raw HTML source.
        """
        self.name = name.rsplit(".", 1)[0] if name.endswith(".html") else name
        self.doc = doc

    def __repr__(self) -> str:
        return self.name


class ObjectHTML:
    """
    Object HTML renderer.

    Interprets OHTML directives and renders final HTML:
    - <Extends />
    - <Insert>
    - <Import />
    - {{variable}}
    """
    def __init__(
        self,
        doc: HTMLDoc,
        *,
        base: HTMLDoc | None = None,
        imports: list[HTMLDoc] | None = None,
        **kwargs: str
    ) -> None:
        """
        Args:
            doc: Target HTML document.
            base: Base document used by <Extends />.
            imports: Importable HTML documents.
        """
        self.doc = doc
        self.base = base
        self.imports = list(imports) if imports else []
        self.html = self.insert(**kwargs)

    def insert(self, **kwargs: str) -> str:
        """
        Insert the document into final HTML.

        Rendering order:
        1. Extends / Insert
        2. Import
        3. Variable substitution

        Args:
            **kwargs: Values for {{variable}} replacement.

        Returns:
            Rendered HTML string.
        """
        html = self._apply_extends(self.doc.doc)
        html = self._apply_imports(html)
        html = self._apply_slots_strict(html, kwargs)
        return html

    def _apply_extends(self, html: str) -> str:
        m = _EXTENDS_RE.search(html)
        if not m:
            return html

        extends_name = m.group(1)
        if not self.base:
            raise ObjectHTMLExtendsError(extends_name)
        if self.base.name != extends_name:
            raise ObjectHTMLExtendsError(f"{extends_name} != {self.base.name}")

        inserts = {t: c.strip() for t, c in _INSERT_RE.findall(html)}

        return self._apply_slots_non_strict(self.base.doc, inserts)

    def _apply_imports(self, html: str) -> str:
        import_map = {d.name: d.doc for d in self.imports}

        def repl(m: re.Match) -> str:
            name = m.group(1)
            if name not in import_map:
                raise ObjectHTMLImportError(name)
            return import_map[name]

        return _IMPORT_RE.sub(repl, html)

    def _apply_slots_non_strict(self, html: str, values: dict[str, str]) -> str:
        def repl(m: re.Match) -> str:
            key = m.group(1)
            return str(values[key]) if key in values else m.group(0)
        return _SLOT_RE.sub(repl, html)

    def _apply_slots_strict(self, html: str, values: dict[str, str]) -> str:
        def repl(m: re.Match) -> str:
            key = m.group(1)
            if key not in values:
                raise ObjectHTMLInsertValueError(key)
            return str(values[key])
        return _SLOT_RE.sub(repl, html)
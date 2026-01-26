"""
Nexom Object HTML (OHTML)

A lightweight HTML composition system that extends plain HTML with:
- <Extends ... />
- <Insert ...>...</Insert>
- <Import ... />
- {{slot}}

This renderer also preserves indentation when importing blocks or inserting
multi-line slot values.
"""

from __future__ import annotations

import re
from collections import UserList
from typing import Final

from .error import (
    HTMLDocLibNotFoundError,
    ObjectHTMLImportError,
    ObjectHTMLInsertValueError,
    ObjectHTMLExtendsError,
    ObjectHTMLTypeError
)


# Slots: {{ key }}
_SLOT_RE: Final = re.compile(r"\{\{\s*(\w+)\s*\}\}")

# Extends: <Extends a.b />
_EXTENDS_RE: Final = re.compile(r"<Extends\s+([\w\.]+)\s*/>")

# Insert: <Insert key>...</Insert>
_INSERT_RE: Final = re.compile(r"<Insert\s+([\w\.]+)>(.*?)</Insert>", flags=re.DOTALL)

# Import: line-based (captures indent + name)
# Example:
#     <Import components.header />
_IMPORT_LINE_RE: Final = re.compile(r"(?m)^([ \t]*)<Import\s+([\w\.]+)\s*/>\s*$")


class HTMLDoc:
    """Raw HTML document container (no rendering)."""

    def __init__(self, name: str, html: str) -> None:
        self.name = name.rsplit(".", 1)[0] if name.endswith(".html") else name
        self.html = html

    def __repr__(self) -> str:
        return self.name


class HTMLDocLib(UserList[HTMLDoc]):
    """A list of HTML documents with name lookup."""

    def __init__(self, docs: list[HTMLDoc] | None = None) -> None:
        super().__init__(docs or [])

    def get(self, name: str, raise_error: bool = False) -> HTMLDoc | None:
        for doc in self.data:
            if doc.name == name:
                return doc
        if raise_error:
            raise HTMLDocLibNotFoundError(name)
        return None


class ObjectHTML:
    """
    Object HTML renderer.

    Provides dynamic callable access:
        engine.default(title="x")
        engine.layout.base(title="x")

    Internals:
    - Extends/Insert are applied first (non-strict slots for inserts)
    - Imports are expanded with indentation preserved
    - Final {{slot}} replacement is applied (strict)
    """

    def __init__(self, *docs: HTMLDoc, lib: HTMLDocLib | None = None) -> None:
        self.lib = lib or HTMLDocLib()
        for doc in docs:
            self.lib.append(doc)

        # Build dynamic callables for each doc name
        for doc in self.lib:
            self._set_doc(doc)

    def _set_doc(self, doc: HTMLDoc) -> None:
        if not isinstance(doc, HTMLDoc):
            raise ObjectHTMLTypeError()
        def _call(**kwargs: str) -> str:
            return self.render(doc.name, **kwargs)

        setattr(self, doc.name, _call)

    def render(self, name: str, **kwargs: str) -> str:
        """Render a template by name."""
        html = self._render_structure(name)
        # Final strict slot fill (indent-aware)
        return self._apply_slots_strict(html, kwargs)

    # -------------------------
    # phases
    # -------------------------

    def _render_structure(self, name: str) -> str:
        """Resolve Extends/Insert and Import. Leaves {{slots}} unresolved."""
        doc = self.lib.get(name, raise_error=True)
        html = self._apply_extends(doc.html)
        html = self._apply_imports(html)
        return html

    def _apply_extends(self, html: str) -> str:
        m = _EXTENDS_RE.search(html)
        if not m:
            return html

        extends_name = m.group(1)
        base = self.lib.get(extends_name)
        if not base:
            raise ObjectHTMLExtendsError(extends_name)

        inserts = {t: c.strip() for t, c in _INSERT_RE.findall(html)}

        # Replace only specified slots in base (non-strict, indent-aware)
        return self._apply_slots_non_strict(base.html, inserts)

    def _apply_imports(self, html: str) -> str:
        import_map = {d.name: d.html for d in self.lib}

        def indent_block(block: str, indent: str) -> str:
            # Import replaces the whole line, so indent ALL non-empty lines.
            lines = block.splitlines(True)  # keep line breaks
            out: list[str] = []
            for line in lines:
                if line.strip() == "":
                    out.append(line)
                else:
                    out.append(indent + line)
            return "".join(out)

        def repl(m: re.Match) -> str:
            indent = m.group(1)
            name = m.group(2)

            if name not in import_map:
                raise ObjectHTMLImportError(name)

            imported = import_map[name]
            return indent_block(imported, indent)

        return _IMPORT_LINE_RE.sub(repl, html)

    # -------------------------
    # slot replacement (indent-aware)
    # -------------------------

    def _line_indent_before(self, html: str, pos: int) -> str:
        """
        Return whitespace indent from the start of the line up to pos.

        If the substring from line start to pos contains only whitespace,
        that whitespace is returned. Otherwise returns empty string.
        """
        line_start = html.rfind("\n", 0, pos)
        line_start = 0 if line_start == -1 else line_start + 1
        prefix = html[line_start:pos]

        m = re.match(r"[ \t]*", prefix)
        indent = m.group(0) if m else ""
        # If there is any non-whitespace before the slot, don't indent-inject.
        return indent if prefix == indent else ""

    def _indent_multiline_slot_value(self, value: str, indent: str) -> str:
        """
        Indent multi-line slot values for {{slot}} replacement.

        IMPORTANT: The indent before {{slot}} already remains in the output,
        so we indent ONLY lines after the first line.
        """
        if "\n" not in value:
            return value

        lines = value.splitlines(True)  # keepends
        if not lines:
            return value

        out = [lines[0]]
        for line in lines[1:]:
            if line.strip() == "":
                out.append(line)
            else:
                out.append(indent + line)
        return "".join(out)

    def _apply_slots_non_strict(self, html: str, values: dict[str, str]) -> str:
        def repl(m: re.Match) -> str:
            key = m.group(1)
            if key not in values:
                return m.group(0)

            raw = str(values[key])
            indent = self._line_indent_before(html, m.start())
            if indent:
                return self._indent_multiline_slot_value(raw, indent)
            return raw

        return _SLOT_RE.sub(repl, html)

    def _apply_slots_strict(self, html: str, values: dict[str, str]) -> str:
        def repl(m: re.Match) -> str:
            key = m.group(1)
            if key not in values:
                raise ObjectHTMLInsertValueError(key)

            raw = str(values[key])
            indent = self._line_indent_before(html, m.start())
            if indent:
                return self._indent_multiline_slot_value(raw, indent)
            return raw

        return _SLOT_RE.sub(repl, html)
"""Object HTML template renderer."""

from __future__ import annotations

import html as html_lib
import json
import re
from collections import UserList
from typing import Final, Iterable

from .error import (
    HTMLDocLibNotFoundError,
    ObjectHTMLImportError,
    ObjectHTMLInsertValueError,
    ObjectHTMLExtendsError,
    ObjectHTMLTypeError,
    TemplateUnsafeSlotError,
)


class Markup(str):
    """Trusted HTML fragment that bypasses text slot escaping."""

    __slots__ = ()

    def __html__(self) -> str:
        return str(self)

    def __add__(self, other: object) -> Markup:
        return Markup(str(self) + str(escape(other)))

    def __radd__(self, other: object) -> Markup:
        return Markup(str(escape(other)) + str(self))

    def join(self, iterable: Iterable[object]) -> Markup:
        return Markup(str(self).join(str(escape(value)) for value in iterable))

    def format(self, *args: object, **kwargs: object) -> Markup:
        return Markup(str(self).format(
            *(escape(value) for value in args),
            **{key: escape(value) for key, value in kwargs.items()},
        ))

    def __repr__(self) -> str:
        return f"Markup({str(self)!r})"


def escape(value: object) -> Markup:
    """Escape HTML text, preserving Markup and callable __html__ values."""
    if isinstance(value, Markup):
        return value
    html_method = getattr(value, "__html__", None)
    if callable(html_method):
        return Markup(html_method())
    return Markup(html_lib.escape(str(value), quote=True))


class AttrSafe(Markup):
    """Fully escaped attribute value (quotes encoded); not escaped again in attributes."""

    __slots__ = ()

    def __repr__(self) -> str:
        return f"AttrSafe({str(self)!r})"


def safe_url(
    value: object, *, allowed_schemes: tuple[str, ...] = ("http", "https", "mailto")
) -> AttrSafe:
    """Decode, validate and escape a URL, including trusted Markup inputs."""
    raw = html_lib.unescape(str(value))
    probe = re.sub(r"[\x00-\x20]", "", raw).lower()
    match = re.match(r"^([a-z][a-z0-9+.\-]*):", probe)
    if match and match.group(1) not in allowed_schemes:
        return AttrSafe("")
    return AttrSafe(html_lib.escape(raw, quote=True))


def json_script(value: object, element_id: str | None = None) -> Markup:
    """Embed JSON safely against HTML parser breakout, not innerHTML use."""
    if element_id is not None and re.fullmatch(r"[A-Za-z0-9_-]+", element_id) is None:
        raise ValueError("Invalid JSON script element id.")
    data = json.dumps(value, ensure_ascii=False)
    data = data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    if element_id is not None:
        data = f'<script id="{element_id}" type="application/json">{data}</script>'
    return Markup(data)


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


# Load-time check: event handler / srcdoc / style attribute values must not hold slots.
_UNSAFE_ATTR_SLOT_RE: Final = re.compile(
    r"""(?:\s|<\w+)(on\w+|srcdoc|style)\s*=\s*(?:"[^"]*|'[^']*)\{\{""",
    flags=re.IGNORECASE,
)


def _in_attr_value(html: str, pos: int) -> bool:
    """True if pos lies inside an open quoted attribute value of an HTML tag."""
    start = html.rfind("<", 0, pos)
    if start == -1:
        return False
    if html.startswith("<!--", start):
        return False
    quote = ""
    for ch in html[start + 1:pos]:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == ">":
            return False
    return bool(quote)


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

    Slots inside script bodies are unsupported and unsafe:
    <script>let x={{ x }}</script> with x="alert(1)" executes code.
    Use json_script(data, element_id="boot") and parse the element's
    textContent with JSON.parse in JavaScript. Do not use it with innerHTML.
    """

    def __init__(
        self, *docs: HTMLDoc, lib: HTMLDocLib | None = None, autoescape: bool = True
    ) -> None:
        self.lib = lib or HTMLDocLib()
        self.autoescape = autoescape
        for doc in docs:
            self.lib.append(doc)

        # Build dynamic callables for each doc name
        for doc in self.lib:
            self._set_doc(doc)

    def _set_doc(self, doc: HTMLDoc) -> None:
        if not isinstance(doc, HTMLDoc):
            raise ObjectHTMLTypeError()
        unsafe = _UNSAFE_ATTR_SLOT_RE.search(doc.html)
        if unsafe:
            raise TemplateUnsafeSlotError(doc.name, unsafe.group(1))
        name = doc.name
        if (not name.isidentifier() or name.startswith("_")
                or hasattr(type(self), name) or name in self.__dict__):
            return

        def _call(**kwargs: object) -> Markup:
            return self.render(doc.name, **kwargs)

        setattr(self, doc.name, _call)

    def render(self, name: str, **kwargs: object) -> Markup:
        """Render a template by name."""
        html = self._render_structure(name)
        # Final strict slot fill (indent-aware)
        return Markup(self._apply_slots_strict(html, kwargs))

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

    def _apply_slots_strict(self, html: str, values: dict[str, object]) -> str:
        def repl(m: re.Match) -> str:
            key = m.group(1)
            if key not in values:
                raise ObjectHTMLInsertValueError(key)

            value = values[key]
            if not self.autoescape:
                raw = str(value)
            elif _in_attr_value(html, m.start()):
                if isinstance(value, AttrSafe):
                    raw = str(value)
                else:
                    raw = html_lib.escape(str(value), quote=True)
            else:
                raw = str(escape(value))
            indent = self._line_indent_before(html, m.start())
            if indent:
                return self._indent_multiline_slot_value(raw, indent)
            return raw

        return _SLOT_RE.sub(repl, html)

"""Object HTML template renderer."""

from __future__ import annotations

import html as html_lib
import json
import re
from collections import UserList
from typing import Final, Iterable, NamedTuple

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


class _AttrSafe(Markup):
    """Fully escaped attribute value (quotes encoded); not escaped again in attributes.

    Private: only safe_url() constructs it (use type(safe_url("/")) if the type is needed).
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f"_AttrSafe({str(self)!r})"


def safe_url(
    value: object, *, allowed_schemes: tuple[str, ...] = ("http", "https", "mailto")
) -> Markup:
    """Decode, validate and escape a URL, including trusted Markup inputs."""
    raw = html_lib.unescape(str(value))
    probe = re.sub(r"[\x00-\x20]", "", raw).lower()
    match = re.match(r"^([a-z][a-z0-9+.\-]*):", probe)
    if match and match.group(1) not in allowed_schemes:
        return _AttrSafe("")
    return _AttrSafe(html_lib.escape(raw, quote=True))


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


# -------------------------
# slot classification (HTML tokenizer)
# -------------------------
#
# One forward pass over the template records, for every {{ slot }}, the HTML
# tokenizer state at its start.  Inside a quoted attribute value "<", "<!--"
# and ">" never change state (they are part of the value); inside a tag both
# whitespace and "/" separate attributes (so "<p/onclick=" is an attribute);
# <script>/<style> bodies are RAWTEXT until the matching end tag.

DATA: Final = "DATA"
TAG_OPEN: Final = "TAG_OPEN"              # reading the tag name
IN_TAG: Final = "IN_TAG"                  # between attributes / reading an attribute name
ATTR_VALUE_DQ: Final = "ATTR_VALUE_DQ"
ATTR_VALUE_SQ: Final = "ATTR_VALUE_SQ"
ATTR_VALUE_UNQUOTED: Final = "ATTR_VALUE_UNQUOTED"
COMMENT: Final = "COMMENT"
RAWTEXT: Final = "RAWTEXT"

_ATTR_VALUE_STATES: Final = frozenset({ATTR_VALUE_DQ, ATTR_VALUE_SQ})
_RAWTEXT_TAGS: Final = frozenset({"script", "style"})
_WS: Final = " \t\n\r\f"
_UNSAFE_ATTR_RE: Final = re.compile(r"on\w+|srcdoc|style")


class SlotInfo(NamedTuple):
    """Tokenizer state at a slot start (attr / tag are lowercase, None when not applicable)."""

    start: int
    state: str
    attr: str | None
    tag: str | None


def _classify_slots(html: str) -> list[SlotInfo]:
    """Tokenize html once and record the state at the start of every {{ slot }}."""
    slots = [(m.start(), m.end()) for m in _SLOT_RE.finditer(html)]
    out: list[SlotInfo] = []
    if not slots:
        return out
    n = len(html)
    i = 0
    slot_i = 0
    state = DATA
    # IN_TAG sub-state: "" (expecting a name / separator), "name" (reading a name),
    # "after_name" (name done, "=" may follow), "before_value" ("=" seen, value not started)
    sub = ""
    tag = ""          # current tag name
    closing = False   # </tag>
    attr = ""         # current attribute name
    raw_tag = ""      # tag whose RAWTEXT body we are in

    def end_tag() -> str:
        nonlocal tag, attr, sub, closing, raw_tag
        next_state = DATA
        if not closing and tag in _RAWTEXT_TAGS:
            raw_tag = tag
            next_state = RAWTEXT
        tag, attr, sub, closing = "", "", "", False
        return next_state

    while i < n:
        if slot_i < len(slots) and i == slots[slot_i][0]:
            start, end = slots[slot_i]
            slot_state = state
            if state == IN_TAG and sub == "before_value":
                slot_state = ATTR_VALUE_UNQUOTED
            slot_attr = attr or None
            slot_tag = (raw_tag if state == RAWTEXT else tag) or None
            out.append(SlotInfo(start, slot_state, slot_attr, slot_tag))
            slot_i += 1
            i = end  # the slot text itself never drives the tokenizer
            continue
        ch = html[i]
        if state == DATA:
            if html.startswith("<!--", i):
                state = COMMENT
                i += 4
                continue
            if ch == "<" and i + 1 < n:
                nxt = html[i + 1]
                if nxt.isalpha() or nxt in "!?":
                    state, tag, closing = TAG_OPEN, "", False
                    i += 1
                    continue
                if nxt == "/":
                    state, tag, closing = TAG_OPEN, "", True
                    i += 2
                    continue
                if slot_i < len(slots) and i + 1 == slots[slot_i][0]:
                    state, tag, closing = TAG_OPEN, "", False  # "<{{ t }}>"
                    i += 1
                    continue
            i += 1
        elif state == COMMENT:
            if html.startswith("-->", i):
                state = DATA
                i += 3
                continue
            i += 1
        elif state == RAWTEXT:
            end = i + 2 + len(raw_tag)
            if (ch == "<" and html.startswith("/", i + 1)
                    and html[i + 2:end].lower() == raw_tag
                    and (end >= n or html[end] in _WS + "/>")):
                state, tag, closing, raw_tag = TAG_OPEN, "", True, ""
                i += 2
                continue
            i += 1
        elif state == TAG_OPEN:
            if ch in _WS or ch == "/":
                state, sub = IN_TAG, ""
            elif ch == ">":
                state = end_tag()
            else:
                tag += ch.lower()
            i += 1
        elif state == IN_TAG:
            if sub == "name":
                if ch in _WS:
                    sub = "after_name"
                elif ch == "/":
                    sub, attr = "", ""
                elif ch == "=":
                    sub = "before_value"
                elif ch == ">":
                    state = end_tag()
                else:
                    attr += ch.lower()
            elif sub == "after_name":
                if ch in _WS:
                    pass
                elif ch == "=":
                    sub = "before_value"
                elif ch == "/":
                    sub, attr = "", ""
                elif ch == ">":
                    state = end_tag()
                else:
                    sub, attr = "name", ch.lower()
            elif sub == "before_value":
                if ch in _WS:
                    pass
                elif ch == '"':
                    state = ATTR_VALUE_DQ
                elif ch == "'":
                    state = ATTR_VALUE_SQ
                elif ch == ">":
                    state = end_tag()
                else:
                    state = ATTR_VALUE_UNQUOTED
            else:  # expecting an attribute name, a separator or the end of the tag
                if ch in _WS or ch == "/":
                    pass
                elif ch == ">":
                    state = end_tag()
                else:
                    sub, attr = "name", ch.lower()
            i += 1
        elif state == ATTR_VALUE_DQ:
            if ch == '"':
                state, sub, attr = IN_TAG, "", ""
            i += 1
        elif state == ATTR_VALUE_SQ:
            if ch == "'":
                state, sub, attr = IN_TAG, "", ""
            i += 1
        elif state == ATTR_VALUE_UNQUOTED:
            if ch in _WS:
                state, sub, attr = IN_TAG, "", ""
            elif ch == ">":
                state = end_tag()
            i += 1
        else:  # pragma: no cover - defensive
            i += 1
    return out


def _unsafe_slot_reason(info: SlotInfo) -> str | None:
    """Reason string for OH06 when the slot position is unsafe, else None."""
    if info.state == RAWTEXT:
        return "script/style body"
    if info.state == ATTR_VALUE_UNQUOTED:
        return "unquoted attribute"
    if info.state in (TAG_OPEN, IN_TAG):
        return "tag/attribute name position"
    if info.state == COMMENT:
        return "comment"
    if info.state in _ATTR_VALUE_STATES and info.attr and _UNSAFE_ATTR_RE.fullmatch(info.attr):
        return info.attr
    return None


def _checked_slots(doc_name: str, html: str) -> dict[int, SlotInfo]:
    """Classify slots and raise TemplateUnsafeSlotError (OH06) on the first unsafe one."""
    infos: dict[int, SlotInfo] = {}
    for info in _classify_slots(html):
        reason = _unsafe_slot_reason(info)
        if reason is not None:
            raise TemplateUnsafeSlotError(doc_name, reason)
        infos[info.start] = info
    return infos


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

    Slot positions are classified by a one-pass HTML tokenizer at load time.
    Slots inside <script>/<style> bodies, comments, unquoted attribute values,
    tag/attribute-name position, or on*/srcdoc/style attribute values are
    rejected with TemplateUnsafeSlotError (OH06) regardless of autoescape:
    <script>let x={{ x }}</script> with x="alert(1)" would execute code.
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
        _checked_slots(doc.name, doc.html)
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
        return Markup(self._apply_slots_strict(html, kwargs, name))

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

    def _apply_slots_strict(self, html: str, values: dict[str, object], name: str = "") -> str:
        # Classify on the composed document (Extends / Import applied): a slot's
        # context can differ from the one in its source doc.
        infos = _checked_slots(name, html)

        def repl(m: re.Match) -> str:
            key = m.group(1)
            if key not in values:
                raise ObjectHTMLInsertValueError(key)

            value = values[key]
            info = infos.get(m.start())
            if not self.autoescape:
                raw = str(value)
            elif info is not None and info.state in _ATTR_VALUE_STATES:
                if isinstance(value, _AttrSafe):
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

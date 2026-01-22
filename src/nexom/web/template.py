from __future__ import annotations
import os
import re
from typing import Optional

from ..core.error import TemplateNotFoundError, TemplatesInvalidTypeError


class Template:
    """
    Represents an HTML template with optional inheritance, insertions, and imports.
    """

    def __init__(self, template: str, base_dir: Optional[str] = None, **kwargs: str) -> None:
        self.template: str = template
        self.base_dir: Optional[str] = base_dir
        self.kwargs: dict[str, str] = kwargs
        self._doc: str = self._assemble()

    def _open(self, template: str, **kwargs: str) -> str:
        template_file = template if template.endswith(".html") else f"{template}.html"
        path = os.path.join(self.base_dir, template_file) if self.base_dir else template_file

        if not os.path.exists(path):
            raise TemplateNotFoundError(template_file)

        with open(path, "r", encoding="utf-8") as f:
            doc = f.read()

        return self._render(doc, **kwargs)

    def _render(self, doc: str, **kwargs: str) -> str:
        """
        Replace {{key}} with kwargs values in the template.
        """
        pattern = re.compile(r"\{\{\s*(\w+)\s*\}\}")

        def replace(m: re.Match) -> str:
            key = m.group(1)
            if key not in kwargs:
                raise TemplateNotFoundError(key)
            return str(kwargs[key])

        return pattern.sub(replace, doc)

    def _assemble(self) -> str:
        doc = self._open(self.template, **self.kwargs)

        # Handle <Extends base /> logic
        extends_match = re.search(r"<Extends\s+([\w\.]+)\s*/>", doc)
        if extends_match:
            base_template = extends_match.group(1)
            inserts = re.findall(r"<Insert\s+([\w\.]+)>(.*?)</Insert>", doc, flags=re.DOTALL)
            format_values = self.kwargs.copy()
            for target, content in inserts:
                format_values[target] = content.strip()
            doc = self._open(base_template, **format_values)

        # Handle <Import template /> logic
        import_pattern = re.compile(r"<Import\s+(\w+)\s*/>")

        def replace_import(m: re.Match) -> str:
            template_name = m.group(1)
            return self._open(template_name)

        return import_pattern.sub(replace_import, doc)

    def __repr__(self) -> str:
        return self._doc

    __str__ = __repr__

    def push(self, **kwargs: str) -> str:
        """
        Update template kwargs and re-render.
        """
        self.kwargs = kwargs
        self._doc = self._assemble()
        return self._doc


class Templates:
    """
    Container for multiple Template objects with dynamic access.
    """

    def __init__(self, base_dir: str, *templates: str) -> None:
        self.base_dir: str = base_dir
        for template_name in templates:
            self.append(template_name)

    def append(self, template: str) -> None:
        """
        Add a new template dynamically accessible as a method.
        """
        t_name = template.removesuffix(".html")

        def _call(**kwargs: str) -> str:
            return Template(t_name, self.base_dir, **kwargs).__repr__()

        setattr(self, t_name, _call)

    def delete(self, template: str) -> None:
        if hasattr(self, template):
            delattr(self, template)
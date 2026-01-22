import re 

from ..core.error import ObjectHTMLInsertValueError, ObjectHTMLExtendsError, ObjectHTMLImportError

class HTMLDoc:
    def __init__(self, name: str, doc: str, **kwargs: str) -> None:
        self.name: str = name if not name.endswith('.html') else name.rsplit('.', 1)[0]
        self._doc: str = doc
        self.kwargs: dict[str, str] = kwargs

        self.html: str = self._doc
        self.branks: dict[str, str | None] = {m.group(1): None for m in re.compile(r"\{\{\s*(\w+)\s*\}\}").finditer(self._doc)}

        if kwargs:
            self.insert(**kwargs)


    def insert(self, **kwargs: str) -> None:
        """
        Replace {{key}} with kwargs values in the template.
        """
        def replace(m: re.Match) -> str:
            key = m.group(1)
            if key in kwargs:
                self.branks[key] = kwargs[key]
                return str(kwargs[key])
            else:
                return m.group(0)

        self.html = re.compile(r"\{\{\s*(\w+)\s*\}\}").sub(replace, self._doc)
    
    def __repr__(self) -> str:
        return self.name

class ObjectHTML:
    def __init__(self, doc: HTMLDoc, base: HTMLDoc | None = None, imports: list[HTMLDoc] = [], **kwargs: str) -> None:
        self.name: str = doc.name
        self._doc: str = doc._doc
        self.kwargs: dict[str, str] = kwargs
        self.base: HTMLDoc | None = base
        self.imports: list[HTMLDoc] = imports
        self.html = self._assemble()
    
    def _assemble(self) -> str:
        html = self._doc
        # Handle <Extends document /> logic
        extends_match = re.search(r"<Extends\s+([\w\.]+)\s*/>", self._doc)
        if extends_match:
            extends_name = extends_match.group(1)
            base_object = self.base

            if not base_object:
                raise ObjectHTMLExtendsError(extends_name)
            if not (base_object.name == extends_name):
                raise ObjectHTMLExtendsError(extends_name + " != " + base_object.name)
            
            inserts = re.findall(r"<Insert\s+([\w\.]+)>(.*?)</Insert>", self._doc, flags=re.DOTALL)
            inserts_values = {}
            for target, content in inserts:
                inserts_values[target] = content.strip()
            
            base_object.insert(**inserts_values)
            html = base_object.html

        # Handle <Import document /> logic
        import_pattern = re.compile(r"<Import\s+(\w+)\s*/>")
        def replace_import(m: re.Match) -> str:
            doc_name = m.group(1)
            for imp in self.imports:
                if imp.name == doc_name:
                    return imp.html
            raise ObjectHTMLImportError(doc_name)
        html = import_pattern.sub(replace_import, html)

        # Handle {{key}} replacements
        brank_pattern = re.compile(r"\{\{\s*(\w+)\s*\}\}")
        def replace_brank(m: re.Match) -> str:
            key = m.group(1)
            if not key in self.kwargs:
                raise ObjectHTMLInsertValueError(key)
            
            return str(self.kwargs[key])
        html = brank_pattern.sub(replace_brank, html)

        return html
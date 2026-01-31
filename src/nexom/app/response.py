from __future__ import annotations

from typing import Iterable, Optional
from importlib import resources
import json

from ..core.object_html_render import HTMLDoc, ObjectHTML

from .http_status_codes import http_status_codes


Header = tuple[str, str]


class Response:
    """
    Represents an HTTP response.
    """

    def __init__(
        self,
        body: str | bytes = b"",
        status: int = 200,
        headers: Iterable[Header] | None = None,
        cookie: str | None = None,
        content_type: str = "text/html",
        charset: str = "utf-8",
        include_charset: bool = False
    ) -> None:
        self.charset: str = charset
        self.include_charset: bool = include_charset

        if isinstance(body, str):
            self.body: bytes = body.encode(charset)
            self.is_text: bool = True
        else:
            self.body = body
            self.is_text = False

        self.status_code: int = status

        from .http_status_codes import http_status_codes
        self.status_text: str = f"{status} {http_status_codes.get(status, '')}".strip()

        ct = content_type
        if include_charset and (ct.startswith("text/") or ct == "application/json"):
            ct = f"{ct}; charset={charset}"

        self.headers: list[Header] = list(headers) if headers else [("Content-Type", ct)]

        if cookie:
            self.headers.append(("Set-Cookie", cookie))

        # ---- auto Content-Length (if not already present) ----
        has_len = any(k.lower() == "content-length" for k, _ in self.headers)
        if not has_len and isinstance(self.body, (bytes, bytearray)):
            self.headers.append(("Content-Length", str(len(self.body))))

    def __iter__(self):
        """
        Allow Response to be returned directly from WSGI apps.
        """
        yield self.body

    def append_header(self, key: str, value: str) -> None:
        self.headers.append((key, value))

class HtmlResponse(Response):
    def __init__(
        self,
        body: str | bytes = b"",
        status: int = 200,
        headers: Iterable[Header] | None = None,
        cookie: str | None = None,
        *,
        charset: str = "utf-8",
        include_charset: bool = True,
    ) -> None:
        super().__init__(
            body=body,
            status=status,
            headers=headers,
            cookie=cookie,
            content_type="text/html",
            charset=charset,
            include_charset=include_charset,
        )


class JsonResponse(Response):
    def __init__(
        self,
        body: Optional[dict] = None,
        status: int = 200,
        headers: Iterable[Header] | None = None,
        cookie: str | None = None,
        *,
        charset: str = "utf-8",
        include_charset: bool = True,
    ) -> None:
        if body is None:
            body = {}

        content_type = "application/json"
        if include_charset:
            content_type = f"{content_type}; charset={charset}"

        jb = json.dumps(body, ensure_ascii=False).encode(charset)

        super().__init__(
            body=jb,
            status=status,
            headers=headers,
            cookie=cookie,
            content_type=content_type,
            charset=charset,
            include_charset=False,
        )

class Redirect(Response):
    """
    HTTP redirect response (302).
    """

    def __init__(
        self,
        location: str,
        headers: Iterable[Header] | None = None,
        cookie: str | None = None,
    ) -> None:
        extra = list(headers) if headers else []
        res_headers = [("Location", location), *extra]

        super().__init__(
            body=b"",
            status=302,
            headers=res_headers,
            cookie=cookie,
        )


class ErrorResponse(Response):
    """
    HTML error response rendered from template.
    """

    def __init__(self, status: int, message: str) -> None:
        html = self._render(status, message)
        
        super().__init__(html, status=status)

    @staticmethod
    def _render(status: int, message: str) -> str:
        status_text = f"{status} {http_status_codes.get(status, '')}".strip()

        template = (
            resources.files("nexom.assets.error_page")
            .joinpath("error.html")
            .read_text(encoding="utf-8")
        )

        ohtml = ObjectHTML(HTMLDoc("error_page", template))

        status_str = f"{status} - {http_status_codes.get(status)}"

        return (
            ohtml.render("error_page", status=status_str, message=message)
        )
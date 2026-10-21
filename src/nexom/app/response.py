"""HTTP response classes."""

from __future__ import annotations

from typing import ClassVar, Iterable, Optional
from importlib import resources
import json
import re
from urllib.parse import urlsplit

from ..core.error import ResponseHeaderInvalidError, ResponseRedirectExternalError
from ..core.object_html_render import HTMLDoc, Markup, ObjectHTML, escape

from .http_status_codes import http_status_codes


Header = tuple[str, str]


def _validate_header(name: str, value: str) -> None:
    if (
        not isinstance(name, str)
        or re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name) is None
        or not isinstance(value, str)
        or re.fullmatch(r"[\t\x20-\x7e\x80-\xff]*", value) is None
    ):
        raise ResponseHeaderInvalidError(name)


def _is_local_location(loc: str) -> bool:
    if not loc or loc.startswith("\\"):
        return False
    try:
        parsed = urlsplit(loc)
    except ValueError:
        return False
    return not (
        parsed.scheme or parsed.netloc or loc.startswith(("//", "/\\"))
    )


class Response:
    """
    Represents an HTTP response.
    """

    security_headers: ClassVar[dict[str, str]] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
    }

    def __init__(
        self,
        body: str | bytes = b"",
        status: int = 200,
        headers: Iterable[Header] | None = None,
        cookie: "str | Cookie | None" = None,
        content_type: str = "text/plain",
        charset: str = "utf-8",
        include_charset: bool = False,
        *,
        security_headers: bool = True,
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

        _validate_header("Content-Type", ct)
        base = [("Content-Type", ct)]
        sec = list(type(self).security_headers.items()) if security_headers else []
        caller = list(headers or [])
        for key, value in caller:
            _validate_header(key, value)
        override = {key.lower() for key, _ in caller}
        self.headers: list[Header] = [
            header for header in base + sec if header[0].lower() not in override
        ] + caller

        if cookie is not None:
            self.append_header("Set-Cookie", str(cookie))

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
        """Append a response header (no dedupe)."""
        _validate_header(key, value)
        self.headers.append((key, value))

class HtmlResponse(Response):
    """HTML response with text/html content type."""
    def __init__(
        self,
        body: str | bytes = b"",
        status: int = 200,
        headers: Iterable[Header] | None = None,
        cookie: "str | Cookie | None" = None,
        *,
        charset: str = "utf-8",
        include_charset: bool = True,
        security_headers: bool = True,
    ) -> None:
        super().__init__(
            body=body,
            status=status,
            headers=headers,
            cookie=cookie,
            content_type="text/html",
            charset=charset,
            include_charset=include_charset,
            security_headers=security_headers,
        )


class JsonResponse(Response):
    """JSON response with application/json content type."""
    def __init__(
        self,
        body: Optional[dict] = None,
        status: int = 200,
        headers: Iterable[Header] | None = None,
        cookie: "str | Cookie | None" = None,
        *,
        charset: str = "utf-8",
        include_charset: bool = True,
        security_headers: bool = True,
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
            security_headers=security_headers,
        )

class Redirect(Response):
    """
    HTTP redirect response.
    """

    def __init__(
        self,
        location: str,
        headers: Iterable[Header] | None = None,
        cookie: "str | Cookie | None" = None,
        *,
        status: int = 302,
        allow_external: bool = False,
    ) -> None:
        if status not in (301, 302, 303, 307, 308):
            raise ValueError("Invalid redirect status")
        # Header-injection class first (CR/LF and other controls -> RS01, as for any header).
        _validate_header("Location", location)
        # Local redirects: reject a leading space and any C0 control / DEL anywhere
        # (browsers strip TAB/LF/CR mid-string, so "/\t\\evil" becomes "/\\evil").
        if not allow_external and (
            (location and location[0] == " ")
            or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in location)
            or not _is_local_location(location)
        ):
            raise ResponseRedirectExternalError(location)
        extra = list(headers) if headers else []
        res_headers = [("Location", location), *extra]

        super().__init__(
            body=b"",
            status=status,
            headers=res_headers,
            cookie=cookie,
        )


class ErrorResponse(Response):
    """
    HTML error response rendered from template.
    """

    def __init__(
        self, status: int, message: str, headers: Iterable[Header] | None = None,
    ) -> None:
        html = self._render(status, message)
        
        super().__init__(
            html, status=status, headers=headers,
            content_type="text/html", include_charset=True,
        )

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

        return str(
            ohtml.render("error_page", status=status_str, message=escape(str(message)))
        )

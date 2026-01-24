from __future__ import annotations

from typing import Any, Mapping
from http.cookies import SimpleCookie

from .cookie import RequestCookies


WSGIEnviron = Mapping[str, Any]


class Request:
    """
    Represents an HTTP request constructed from a WSGI environ.
    """

    def __init__(self, environ: WSGIEnviron) -> None:
        self.environ: WSGIEnviron = environ

        self.method: str = environ.get("REQUEST_METHOD", "GET")
        self.path: str = environ.get("PATH_INFO", "").lstrip("/")
        self.query: str = environ.get("QUERY_STRING", "")
        self.headers: dict[str, str] = {
            k[5:].replace("_", "-"): v
            for k, v in environ.items()
            if k.startswith("HTTP_")
        }

        self.cookie: RequestCookies | None = self._parse_cookies()
        self._body: bytes | None = None

    def _parse_cookies(self) -> RequestCookies | None:
        cookie_header = self.environ.get("HTTP_COOKIE")
        if not cookie_header:
            return None

        simple_cookie = SimpleCookie()
        simple_cookie.load(cookie_header)

        cookies = {
            key: morsel.value
            for key, morsel in simple_cookie.items()
        }

        rc = RequestCookies(**cookies)
        rc.default = None
        return rc

    def read_body(self) -> bytes:
        """
        Read and cache the request body.
        """
        if self._body is not None:
            return self._body

        length = int(self.environ.get("CONTENT_LENGTH") or 0)
        if length <= 0:
            self._body = b""
            return self._body

        self._body = self.environ["wsgi.input"].read(length)
        return self._body
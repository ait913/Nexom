"""WSGI request parsing."""

from __future__ import annotations

from typing import Any, Mapping
from dataclasses import dataclass
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
import json

from .cookie import RequestCookies


WSGIEnviron = Mapping[str, Any]


@dataclass(frozen=True)
class File:
    """Uploaded file container from multipart/form-data."""
    filename: str
    content_type: str | None
    size: int | None
    file: Any


# sentinel for caching "None" results
_UNSET = object()


class Request:
    """
    Represents an HTTP request constructed from a WSGI environ.

    Notes:
    - headers keys are normalized to lower-case
    - wsgi.input is readable only once; this class caches parsed body per request
    - .json() / .form() use cached raw body (bytes)
    - .files() parses multipart/form-data using python-multipart (external dependency)
        and cannot be used together with .read_body()/.json()/.form() after reading the stream
    """

    DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB

    def __init__(self, environ: WSGIEnviron, *, max_body_size: int | None = None) -> None:
        self.environ: WSGIEnviron = environ
        self.max_body_size = self.DEFAULT_MAX_BODY_SIZE if max_body_size is None else int(max_body_size)

        self.method: str = str(environ.get("REQUEST_METHOD", "GET")).upper()
        self.path: str = str(environ.get("PATH_INFO", "")).lstrip("/")
        self.query: dict[str, list[str]] = parse_qs(str(environ.get("QUERY_STRING", "")))

        # normalize header keys to lower-case
        self.headers: dict[str, str] = {
            k[5:].replace("_", "-").lower(): v
            for k, v in environ.items()
            if k.startswith("HTTP_") and isinstance(v, str)
        }
        ct = environ.get("CONTENT_TYPE")
        if isinstance(ct, str) and ct:
            self.headers["content-type"] = ct
        cl = environ.get("CONTENT_LENGTH")
        if isinstance(cl, str) and cl:
            self.headers["content-length"] = cl

        self.cookie: RequestCookies | dict[str, str] | None = self._parse_cookies()

        self._body: bytes | None = None
        self._json_cache: Any = _UNSET
        self._form_cache: dict[str, list[str]] | None = None
        self._files_cache: dict[str, str | File] | None = None
        self._multipart_consumed: bool = False

    # -------------------------
    # basic helpers
    # -------------------------

    def _parse_cookies(self) -> RequestCookies | dict[str, str] | None:
        """Parse Cookie header into RequestCookies if possible."""
        cookie_header = self.environ.get("HTTP_COOKIE")
        if not cookie_header:
            return None

        simple_cookie = SimpleCookie()
        simple_cookie.load(cookie_header)

        cookies = {key: morsel.value for key, morsel in simple_cookie.items()}

        try:
            return RequestCookies(**cookies)
        except Exception:
            return cookies

    @property
    def content_type(self) -> str:
        """
        Lower-cased mime type without parameters (no charset/boundary).
        Example:
            "application/json; charset=utf-8" -> "application/json"
        """
        return (self.headers.get("content-type") or "").split(";", 1)[0].strip().lower()

    def _content_length(self) -> int | None:
        raw = self.environ.get("CONTENT_LENGTH")
        try:
            if raw is None or raw == "":
                return None
            n = int(raw)
            return n if n >= 0 else None
        except (TypeError, ValueError):
            return None

    # -------------------------
    # body
    # -------------------------

    def read_body(self) -> bytes:
        """
        Read and cache request body bytes.

        WARNING:
        - If multipart parsing (.files()) already consumed the stream, body will be empty.
        """
        if self._body is not None:
            return self._body

        if self._multipart_consumed:
            self._body = b""
            return self._body

        stream = self.environ["wsgi.input"]
        length = self._content_length()

        if length is not None:
            if length == 0:
                self._body = b""
                return self._body
            if self.max_body_size is not None and length > self.max_body_size:
                raise ValueError(f"Request body too large (Content-Length={length}, max={self.max_body_size})")
            self._body = stream.read(length)
            return self._body

        if self.max_body_size is not None:
            data = stream.read(self.max_body_size + 1)
            if len(data) > self.max_body_size:
                raise ValueError(f"Request body too large (no valid Content-Length, max={self.max_body_size})")
            self._body = data
            return self._body

        self._body = stream.read()
        return self._body

    @property
    def body(self) -> bytes:
        return self.read_body()

    # -------------------------
    # POST parsers
    # -------------------------

    def json(self) -> Any | None:
        """
        Parse application/json body.

        Returns:
            Parsed JSON (dict/list/...) or None if not JSON or empty body.

        Raises:
            json.JSONDecodeError: If Content-Type is JSON but body is invalid.
        """
        if self._json_cache is not _UNSET:
            return self._json_cache  # may be None

        if self.content_type != "application/json":
            self._json_cache = None
            return None

        raw = self.body
        if not raw:
            self._json_cache = None
            return None

        self._json_cache = json.loads(raw.decode("utf-8"))
        return self._json_cache

    def form(self) -> dict[str, list[str]] | None:
        """
        Parse application/x-www-form-urlencoded body.

        Returns:
            dict[str, list[str]] or None if not urlencoded form.
        """
        if self._form_cache is not None:
            return self._form_cache

        if self.content_type != "application/x-www-form-urlencoded":
            return None

        raw = self.body
        if not raw:
            self._form_cache = {}
            return self._form_cache

        self._form_cache = parse_qs(raw.decode("utf-8"))
        return self._form_cache

    def files(self) -> dict[str, str | File] | None:
        """
        Parse multipart/form-data using python-multipart.
        """
        if self._files_cache is not None:
            return self._files_cache

        if self.content_type != "multipart/form-data":
            return None

        try:
            from multipart import MultipartParser  # type: ignore
        except Exception as e:
            raise ModuleNotFoundError(
                "python-multipart is required for multipart/form-data parsing. "
                "Install with: pip install python-multipart"
            ) from e

        # Prevent mixing with body-based parsing
        if self._body is not None:
            raise ValueError("Body was already read. multipart parsing must be done first.")

        self._multipart_consumed = True

        # Extract boundary from Content-Type header
        ctype_full = self.headers.get("content-type", "")
        boundary = None
        for part in ctype_full.split(";")[1:]:
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part.split("=", 1)[1].strip().strip('"')
                break
        if not boundary:
            raise ValueError("multipart/form-data boundary not found")

        stream = self.environ["wsgi.input"]
        parser = MultipartParser(stream, boundary.encode("utf-8"))

        out: dict[str, str | File] = {}

        for p in parser:  # type: ignore
            name = getattr(p, "name", None)
            if not name:
                continue
            if isinstance(name, (bytes, bytearray)):
                name = name.decode("utf-8", errors="replace")

            filename = getattr(p, "filename", None)
            if filename:
                if isinstance(filename, (bytes, bytearray)):
                    filename = filename.decode("utf-8", errors="replace")

                content_type = None
                headers = getattr(p, "headers", None)
                if isinstance(headers, dict):
                    ct = headers.get(b"Content-Type") or headers.get("Content-Type")
                    if ct:
                        content_type = ct.decode() if isinstance(ct, (bytes, bytearray)) else str(ct)

                fileobj = getattr(p, "file", None)
                raw = getattr(p, "raw", None)

                out[name] = File(
                    filename=str(filename),
                    content_type=content_type,
                    size=None,
                    file=fileobj if fileobj is not None else raw,
                )
            else:
                value = getattr(p, "value", None)
                if value is None:
                    raw = getattr(p, "raw", b"")
                    if isinstance(raw, (bytes, bytearray)):
                        value = raw.decode("utf-8", errors="replace")
                    else:
                        value = str(raw)
                if isinstance(value, (bytes, bytearray)):
                    value = value.decode("utf-8", errors="replace")
                out[name] = str(value)

        self._files_cache = out
        return self._files_cache

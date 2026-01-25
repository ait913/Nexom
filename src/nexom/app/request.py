from __future__ import annotations

from typing import Any, Mapping, Optional
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
import json

from .cookie import RequestCookies


WSGIEnviron = Mapping[str, Any]


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

    def __init__(self, environ: WSGIEnviron) -> None:
        self.environ: WSGIEnviron = environ

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

        self.cookie: RequestCookies | None = self._parse_cookies()

        self._body: bytes | None = None
        self._json_cache: Any | None = None
        self._form_cache: dict[str, list[str]] | None = None
        self._files_cache: dict[str, Any] | None = None
        self._multipart_consumed: bool = False

    # -------------------------
    # basic helpers
    # -------------------------

    def _parse_cookies(self) -> RequestCookies | None:
        cookie_header = self.environ.get("HTTP_COOKIE")
        if not cookie_header:
            return None

        simple_cookie = SimpleCookie()
        simple_cookie.load(cookie_header)

        cookies = {key: morsel.value for key, morsel in simple_cookie.items()}
        return RequestCookies(**cookies)

    @property
    def content_type(self) -> str:
        """
        Lower-cased mime type without parameters (no charset/boundary).
        Example:
            "application/json; charset=utf-8" -> "application/json"
        """
        return (self.headers.get("content-type") or "").split(";", 1)[0].strip().lower()

    def _content_length(self) -> int:
        raw = self.environ.get("CONTENT_LENGTH")
        try:
            return int(raw) if raw else 0
        except (TypeError, ValueError):
            return 0

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

        length = self._content_length()
        if length <= 0:
            self._body = b""
            return self._body

        self._body = self.environ["wsgi.input"].read(length)
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
        if self._json_cache is not None:
            return self._json_cache

        if self.content_type != "application/json":
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

    def files(self) -> dict[str, Any] | None:
        """
        Parse multipart/form-data using python-multipart.

        Returns:
            dict[str, Any] mapping field name to either:
              - str for normal form fields
              - dict for file fields:
                    {
                        "filename": str,
                        "content_type": str | None,
                        "size": int | None,
                        "file": <file-like object or bytes depending on backend>
                    }

        Raises:
            ModuleNotFoundError: if python-multipart is not installed.
            ValueError: if Content-Type is multipart but parsing fails.

        IMPORTANT:
            multipart parsing consumes wsgi.input. Do not call .read_body()/.json()/.form()
            after calling this method.
        """
        if self._files_cache is not None:
            return self._files_cache

        if self.content_type != "multipart/form-data":
            return None

        # Lazy import (optional dependency)
        # python-multipart package provides "multipart" module.
        try:
            from multipart import MultipartParser  # type: ignore
        except Exception as e:
            raise ModuleNotFoundError(
                "python-multipart is required for multipart/form-data parsing. "
                "Install with: pip install python-multipart"
            ) from e

        # Prevent mixing with body-based parsing
        if self._body is not None and self._body != b"":
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

        # Parse stream
        stream = self.environ["wsgi.input"]

        parser = MultipartParser(stream, boundary.encode("utf-8"))

        out: dict[str, Any] = {}

        # MultipartParser yields parts; API differs slightly by version.
        # We handle common attributes: name, filename, headers, raw, file.
        for p in parser:  # type: ignore
            name = getattr(p, "name", None)
            if not name:
                continue

            filename = getattr(p, "filename", None)
            if filename:
                # file part
                content_type = None
                headers = getattr(p, "headers", None)
                if isinstance(headers, dict):
                    # some versions use bytes keys/values
                    ct = headers.get(b"Content-Type") or headers.get("Content-Type")
                    if ct:
                        content_type = ct.decode() if isinstance(ct, (bytes, bytearray)) else str(ct)

                # Try to expose a stream if available, else raw bytes
                fileobj = getattr(p, "file", None)
                raw = getattr(p, "raw", None)

                out[name] = {
                    "filename": filename,
                    "content_type": content_type,
                    "size": None,
                    "file": fileobj if fileobj is not None else raw,
                }
            else:
                # normal field
                value = getattr(p, "value", None)
                if value is None:
                    raw = getattr(p, "raw", b"")
                    if isinstance(raw, (bytes, bytearray)):
                        value = raw.decode("utf-8", errors="replace")
                    else:
                        value = str(raw)
                out[name] = value

        self._files_cache = out
        return self._files_cache
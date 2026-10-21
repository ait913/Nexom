"""WSGI request parsing."""

from __future__ import annotations

from typing import Any, Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import parse_qs
import json
import re

from ..core.error import RequestEntityTooLargeError, RequestParseError
from .cookie import RequestCookies


WSGIEnviron = Mapping[str, Any]


@dataclass(frozen=True)
class File:
    """Uploaded file container from multipart/form-data."""
    filename: str
    content_type: str | None
    size: int | None
    file: Any


def client_ip(environ: Mapping[str, Any], *, trusted_proxy_count: int = 0) -> str:
    """Resolve the client address through the configured trusted proxy hops."""
    remote = environ.get("REMOTE_ADDR") or "-"
    if trusted_proxy_count <= 0:
        return remote
    hops = [hop.strip() for hop in (environ.get("HTTP_X_FORWARDED_FOR") or "").split(",") if hop.strip()]
    if len(hops) < trusted_proxy_count:
        return remote
    candidate = hops[-trusted_proxy_count]
    try:
        ip_address(candidate)
    except ValueError:
        return remote
    return candidate


class _LimitedStream:
    """Limit cumulative reads to the body limit plus one detection byte."""

    def __init__(self, stream: Any, *, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._limit - self._read
        if size < 0 or size > remaining + 1:
            size = remaining + 1
        data = self._stream.read(size)
        self._read += len(data)
        if self._read > self._limit:
            raise RequestEntityTooLargeError()
        return data


_COOKIE_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


# sentinel for caching "None" results
_UNSET = object()


class Request:
    """
    Represents an HTTP request constructed from a WSGI environ.

    Notes:
    - headers keys are normalized to lower-case
    - wsgi.input is readable only once; this class caches parsed body per request
    - .json() / .form() use cached raw body (bytes)
    - .files() parses multipart/form-data using multipart (external dependency)
        and cannot be used together with .read_body()/.json()/.form() after reading the stream
    """

    DEFAULT_MAX_BODY_SIZE: int = 10 * 1024 * 1024  # 10MB
    DEFAULT_MAX_MULTIPART_PARTS: int = 64

    def __init__(
        self,
        environ: WSGIEnviron,
        *,
        max_body_size: int | None = None,
        max_multipart_parts: int | None = None,
        trusted_proxy_count: int = 0,
    ) -> None:
        self.environ: WSGIEnviron = environ
        self.max_body_size = self.DEFAULT_MAX_BODY_SIZE if max_body_size is None else int(max_body_size)

        self.max_multipart_parts = (
            self.DEFAULT_MAX_MULTIPART_PARTS if max_multipart_parts is None else max_multipart_parts
        )
        self.trusted_proxy_count = trusted_proxy_count
        self._length = self._content_length()

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

        cookies: dict[str, str] = {}
        for piece in cookie_header.split(";"):
            name, separator, value = piece.strip().partition("=")
            if not separator or _COOKIE_NAME.fullmatch(name) is None:
                continue
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            cookies.setdefault(name, value)
        if "self" in cookies:
            # Avoid colliding with the constructor's instance parameter.
            parsed = RequestCookies()
            parsed.update(cookies)
            return parsed
        return RequestCookies(**cookies)

    @property
    def remote_addr(self) -> str:
        return self.environ.get("REMOTE_ADDR") or ""

    @property
    def client_ip(self) -> str:
        return client_ip(self.environ, trusted_proxy_count=self.trusted_proxy_count)

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
        except (TypeError, ValueError) as e:
            raise RequestParseError("invalid Content-Length") from e
        if n < 0:
            raise RequestParseError("invalid Content-Length")
        return n

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
        length = self._length

        if length is not None:
            if length == 0:
                self._body = b""
                return self._body
            if length > self.max_body_size:
                raise RequestEntityTooLargeError()
            self._body = stream.read(length)
            return self._body

        data = stream.read(self.max_body_size + 1)
        if len(data) > self.max_body_size:
            raise RequestEntityTooLargeError()
        self._body = data
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
            RequestParseError: If Content-Type is JSON but body is invalid.
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

        try:
            self._json_cache = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RequestParseError("invalid JSON body") from e
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

        try:
            self._form_cache = parse_qs(raw.decode("utf-8"), max_num_fields=1000)
        except (UnicodeDecodeError, ValueError) as e:
            raise RequestParseError("invalid form body") from e
        return self._form_cache

    def files(self) -> dict[str, str | File] | None:
        """
        Parse multipart/form-data using multipart.
        """
        if self._files_cache is not None:
            return self._files_cache

        if self.content_type != "multipart/form-data":
            return None

        try:
            from multipart import MultipartParser, ParserLimitReached, MultipartError  # type: ignore
        except Exception as e:
            raise ModuleNotFoundError(
                "multipart is required for multipart/form-data parsing. "
                "Install with: pip install multipart"
            ) from e

        # Prevent mixing with body-based parsing
        if self._body is not None:
            raise ValueError("Body was already read. multipart parsing must be done first.")

        length = self._length
        if length is not None and length > self.max_body_size:
            raise RequestEntityTooLargeError()

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
            raise RequestParseError("multipart/form-data boundary not found")

        out: dict[str, str | File] = {}

        limited = _LimitedStream(self.environ["wsgi.input"], limit=self.max_body_size)
        try:
            parser = MultipartParser(
                limited,
                boundary.encode("utf-8"),
                content_length=length if length is not None else -1,
                part_limit=self.max_multipart_parts,
                partsize_limit=self.max_body_size,
                disk_limit=self.max_body_size,
                memory_limit=min(8 * 1024 * 1024, self.max_body_size),
                spool_limit=64 * 1024,
            )
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

                    fileobj = getattr(p, "file", None)
                    raw = getattr(p, "raw", None)

                    out[name] = File(
                        filename=str(filename),
                        content_type=p.content_type,
                        size=p.size,
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

        except ParserLimitReached as e:
            raise RequestEntityTooLargeError() from e
        except MultipartError as e:
            raise RequestParseError("invalid multipart body") from e

        self._files_cache = out
        return self._files_cache

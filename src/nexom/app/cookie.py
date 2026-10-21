"""HTTP cookie helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import format_datetime
import re
from typing import Literal

from .response import Response
from ..core.error import CookieInvalidAttributeError, CookieInvalidValueError


class Cookie:
    """Represents a single HTTP cookie with read-only attributes."""

    def __init__(
        self,
        name: str,
        value: str,
        *,
        max_age: int | None = None,
        expires: datetime | None = None,
        path: str = "/",
        domain: str | None = None,
        secure: bool = True,
        http_only: bool = True,
        same_site: Literal["Strict", "Lax", "None"] = "Lax",
    ) -> None:
        if not isinstance(name, str) or re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name) is None:
            raise CookieInvalidValueError("Cookie name contains invalid characters")
        if not isinstance(value, str) or re.fullmatch(r"[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*", value) is None:
            raise CookieInvalidValueError("Cookie value contains invalid characters")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or re.fullmatch(r"[\x21-\x3A\x3C-\x7E]*", path) is None
        ):
            raise CookieInvalidAttributeError("path", "Expected an absolute path without invalid characters")
        if domain is not None and (
            not isinstance(domain, str) or re.fullmatch(r"[A-Za-z0-9.-]+", domain) is None
        ):
            raise CookieInvalidAttributeError("domain", "Invalid domain characters")
        if max_age is not None:
            if not isinstance(max_age, int) or isinstance(max_age, bool):
                raise CookieInvalidAttributeError("max_age", "Expected an integer")
            max_age = max(0, max_age)
        if expires is not None:
            if not isinstance(expires, datetime):
                raise CookieInvalidAttributeError("expires", "Expected a datetime")
            if expires.tzinfo is None or expires.utcoffset() is None:
                expires = expires.replace(tzinfo=timezone.utc)
            else:
                expires = expires.astimezone(timezone.utc)
        if same_site not in ("Strict", "Lax", "None"):
            raise CookieInvalidAttributeError("same_site", "Expected Strict, Lax, or None")
        if same_site == "None" and not secure:
            raise CookieInvalidAttributeError("same_site", "None requires Secure")

        self._name = name
        self._value = value
        self._max_age = max_age
        self._expires = expires
        self._path = path
        self._domain = domain
        self._secure = secure
        self._http_only = http_only
        self._same_site = same_site

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> str:
        return self._value

    @property
    def max_age(self) -> int | None:
        return self._max_age

    @property
    def expires(self) -> datetime | None:
        return self._expires

    @property
    def path(self) -> str:
        return self._path

    @property
    def domain(self) -> str | None:
        return self._domain

    @property
    def secure(self) -> bool:
        return self._secure

    @property
    def http_only(self) -> bool:
        return self._http_only

    @property
    def same_site(self) -> Literal["Strict", "Lax", "None"]:
        return self._same_site

    @classmethod
    def delete(
        cls,
        name: str,
        *,
        path: str = "/",
        domain: str | None = None,
        secure: bool = True,
        http_only: bool = True,
        same_site: Literal["Strict", "Lax", "None"] = "Lax",
    ) -> "Cookie":
        """Expire a cookie; path and domain must match those used at issuance."""
        return cls(
            name, "", max_age=0, expires=datetime(1970, 1, 1, tzinfo=timezone.utc),
            path=path, domain=domain, secure=secure, http_only=http_only,
            same_site=same_site,
        )

    def to_header(self) -> str:
        """Return the Set-Cookie header value."""
        parts = [f"{self.name}={self.value}"]
        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")
        if self.expires is not None:
            parts.append(f"Expires={format_datetime(self.expires, usegmt=True)}")
        parts.append(f"Path={self.path}")
        if self.domain is not None:
            parts.append(f"Domain={self.domain}")
        if self.secure:
            parts.append("Secure")
        if self.http_only:
            parts.append("HttpOnly")
        parts.append(f"SameSite={self.same_site}")
        return "; ".join(parts)

    def __repr__(self) -> str:
        return self.to_header()

    def __str__(self) -> str:
        return self.to_header()

    def response(self, body: str | bytes = "OK") -> Response:
        """Generate a response with this cookie set."""
        return Response(body, cookie=self)


class RequestCookies(dict[str, str | None]):
    """
    Container for cookies parsed from a request.
    """

    def __init__(self, **kwargs: str) -> None:
        super().__init__(kwargs)
        self.default: str | None = None

    def get(self, key: str, default: str | None = None) -> str | None:
        if default is None:
            default = self.default
        return super().get(key, default)
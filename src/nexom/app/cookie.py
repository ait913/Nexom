from __future__ import annotations
from typing import Any
from .response import Response
from ..core.error import CookieInvalidValueError


class Cookie:
    """
    Represents a single HTTP cookie.
    """

    def __init__(
        self,
        name: str,
        value: str,
        *,
        http_only: bool = True,
        secure: bool = True,
        **kwargs: str | int,
    ) -> None:
        if name is None:
            raise CookieInvalidValueError("Cookie name cannot be None")
        self.name: str = name
        self.value: str = value
        self.http_only: bool = http_only
        self.secure: bool = secure
        self.attributes: dict[str, str | int] = kwargs

    def __repr__(self) -> str:
        parts = [f"{self.name}={self.value};"]
        for k, v in self.attributes.items():
            parts.append(f"{k}={v};")
        if self.http_only:
            parts.append("HttpOnly;")
        if self.secure:
            parts.append("Secure;")
        return " ".join(parts)

    def __str__(self) -> str:
        return repr(self)

    def set(self, key: str, value: str | int) -> None:
        """
        Add or update an attribute of the cookie.
        """
        self.attributes[key] = value

    def to_header(self) -> str:
        """
        Return the cookie string for Set-Cookie header.
        """
        return str(self)

    def response(self, body: str | bytes = "OK") -> Response:
        """
        Generate a Response object with this cookie set.
        """
        res = Response(body)
        res.headers.append(("Set-Cookie", self.to_header()))
        return res


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
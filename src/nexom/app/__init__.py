"""
Nexom application layer public API.

This module exposes the stable interfaces intended for application developers.
Internal implementation details should NOT be imported directly.
"""

# ---- Request / Response ----
from .request import Request
from .response import (
    Response,
    HtmlResponse,
    JsonResponse,
    Redirect,
    ErrorResponse,
)

# ---- Routing ----
from .path import Path, Static, Router

# ---- Cookie ----
from .cookie import Cookie, RequestCookies

# ---- Templates ----
from .template import ObjectHTMLTemplates

# ---- Auth ----
from .auth import AuthService, AuthClient

# ---- Middleware ----
from .middleware import Middleware, MiddlewareChain


__all__ = [
    # request / response
    "Request",
    "Response",
    "HtmlResponse",
    "JsonResponse",
    "Redirect",
    "ErrorResponse",

    # routing
    "Path",
    "Static",
    "Pathlib",

    # cookie
    "Cookie",
    "RequestCookies",

    # templates
    "ObjectHTMLTemplates",

    # auth
    "AuthService",
    "AuthVerify",

    # middleware
    "Middleware",
    "MiddlewareChain",
]
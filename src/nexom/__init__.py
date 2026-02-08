"""
NEXOM - A lightweight Python web framework.

Top-level public API exports the most commonly used application-layer types.
"""

from __future__ import annotations

from .app import (
    Request,
    Response,
    HtmlResponse,
    JsonResponse,
    Redirect,
    ErrorResponse,
    Path,
    Get,
    Post,
    Static,
    Router,
    Cookie,
    RequestCookies,
    ObjectHTMLTemplates,
    AuthService,
    AuthClient,
    KEY_NAME,
    ParallelStorage,
    MultiPartUploader,
)

__all__ = [
    "Request",
    "Response",
    "HtmlResponse",
    "JsonResponse",
    "Redirect",
    "ErrorResponse",
    "Path",
    "Get",
    "Post",
    "Static",
    "Router",
    "Cookie",
    "RequestCookies",
    "ObjectHTMLTemplates",
    "AuthService",
    "AuthClient",
    "KEY_NAME",
    "ParallelStorage",
    "MultiPartUploader",
    "__version__",
]

__version__ = "1.1.0"

"""Nexom public API exports."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

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

try:
    __version__ = _pkg_version("nexom")
except PackageNotFoundError:  # 未インストールのソースツリーから import した時
    __version__ = "0.0.0+unknown"

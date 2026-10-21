"""WSGI entrypoint template for generated auth app."""

from __future__ import annotations

from typing import Callable, Iterable
import time

from nexom.app.request import Request, client_ip
from nexom.app.response import Response, JsonResponse
from nexom.core.log import AppLogger, sanitize_log_field
from nexom.app.auth import AuthService

from auth.config import (
    AUTH_DB,
    INFO_LOG,
    WARN_LOG,
    ERR_LOG,
    ACES_LOG,
    AUTH_LOG,
    MASTER_USER,
    ALLOWED_CLIENTS,
    TRUSTED_PROXY_COUNT,
)


# Logger
logger = AppLogger(
    info=INFO_LOG,
    warn=WARN_LOG,
    error=ERR_LOG,
    access=ACES_LOG,
)

# AuthService
service = AuthService(
    AUTH_DB,
    AUTH_LOG,
    master_user=MASTER_USER,
    master_login_password="",
    allowed_clients=ALLOWED_CLIENTS,
)


def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    t0 = time.time()
    req: Request | None = None
    res: Response
    try:
        req = Request(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT)
        res = service.handler(environ)
    except Exception as e:
        logger.error(e)
        res = JsonResponse({"ok": False, "error": "InternalError"}, status=500)

    try:
        dt_ms = int((time.time() - t0) * 1000)
        method = req.method if req else str(environ.get("REQUEST_METHOD") or "-")
        path = (req.path if req else str(environ.get("PATH_INFO") or "")).lstrip("/")
        ip = client_ip(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT)
        ua = str(environ.get("HTTP_USER_AGENT") or "-")
        logger.access(
            f'{sanitize_log_field(ip)} "{sanitize_log_field(method)} /{sanitize_log_field(path)}" '
            f'{res.status_code} {dt_ms}ms "{sanitize_log_field(ua)}"'
        )
    except Exception:
        pass

    start_response(res.status_text, res.headers)
    return [res.body]

from __future__ import annotations

from typing import Callable, Iterable
import time

from nexom.app.request import Request
from nexom.app.response import JsonResponse
from nexom.core.error import NexomError
from nexom.core.log import AppLogger, AuthLogger
from nexom.app.auth import AuthService

from auth.config import AUTH_DB, INFO_LOG, WARN_LOG, ERR_LOG, ACES_LOG, AUTH_LOG


# Logger
logger = AppLogger(
    info=INFO_LOG,
    warn=WARN_LOG,
    error=ERR_LOG,
    access=ACES_LOG,
)

# AuthService
service = AuthService(AUTH_DB, AUTH_LOG)


def _ip(environ: dict) -> str:
    xff = environ.get("HTTP_X_FORWARDED_FOR")
    if isinstance(xff, str) and xff.strip():
        return xff.split(",")[0].strip()
    return str(environ.get("REMOTE_ADDR") or "-")


def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    """
    WSGI application entrypoint.
    """
    try:
        t0 = time.time()

        res = service.handler(environ)

    except NexomError as e:
        logger.error(e)
        return JsonResponse({"error": e.code})
    except Exception:
        logger.error(e)
        return JsonResponse({"error": "Internal Server Error"})
    
    try:
        req = Request(environ)
        dt_ms = int((time.time() - t0) * 1000)
        method = req.method if req else str(environ.get("REQUEST_METHOD") or "-")
        path = (req.path if req else str(environ.get("PATH_INFO") or "")).lstrip("/")
        ip = _ip(environ)
        ua = str(environ.get("HTTP_USER_AGENT") or "-")
        logger.access(f'{ip} "{method} /{path}" {res.status_code} {dt_ms}ms "{ua}"')
    except Exception:
        pass

    start_response(res.status_text, res.headers)
    return [res.body]
from __future__ import annotations

from typing import Callable, Iterable
import time

from nexom.app.request import Request
from nexom.app.response import Response, ErrorResponse
from nexom.core.error import PathNotFoundError
from nexom.core.log import AppLogger, AuthLogger

from __app_name__.config import INFO_LOG, WARN_LOG, ERR_LOG, ACES_LOG
from .router import routing


# Logger (global)
logger = AppLogger(
    info=INFO_LOG,
    warn=WARN_LOG,
    error=ERR_LOG,
    access=ACES_LOG,
)


def _ip(environ: dict) -> str:
    xff = environ.get("HTTP_X_FORWARDED_FOR")
    if isinstance(xff, str) and xff.strip():
        return xff.split(",")[0].strip()
    return str(environ.get("REMOTE_ADDR") or "-")


def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    t0 = time.time()

    req: Request | None = None
    res: Response

    try:
        req = Request(environ)
        path = req.path
        method = req.method

        res = routing.handle(req)

    except PathNotFoundError as e:
        logger.warn(str(e))
        res = ErrorResponse(404, "Not Found")

    except Exception as e:
        logger.error(e)
        res = ErrorResponse(500, "Internal Server Error")

    try:
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
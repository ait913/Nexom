"""WSGI entrypoint template for generated app."""

from __future__ import annotations

from typing import Callable, Iterable
import time

from nexom.app.request import Request, client_ip
from nexom.app.response import Response, ErrorResponse
from nexom.app.http_status_codes import http_status_codes
from nexom.core.error import (
    PathNotFoundError,
    PathMethodNotAllowedError,
    RequestEntityTooLargeError,
    RequestParseError,
)
from nexom.core.log import AppLogger, sanitize_log_field

from __app_name__.config import INFO_LOG, WARN_LOG, ERR_LOG, ACES_LOG, MAX_BODY_SIZE, TRUSTED_PROXY_COUNT
from .router import routing


logger = AppLogger(info=INFO_LOG, warn=WARN_LOG, error=ERR_LOG, access=ACES_LOG)


def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    t0 = time.time()
    req: Request | None = None
    res: Response

    try:
        req = Request(environ, max_body_size=MAX_BODY_SIZE, trusted_proxy_count=TRUSTED_PROXY_COUNT)
        res = routing.handle(req)
    except PathNotFoundError:
        # Log 404s only to access.log to avoid warning.log growth from anonymous scans (DATA-12).
        res = ErrorResponse(404, http_status_codes[404])
    except PathMethodNotAllowedError as e:
        res = ErrorResponse(405, http_status_codes[405], headers=[("Allow", e.allow_header)])
    except RequestEntityTooLargeError:
        res = ErrorResponse(413, http_status_codes[413])
    except RequestParseError:
        res = ErrorResponse(400, http_status_codes[400])
    except Exception as e:
        logger.error(e)
        res = ErrorResponse(500, http_status_codes[500])

    try:
        dt_ms = int((time.time() - t0) * 1000)
        method = req.method if req else str(environ.get("REQUEST_METHOD") or "-")
        path = (req.path if req else str(environ.get("PATH_INFO") or "")).lstrip("/")
        ip = req.client_ip if req else client_ip(environ, trusted_proxy_count=TRUSTED_PROXY_COUNT)
        ua = str(environ.get("HTTP_USER_AGENT") or "-")
        logger.access(
            f'{ip} "{sanitize_log_field(method)} /{sanitize_log_field(path)}" '
            f'{res.status_code} {dt_ms}ms "{sanitize_log_field(ua)}"'
        )
    except Exception:
        pass

    start_response(res.status_text, res.headers)
    return [res.body]

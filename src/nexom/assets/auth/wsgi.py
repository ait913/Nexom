from __future__ import annotations

from typing import Callable, Iterable

from nexom.app.request import Request
from nexom.app.response import Response, ErrorResponse
from nexom.app.auth import AuthService

from auth.config import AUTH_DB
SERVICE = AuthService(AUTH_DB)

def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    """
    WSGI application entrypoint.
    """
    try:
        res: Response = SERVICE.handler(environ)

    except Exception as e:
        res = ErrorResponse(500, str(e))

    start_response(res.status_text, res.headers)
    return [res.body]
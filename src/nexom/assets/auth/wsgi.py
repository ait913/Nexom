from __future__ import annotations

from typing import Callable, Iterable

from nexom.app.request import Request
from nexom.app.response import JsonResponse
from nexom.app.auth import AuthService

from nexom.core.error import NexomError

from auth.config import AUTH_DB
SERVICE = AuthService(AUTH_DB)

def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    """
    WSGI application entrypoint.
    """
    try:
        res: JsonResponse = SERVICE.handler(environ)

    except NexomError as e:
        return JsonResponse({"error": e.code})
    except Exception:
        return JsonResponse({"error": "Internal Server Error"})

    start_response(res.status_text, res.headers)
    return [res.body]
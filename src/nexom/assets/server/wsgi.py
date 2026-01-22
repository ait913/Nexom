from __future__ import annotations

from typing import Callable, Iterable

from nexom.web.request import Request
from nexom.web.response import Response, ErrorResponse
from nexom.core.error import PathNotFoundError

# Project-local router
from router import routing


def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    """
    WSGI application entrypoint.
    """
    try:
        request = Request(environ)
        path = request.path

        p = routing.get(path)
        res = p.call_handler(request)

    except PathNotFoundError as e:
        res = ErrorResponse(404, str(e))
    except Exception as e:
        res = ErrorResponse(500, str(e))

    start_response(res.status_text, res.headers)
    return [res.body]
from __future__ import annotations

from io import BytesIO
from typing import Any


def make_environ(
    *,
    method: str = "GET",
    path: str = "/",
    query: str = "",
    body: bytes = b"",
    content_type: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "SERVER_NAME": "testserver",
        "SERVER_PORT": "80",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.input": BytesIO(body),
    }

    if body is not None:
        environ["CONTENT_LENGTH"] = str(len(body))
    if content_type:
        environ["CONTENT_TYPE"] = content_type

    if headers:
        for k, v in headers.items():
            key = "HTTP_" + k.upper().replace("-", "_")
            environ[key] = v

    return environ

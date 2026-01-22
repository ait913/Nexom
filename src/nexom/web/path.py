from __future__ import annotations
import os
import re
import json
from mimetypes import guess_type
from typing import Callable, Any, Optional, Iterable

from ..core.error import (
    PathNotFoundError,
    PathlibTypeError,
    PathInvalidHandlerTypeError,
    PathHandlerMissingArgError,
)
from .request import Request
from .response import Response, JsonResponse
from .middleware import Middleware, MiddlewareChain, Handler


class Path:
    """
    Represents a route with optional path arguments and its handler.
    """

    def __init__(self, path: str, handler: Handler, name: str):
        self.handler = handler
        self.name: str = name

        path_segments = path.strip("/").split("/")
        self.path_args: dict[int, str] = {}
        detection_index = 0

        for idx, segment in enumerate(path_segments):
            m = re.match(r"{(.*?)}", segment)
            if m:
                if detection_index == 0:
                    detection_index = idx
                self.path_args[idx] = m.group(1)
            if idx == len(path_segments) - 1 and detection_index == 0:
                detection_index = idx + 1

        self.path: str = "/".join(path_segments[:detection_index])
        self.detection_range: int = detection_index
        self.args: dict[str, Optional[str]] = {}

    def _read_args(self, request_path: str) -> None:
        segments = request_path.strip("/").split("/")
        for idx, arg_name in self.path_args.items():
            self.args[arg_name] = segments[idx] if idx < len(segments) else None

    def call_handler(self, request: Request, middlewares: tuple[Middleware, ...] = ()) -> Response:
        try:
            self._read_args(request.path)

            handler = self.handler
            if middlewares:
                handler = MiddlewareChain(middlewares).wrap(handler)

            res = handler(request, self.args)
            if isinstance(res, dict):
                return JsonResponse(res)
            if not isinstance(res, Response):
                raise PathInvalidHandlerTypeError(self.handler)
            return res
        except TypeError as e:
            if re.search(r"takes \d+ positional arguments? but \d+ were given", str(e)):
                raise PathHandlerMissingArgError()
            raise


class Static(Path):
    """
    Represents a static file route.
    """

    def __init__(self, path: str, static_directory: str, name: str) -> None:
        self.static_directory = os.path.abspath(static_directory.rstrip("/"))
        super().__init__(path, self._access, name)

    def _access(self, request: Request, args: dict[str, Optional[str]]) -> Response:
        segments = request.path.strip("/").split("/")
        relative_path = os.path.join(*segments[self.detection_range :]) if len(segments) > self.detection_range else ""
        abs_path = os.path.abspath(os.path.join(self.static_directory, relative_path))

        if os.path.isdir(abs_path):
            abs_path = os.path.join(abs_path, "index.html")

        if not abs_path.startswith(self.static_directory) or not os.path.exists(abs_path):
            raise PathNotFoundError(request.path)

        with open(abs_path, "rb") as f:
            content = f.read()

        mime_type, _ = guess_type(abs_path)
        return Response(content, headers=[("Content-Type", mime_type or "application/octet-stream")])


class Pathlib(list[Path]):
    """
    Collection of Path objects with middleware support.
    """

    def __init__(self, *paths: Path) -> None:
        for p in paths:
            self._check(p)
        super().__init__(paths)
        self.raise_if_not_exist: bool = True
        self.middlewares: list[Middleware] = []

    def _check(self, arg: object) -> None:
        if not isinstance(arg, Path):
            raise PathlibTypeError

    def add_middleware(self, *middlewares: Middleware) -> None:
        self.middlewares.extend(middlewares)

    def get(self, request_path: str) -> Path | None:
        segments = request_path.rstrip("/").split("/")
        for p in self:
            detection_path = "/".join(segments[: p.detection_range])
            if detection_path == p.path:
                return p

        if self.raise_if_not_exist:
            raise PathNotFoundError(request_path)
        return None
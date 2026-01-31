from __future__ import annotations

import os
import re
from mimetypes import guess_type
from pathlib import Path as _Path
from typing import Optional

from ..core.error import (
    PathNotFoundError,
    PathlibTypeError,
    PathInvalidHandlerTypeError,
    PathHandlerMissingArgError,
)
from .request import Request
from .response import Response, JsonResponse
from .middleware import Middleware, MiddlewareChain, Handler


# ====================
# Path (base)
# ====================

class Path:
    """Represents a route with optional path arguments and its handler."""

    def __init__(
        self,
        path: str,
        handler: Handler,
        name: str,
        *,
        methods: set[str] | None = None,   # None = any method
    ):
        self.handler = handler
        self.name: str = name
        self.methods: set[str] | None = {m.upper() for m in methods} if methods else None

        path_segments = path.strip("/").split("/") if path.strip("/") else [""]
        self.path_args: dict[int, str] = {}

        detection_index = 0
        for idx, segment in enumerate(path_segments):
            m = re.match(r"{(.*?)}", segment)
            if m:
                if detection_index == 0:
                    detection_index = idx
                self.path_args[idx] = m.group(1)

        if detection_index == 0:
            detection_index = 0 if path == "" else len(path_segments)

        self.path: str = "/".join(path_segments[:detection_index])
        self.detection_range: int = detection_index

    def _read_args(self, request_path: str) -> dict[str, Optional[str]]:
        """Build args for this request. (No shared state)"""
        args: dict[str, Optional[str]] = {}
        segments = request_path.strip("/").split("/") if request_path.strip("/") else [""]
        for idx, arg_name in self.path_args.items():
            args[arg_name] = segments[idx] if idx < len(segments) else None
        return args

    def call_handler(
        self,
        request: Request,
        middlewares: tuple[Middleware, ...] = (),
    ) -> Response:
        try:
            args = self._read_args(request.path)

            handler = self.handler
            if middlewares:
                handler = MiddlewareChain(middlewares).wrap(handler)

            res = handler(request, args)

            if isinstance(res, dict):
                return JsonResponse(res)

            if not isinstance(res, Response):
                raise PathInvalidHandlerTypeError(self.handler)

            return res

        except TypeError as e:
            # handler の引数不足
            if re.search(r"takes \d+ positional arguments? but \d+ were given", str(e)):
                raise PathHandlerMissingArgError()
            raise


# ====================
# Method specific paths
# ====================

class Get(Path):
    def __init__(self, path: str, handler: Handler, name: str):
        super().__init__(path, handler, name, methods={"GET"})


class Post(Path):
    def __init__(self, path: str, handler: Handler, name: str):
        super().__init__(path, handler, name, methods={"POST"})


# ====================
# Static files
# ====================

class Static(Path):
    """Represents a static file route."""

    def __init__(self, path: str, static_directory: str, name: str) -> None:
        self._root = _Path(static_directory).resolve()
        super().__init__(path, self._access, name)

    def _access(self, request: Request, args: dict[str, Optional[str]]) -> Response:
        segments = request.path.strip("/").split("/") if request.path.strip("/") else [""]
        relative_parts = segments[self.detection_range :] if len(segments) > self.detection_range else []
        rel = _Path(*relative_parts) if relative_parts else _Path("")

        try:
            target = (self._root / rel).resolve()
        except Exception:
            raise PathNotFoundError(request.path)

        if not str(target).startswith(str(self._root) + os.sep) and target != self._root:
            raise PathNotFoundError(request.path)

        if target.is_dir():
            target = (target / "index.html").resolve()

        if not target.exists() or not target.is_file():
            raise PathNotFoundError(request.path)

        data = target.read_bytes()
        mime_type, _ = guess_type(str(target))

        headers = [
            ("Content-Type", mime_type or "application/octet-stream"),
            ("Content-Length", str(len(data))),
        ]
        return Response(data, headers=headers)


# ====================
# Pathlib
# ====================

class Router(list[Path]):
    """Collection of Path objects with middleware support."""

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

    def get(self, request_path: str, *, method: str | None = None) -> Path | None:
        segments = request_path.rstrip("/").split("/")
        method_u = method.upper() if method else None

        fallback: Path | None = None

        for p in self:
            detection_path = "/".join(segments[: p.detection_range])
            if detection_path != p.path:
                continue

            # Method-specific Path has priority
            if method_u and p.methods is not None:
                if method_u in p.methods:
                    return p
                continue

            # Method-agnostic Path as fallback
            if fallback is None:
                fallback = p

        if fallback is not None:
            return fallback

        if self.raise_if_not_exist:
            raise PathNotFoundError(request_path)
        return None
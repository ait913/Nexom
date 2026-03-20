"""Routing and static file serving."""

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
        self._segments = path.strip("/").split("/") if path.strip("/") else []
        self.path_args: dict[int, str] = {}
        self.index_allocation_styles: list[int] = []  # 0=static, 1=dynamic
        self._static_segments: list[str] = []
        self._wildcard_index: int | None = None

        detection_index: int | None = None

        for idx, segment in enumerate(self._segments):
            m = re.fullmatch(r"{(.+)}", segment)
            if not m:
                self.index_allocation_styles.append(0)
                self._static_segments.append(segment)
                continue

            if detection_index is None:
                detection_index = idx

            key = m.group(1).strip()
            if key in ("*", '"*"', "'*'"):
                if idx != len(self._segments) - 1:
                    raise ValueError('{"*"} must be the last path segment.')
                self._wildcard_index = idx
                break

            self.index_allocation_styles.append(1)
            self._static_segments.append("")
            self.path_args[idx] = key

        if detection_index is None:
            detection_index = len(self.index_allocation_styles)

        self.detection_range: int = detection_index
        self.path: str = "/".join(self._segments[: self.detection_range])
        self.has_wildcard: bool = self._wildcard_index is not None
        self.index_range: int | None = None if self.has_wildcard else len(self.index_allocation_styles)

    def _read_args(self, request_path: str) -> dict[str, Optional[str] | list[str]]:
        """Build args for this request (no shared state)."""
        req_segments = request_path.strip("/").split("/") if request_path.strip("/") else []
        args: dict[str, Optional[str] | list[str]] = {}
        styles_len = len(self.index_allocation_styles)
        req_len = len(req_segments)
        dead: set[tuple[int, int]] = set()
        consumed_at_match: int | None = None

        def _match(i: int, j: int) -> bool:
            nonlocal consumed_at_match

            if (i, j) in dead:
                return False

            if i == styles_len:
                if self.has_wildcard:
                    consumed_at_match = j
                    return True
                if j == req_len:
                    consumed_at_match = j
                    return True
                dead.add((i, j))
                return False

            style = self.index_allocation_styles[i]
            if style == 0:
                if j >= req_len or req_segments[j] != self._static_segments[i]:
                    dead.add((i, j))
                    return False
                return _match(i + 1, j + 1)

            key = self.path_args[i]

            # left-greedy: dynamic consumes segment first, then fallback to None.
            if j < req_len:
                args[key] = req_segments[j]
                if _match(i + 1, j + 1):
                    return True

            args[key] = None
            if _match(i + 1, j):
                return True

            args.pop(key, None)
            dead.add((i, j))
            return False

        if not _match(0, 0):
            raise PathNotFoundError(request_path)

        if self.has_wildcard:
            consumed = 0 if consumed_at_match is None else consumed_at_match
            subpath = req_segments[consumed:]
            if len(subpath) > 10:
                raise PathNotFoundError(request_path)
            args["subpath"] = subpath

        return args

    def match(self, request_path: str) -> tuple[bool, int]:
        """
        Return whether request_path matches this path and static match count.
        """
        try:
            args = self._read_args(request_path)
        except PathNotFoundError:
            return False, 0

        static_count = self.detection_range
        if self.has_wildcard and isinstance(args.get("subpath"), list):
            # wildcard routes are less specific than exact routes with same prefix
            static_count -= 1
        return True, static_count

    def call_handler(
        self,
        request: Request,
        middlewares: tuple[Middleware, ...] = (),
    ) -> Response:
        """
        Execute the handler (and middlewares) and normalize the result.
        """
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
    """GET-only route."""
    def __init__(self, path: str, handler: Handler, name: str):
        super().__init__(path, handler, name, methods={"GET"})


class Post(Path):
    """POST-only route (plus OPTIONS for preflight)."""
    def __init__(self, path: str, handler: Handler, name: str):
        super().__init__(path, handler, name, methods={"POST", "OPTIONS"})


# ====================
# Static files
# ====================

class Static(Path):
    """Represents a static file route."""

    def __init__(self, path: str, static_directory: str, name: str) -> None:
        self._root = _Path(static_directory).resolve()
        prefix = path.strip("/")
        static_route = '{"*"}' if not prefix else f'{prefix}/{{"*"}}'
        super().__init__(static_route, self._access, name)

    def _access(self, request: Request, args: dict[str, Optional[str] | list[str]]) -> Response:
        """Serve a static file from the configured root."""
        subpath = args.get("subpath")
        relative_parts = subpath if isinstance(subpath, list) else []
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
        """Register middleware(s) for this router."""
        self.middlewares.extend(middlewares)

    def get(self, request_path: str, *, method: str | None = None) -> Path | None:
        """
        Resolve a Path for a request path and method.

        Returns None if not found and raise_if_not_exist is False.
        """
        method_u = method.upper() if method else None

        matched_with_method: list[tuple[Path, int]] = []
        matched_fallback: list[tuple[Path, int]] = []
        for p in self:
            ok, score = p.match(request_path)
            if not ok:
                continue

            # Method-specific Path has priority
            if method_u and p.methods is not None:
                if method_u in p.methods:
                    matched_with_method.append((p, score))
                continue

            # Method-agnostic Path as fallback
            matched_fallback.append((p, score))

        if matched_with_method:
            return max(matched_with_method, key=lambda t: t[1])[0]
        if matched_fallback:
            return max(matched_fallback, key=lambda t: t[1])[0]

        if self.raise_if_not_exist:
            raise PathNotFoundError(request_path)
        return None

    def handle(self, request: Request) -> Response:
        """Resolve and execute a route for the given request."""
        path = self.get(request.path, method=request.method)
        if path is None:
            raise PathNotFoundError(request.path)
        return path.call_handler(request, tuple(self.middlewares))

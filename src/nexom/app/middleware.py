from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, TypeAlias, Any

from .request import Request
from .response import Response


Handler: TypeAlias = Callable[[Request, dict[str, str | None]], Response]


class Middleware(Protocol):
    """
    Middleware interface.

    A middleware receives the request, route args, and next handler.
    It must return a Response.
    """

    def __call__(self, request: Request, args: dict[str, str | None], next_: Handler) -> Response:
        ...


@dataclass(frozen=True)
class MiddlewareChain:
    """
    Build and execute a middleware chain.
    """
    middlewares: tuple[Middleware, ...]

    def wrap(self, handler: Handler) -> Handler:
        """
        Wrap the given handler with middlewares (outer -> inner).
        """
        def wrapped(request: Request, args: dict[str, str | None]) -> Response:
            # Build chain lazily per call (safe and simple)
            def call_at(i: int, req: Request, a: dict[str, str | None]) -> Response:
                if i >= len(self.middlewares):
                    return handler(req, a)

                mw = self.middlewares[i]

                def next_(r: Request, aa: dict[str, str | None]) -> Response:
                    return call_at(i + 1, r, aa)

                return mw(req, a, next_)

            return call_at(0, request, args)

        return wrapped
    

class CORSMiddleware:
    def __init__(
        self,
        allowed_origins: list[str] | None = None,   # None or ["*"] = allow all
        allowed_methods: list[str] | None = None,
        allowed_headers: list[str] | None = None,
        access_control_allow_credentials: bool = False,
        max_age: int | None = 600,
    ) -> None:
        self.allowed_origins = allowed_origins or ["*"]
        self.allowed_methods = [m.upper() for m in (allowed_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"])]
        self.allowed_headers = allowed_headers or ["Content-Type", "Authorization"]
        self.allow_credentials = access_control_allow_credentials
        self.max_age = max_age

    def _is_allowed_origin(self, origin: str) -> bool:
        return "*" in self.allowed_origins or origin in self.allowed_origins

    def _append_vary_origin(self, res: Response) -> None:
        # append_header が単純 append なので、重複しないように軽くケア
        for k, v in getattr(res, "headers", []):
            if k.lower() == "vary":
                # 既に Vary があるなら Origin が含まれてるかだけチェック
                if "origin" in [p.strip().lower() for p in v.split(",")]:
                    return
                res.append_header("Vary", v + ", Origin")
                return
        res.append_header("Vary", "Origin")

    def __call__(self, request: Request, args: dict[str, str | None], next_: Handler) -> Response:
        origin = request.headers.get("origin")
        if not origin:
            return next_(request, args)

        if not self._is_allowed_origin(origin):
            return next_(request, args)

        # preflight 判定
        acrm = request.headers.get("access-control-request-method")
        is_preflight = request.method == "OPTIONS" and acrm is not None

        if is_preflight:
            # 204で十分（body無し）
            res = Response(b"", status=204)
        else:
            res = next_(request, args)

        # Allow-Origin（単一 or *）
        if "*" in self.allowed_origins and not self.allow_credentials:
            res.append_header("Access-Control-Allow-Origin", "*")
        else:
            # credentials=True なら必ず echo（*は禁止）
            res.append_header("Access-Control-Allow-Origin", origin)
            self._append_vary_origin(res)

        # Allow-Credentials
        if self.allow_credentials:
            res.append_header("Access-Control-Allow-Credentials", "true")

        # Allow-Methods
        if self.allowed_methods == ["*"]:
            req_method = request.headers.get("access-control-request-method")
            res.append_header("Access-Control-Allow-Methods", req_method or "GET, POST, PUT, DELETE, OPTIONS")
        else:
            res.append_header("Access-Control-Allow-Methods", ", ".join(self.allowed_methods))
        
        # Allow-Headers
        if self.allowed_headers == ["*"]:
            req_headers = request.headers.get("access-control-request-headers")
            # ブラウザが要求してきたヘッダをそのまま許可
            if req_headers:
                res.append_header("Access-Control-Allow-Headers", req_headers)
            else:
                res.append_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        else:
            res.append_header("Access-Control-Allow-Headers", ", ".join(self.allowed_headers))


        if self.max_age is not None:
            res.append_header("Access-Control-Max-Age", str(self.max_age))

        return res
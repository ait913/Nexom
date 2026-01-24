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
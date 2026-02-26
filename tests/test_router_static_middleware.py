from __future__ import annotations

from pathlib import Path

import pytest
from nexom.app.request import Request
from nexom.app.response import Response, JsonResponse
from nexom.app.path import Router, Get, Post, Static
from nexom.app.middleware import MiddlewareChain, CORSMiddleware
from nexom.core.error import PathNotFoundError

from conftest import make_environ


def test_router_get_post_and_options():
    def handler(req, args):
        return Response("ok")

    routing = Router(
        Get("ping/", handler, "Ping"),
        Post("submit/", handler, "Submit"),
    )

    req_get = Request(make_environ(method="GET", path="/ping/"))
    res_get = routing.handle(req_get)
    assert res_get.status_code == 200

    req_post = Request(make_environ(method="POST", path="/submit/"))
    res_post = routing.handle(req_post)
    assert res_post.status_code == 200

    req_opt = Request(make_environ(method="OPTIONS", path="/submit/"))
    res_opt = routing.handle(req_opt)
    assert res_opt.status_code == 200


def test_static_files(tmp_path: Path):
    root = tmp_path / "static"
    root.mkdir()
    (root / "hello.txt").write_text("hello", encoding="utf-8")

    static = Static("static/", str(root), "Static")
    req = Request(make_environ(method="GET", path="/static/hello.txt"))
    res = static.call_handler(req, ())
    assert res.status_code == 200
    assert res.body == b"hello"


def test_middleware_chain_and_cors():
    def handler(req, args):
        return Response("ok")

    def mw1(req, args, next_):
        res = next_(req, args)
        res.append_header("X-MW", "1")
        return res

    chain = MiddlewareChain((mw1,))
    wrapped = chain.wrap(handler)
    res = wrapped(Request(make_environ(method="GET", path="/")), {})
    assert ("X-MW", "1") in res.headers

    cors = CORSMiddleware()
    env = make_environ(
        method="OPTIONS",
        path="/",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    res = cors(Request(env), {}, handler)
    headers = dict(res.headers)
    assert headers.get("Access-Control-Allow-Origin") == "*"


def test_router_does_not_match_extra_segments_for_static_route():
    def handler(req, args):
        return Response("ok")

    routing = Router(Get("banana/", handler, "Banana"))
    with pytest.raises(PathNotFoundError):
        routing.handle(Request(make_environ(method="GET", path="/banana/hoge1/hoge2")))


def test_router_allows_missing_trailing_dynamic_as_none():
    def handler(req, args):
        return JsonResponse({"arg1": args.get("arg1")})

    routing = Router(Get("user/{arg1}", handler, "User"))

    res1 = routing.handle(Request(make_environ(method="GET", path="/user/")))
    assert res1.status_code == 200
    assert res1.body.decode("utf-8").find('"arg1": null') >= 0

    res2 = routing.handle(Request(make_environ(method="GET", path="/user/abc")))
    assert res2.status_code == 200
    assert res2.body.decode("utf-8").find('"arg1": "abc"') >= 0


def test_router_allows_missing_leading_dynamic_as_none():
    def handler(req, args):
        return JsonResponse({"dummy": args.get("dummy")})

    routing = Router(Get("{dummy}/val1", handler, "DynStatic"))

    res1 = routing.handle(Request(make_environ(method="GET", path="/val1")))
    assert res1.status_code == 200
    assert res1.body.decode("utf-8").find('"dummy": null') >= 0

    res2 = routing.handle(Request(make_environ(method="GET", path="/abc/val1")))
    assert res2.status_code == 200
    assert res2.body.decode("utf-8").find('"dummy": "abc"') >= 0

from __future__ import annotations

from pathlib import Path

from nexom.app.request import Request
from nexom.app.response import Response
from nexom.app.path import Router, Get, Post, Static
from nexom.app.middleware import MiddlewareChain, CORSMiddleware

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

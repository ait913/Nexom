import json

from nexom.web.path import Path, Pathlib
from nexom.web.response import Response
from nexom.web.request import Request
from nexom.core.error import PathNotFoundError


def test_path_extracts_args(make_environ):
    def handler(req: Request, args: dict):
        return Response(args["id"])

    p = Path("user/{id}", handler, "User")
    req = Request(make_environ(path="/user/123"))
    res = p.call_handler(req)
    assert res.body == b"123"


def test_path_returns_json_when_handler_returns_dict(make_environ):
    def handler(req: Request, args: dict):
        return {"ok": True, "id": args.get("id")}

    p = Path("user/{id}", handler, "User")
    req = Request(make_environ(path="/user/7"))
    res = p.call_handler(req)

    data = json.loads(res.body.decode("utf-8"))
    assert data["ok"] is True
    assert data["id"] == "7"
    assert any("application/json" in v for k, v in res.headers if k.lower() == "content-type")


def test_pathlib_get_found(make_environ):
    def h(req: Request, args: dict):
        return Response("ok")

    lib = Pathlib(Path("a/", h, "A"))
    assert lib.get("a/") is not None


def test_pathlib_get_not_found_raises(make_environ):
    lib = Pathlib()
    try:
        lib.get("missing/")
        assert False, "should raise"
    except PathNotFoundError:
        assert True
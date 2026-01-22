import pytest

def test_middleware_chain_order(make_environ):
    """
    middleware 実装が入ってる場合だけ通るテスト。
    無い場合は skip。
    """
    try:
        from nexom.web.middleware import MiddlewareChain
    except Exception:
        pytest.skip("middleware module not available")

    from nexom.web.response import Response
    from nexom.web.request import Request

    events = []

    def mw1(req, args, next_):
        events.append("mw1-before")
        res = next_(req, args)
        events.append("mw1-after")
        return res

    def mw2(req, args, next_):
        events.append("mw2-before")
        res = next_(req, args)
        events.append("mw2-after")
        return res

    def handler(req, args):
        events.append("handler")
        return Response("ok")

    wrapped = MiddlewareChain((mw1, mw2)).wrap(handler)

    req = Request(make_environ(path="/"))
    res = wrapped(req, {})
    assert res.body == b"ok"

    assert events == [
        "mw1-before",
        "mw2-before",
        "handler",
        "mw2-after",
        "mw1-after",
    ]
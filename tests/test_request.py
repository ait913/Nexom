from nexom.web.request import Request

def test_request_parses_method_and_path(make_environ):
    env = make_environ(path="/hello/world", method="POST")
    req = Request(env)
    assert req.method == "POST"
    # Request は strip("/") してる想定
    assert req.path == "hello/world"


def test_request_reads_body_bytes(make_environ):
    env = make_environ(path="/", body=b"abc")
    req = Request(env)
    assert req.read_body() == b"abc"


def test_request_cookie_parsing(make_environ):
    env = make_environ(headers={"HTTP_COOKIE": "a=1; b=two"})
    req = Request(env)
    assert req.cookie is not None
    assert req.cookie.get("a") == "1"
    assert req.cookie.get("b") == "two"
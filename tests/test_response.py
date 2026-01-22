from nexom.web.response import Response, Redirect, ErrorResponse


def test_response_encodes_str_body():
    r = Response("hello")
    assert isinstance(r.body, (bytes, bytearray))
    assert r.body == b"hello"


def test_response_default_headers_has_content_type():
    r = Response("x")
    assert any(k.lower() == "content-type" for k, _ in r.headers)


def test_response_sets_cookie_header():
    r = Response("x", cookie="a=1; HttpOnly")
    assert any(k.lower() == "set-cookie" for k, _ in r.headers)


def test_redirect_sets_location():
    r = Redirect("/to")
    assert r.status_code == 302
    assert ("Location", "/to") in r.headers


def test_error_response_builds_response():
    r = ErrorResponse(404, "nope")
    assert r.status_code == 404
    assert isinstance(r.body, (bytes, bytearray))
    assert any(k.lower() == "content-type" for k, _ in r.headers)
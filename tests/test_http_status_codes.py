from nexom.web.http_status_codes import http_status_codes


def test_http_status_codes_has_200():
    assert http_status_codes[200] == "OK"


def test_http_status_codes_has_404():
    assert http_status_codes[404] == "Not Found"
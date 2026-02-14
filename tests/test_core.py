from __future__ import annotations

from nexom.core.error import NexomError, PsArgmentsError
from nexom.app.http_status_codes import http_status_codes


def test_nexom_error_str():
    err = NexomError("X01", "oops")
    assert str(err) == "X01 -> oops"


def test_ps_arguments_error_message():
    err = PsArgmentsError("name")
    assert "name" in str(err)


def test_http_status_codes_basic():
    assert http_status_codes[200] == "OK"
    assert http_status_codes[404] == "Not Found"

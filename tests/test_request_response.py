from __future__ import annotations

import json
from io import BytesIO

import pytest

from nexom.app.request import Request, File
from nexom.app.response import Response, JsonResponse, Redirect, ErrorResponse

from conftest import make_environ


def test_request_json():
    body = json.dumps({"a": 1}).encode("utf-8")
    env = make_environ(method="POST", path="/", body=body, content_type="application/json")
    req = Request(env)
    assert req.json() == {"a": 1}


def test_request_form():
    body = b"a=1&b=2&b=3"
    env = make_environ(method="POST", path="/", body=body, content_type="application/x-www-form-urlencoded")
    req = Request(env)
    assert req.form() == {"a": ["1"], "b": ["2", "3"]}


def test_request_files_simple():
    boundary = "----nexomtestboundary"
    body = (
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"public_id\"\r\n\r\n"
        "abc\r\n"
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "hello\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    env = make_environ(
        method="POST",
        path="/",
        body=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    req = Request(env)
    form = req.files()
    assert form is not None
    assert form["public_id"] == "abc"
    assert isinstance(form["file"], File)
    f = form["file"]
    data = f.file.read() if hasattr(f.file, "read") else f.file
    assert data == b"hello"


def test_response_headers():
    res = Response("hello")
    assert res.status_code == 200
    assert ("Content-Length", "5") in res.headers


def test_json_response_and_redirect():
    res = JsonResponse({"ok": True})
    assert res.status_code == 200
    assert res.body.startswith(b"{")

    redir = Redirect("/next")
    assert redir.status_code == 302
    assert ("Location", "/next") in redir.headers


def test_error_response():
    res = ErrorResponse(404, "missing")
    assert res.status_code == 404
    assert b"missing" in res.body

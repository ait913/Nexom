from __future__ import annotations

from pathlib import Path

from nexom.core.object_html_render import HTMLDoc, ObjectHTML
from nexom.templates.auth import AuthPages
from nexom.app.request import Request
from nexom.app.response import HtmlResponse
from nexom.buildTools.build import create_app, create_auth

from conftest import make_environ


def test_object_html_render_simple():
    base = HTMLDoc("base", "<div>{{slot}}</div>")
    child = HTMLDoc("child", "<Extends base />\n<Insert slot>hello</Insert>")
    engine = ObjectHTML(base, child)
    out = engine.render("child")
    assert out.strip() == "<div>hello</div>"


def test_auth_pages_login_get(tmp_path: Path):
    # AuthPages should return HTML on GET without external calls
    pages = AuthPages("user/", "http://localhost:7070")
    req = Request(make_environ(method="GET", path="/user/login/"))
    res = pages.call_handler(req, {})
    assert isinstance(res, HtmlResponse)
    assert res.status_code == 200


def test_buildtools_create_app_and_auth(tmp_path: Path):
    app_root = create_app(tmp_path, "banana")
    assert (app_root / "router.py").exists()

    auth_root = create_auth(tmp_path)
    assert (auth_root / "wsgi.py").exists()

from __future__ import annotations

from pathlib import Path

from nexom.core.object_html_render import HTMLDoc, ObjectHTML
from nexom.templates.auth import AuthPages
from nexom.app.request import Request
from nexom.app.response import HtmlResponse
import pytest

from nexom.buildTools.build import create_app, create_auth, create_config

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


def test_buildtools_create_config_for_existing_app(tmp_path: Path):
    app_root = tmp_path / "banana"
    app_root.mkdir()
    cfg = create_config(tmp_path, "banana")
    assert cfg.exists()
    assert cfg.name == "config.py"


def test_buildtools_create_config_raises_if_exists(tmp_path: Path):
    app_root = tmp_path / "banana"
    app_root.mkdir()
    (app_root / "config.py").write_text("# existing\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        create_config(tmp_path, "banana")

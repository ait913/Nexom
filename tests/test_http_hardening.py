"""Nexom 1.2.0 http-hardening: tests derived ONLY from .designs/20261021-http-hardening.md (§17).

Test names carry the behaviour-spec ID (test_E01_..., test_K01_...). No implementation was read.
"""
from __future__ import annotations

import inspect
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path as FsPath

import pytest

from conftest import make_environ

from nexom.app import Markup, escape, safe_url, json_script, CORSMiddleware, client_ip, File  # G10
from nexom.app.cookie import Cookie
from nexom.app.middleware import CORSMiddleware as _CORS
from nexom.app.path import Router, Get, Post, Path, Static
from nexom.app.request import Request
from nexom.app.request import client_ip as client_ip_fn
from nexom.app.response import (
    ErrorResponse,
    HtmlResponse,
    JsonResponse,
    Redirect,
    Response,
)
from nexom.buildTools.build import AppBuildOptions, create_app, create_auth, create_config, start_project
from nexom.core.error import (
    CookieInvalidAttributeError,
    CookieInvalidValueError,
    NexomError,
    PathMethodNotAllowedError,
    PathNotFoundError,
    RequestEntityTooLargeError,
    RequestParseError,
    ResponseHeaderInvalidError,
    ResponseRedirectExternalError,
    TemplateUnsafeSlotError,
)
from nexom.core.object_html_render import HTMLDoc, ObjectHTML
from nexom.app.template import ObjectHTMLTemplates

MiB = 1024 * 1024
SEC_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"),
]


def _eng(html: str, **kw) -> ObjectHTML:
    return ObjectHTML(HTMLDoc("t", html), **kw)


# ============================================================ E: autoescape


def test_E01_text_context_is_escaped():
    out = _eng("<h2>{{ v }}</h2>").render("t", v="</h2><script>alert(1)</script>")
    assert out == "<h2>&lt;/h2&gt;&lt;script&gt;alert(1)&lt;/script&gt;</h2>"


def test_E02_double_quote_attr_escaped():
    out = _eng('<a title="{{ v }}">').render("t", v='" onmouseover="alert(1)')
    assert out == '<a title="&quot; onmouseover=&quot;alert(1)">'


def test_E03_single_quote_attr_escaped():
    out = _eng("<a title='{{ v }}'>").render("t", v="' onmouseover='x")
    assert out == "<a title='&#x27; onmouseover=&#x27;x'>"


def test_E04_markup_passthrough_in_text():
    assert _eng("<h2>{{ v }}</h2>").render("t", v=Markup("<b>ok</b>")) == "<h2><b>ok</b></h2>"


def test_E05_none_renders_as_None():
    assert _eng("<h2>{{ v }}</h2>").render("t", v=None) == "<h2>None</h2>"


def test_E06_int_value():
    assert _eng("<h2>{{ v }}</h2>").render("t", v=5) == "<h2>5</h2>"


def test_E07_dunder_html_protocol():
    class H:
        def __html__(self):
            return "<i>h</i>"

    assert _eng("<h2>{{ v }}</h2>").render("t", v=H()) == "<h2><i>h</i></h2>"


def test_E08_render_returns_markup():
    assert isinstance(_eng("<h2>{{ v }}</h2>").render("t", v="x"), Markup)


def test_E09_nested_render_escaped_once():
    engine = _eng("<h2>{{ v }}</h2>")
    inner = engine.render("t", v="<x>")
    outer = ObjectHTML(HTMLDoc("o", "<div>{{ c }}</div>")).render("o", c=inner)
    assert outer == "<div><h2>&lt;x&gt;</h2></div>"


def test_E10_markup_join_escapes_items():
    out = Markup("\n").join([Markup("<a>"), "<b>"])
    assert out == "<a>\n&lt;b&gt;"
    assert isinstance(out, Markup)


def test_E11_markup_format_escapes_args():
    out = Markup("<i>{}</i>").format("<x>")
    assert out == "<i>&lt;x&gt;</i>" and isinstance(out, Markup)
    assert Markup("<i>{}</i>").format(Markup("<x>")) == "<i><x></i>"


def test_E12_markup_add_radd():
    a = Markup("<a>") + "<b>"
    assert a == "<a>&lt;b&gt;" and isinstance(a, Markup)
    b = "<b>" + Markup("<a>")
    assert b == "&lt;b&gt;<a>" and isinstance(b, Markup)
    c = Markup("<a>") + Markup("<b>")
    assert c == "<a><b>" and isinstance(c, Markup)


def test_E13_strip_returns_plain_str():
    assert type(Markup("<a>").strip()) is str


def test_E14_insert_is_not_escaped():
    base = HTMLDoc("base", "<div>{{slot}}</div>")
    child = HTMLDoc("child", "<Extends base />\n<Insert slot><b>hello</b></Insert>")
    out = ObjectHTML(base, child).render("child")
    assert out.strip() == "<div><b>hello</b></div>"


def test_E15_no_reexpansion():
    assert _eng("<h2>{{ v }}</h2>").render("t", v="{{ v }}") == "<h2>{{ v }}</h2>"


def test_E16_autoescape_false_legacy():
    assert _eng("<h2>{{ v }}</h2>", autoescape=False).render("t", v="<b>") == "<h2><b></h2>"


def test_E17_templates_dir(tmp_path):
    (tmp_path / "page.html").write_text("<p>{{ x }}</p>", encoding="utf-8")
    tpl = ObjectHTMLTemplates(str(tmp_path))
    out = tpl.render("page", x="<s>")
    assert out == "<p>&lt;s&gt;</p>" and isinstance(out, Markup)
    out2 = tpl.page(x="<s>")
    assert out2 == "<p>&lt;s&gt;</p>" and isinstance(out2, Markup)


def test_E18_safe_url_allowed():
    for u in ["https://a.example/x", "/rel", "?q=1", "#top", "//other.example/x", "mailto:a@b"]:
        r = safe_url(u)
        assert r == u and isinstance(r, Markup)


@pytest.mark.parametrize("u", ["javascript:alert(1)", "java\tscript:alert(1)", " JAVASCRIPT:x", "data:text/html,x", "x:y"])
def test_E19_safe_url_rejected(u):
    r = safe_url(u)
    assert r == "" and isinstance(r, Markup)


def test_E20_safe_url_escapes_allowed():
    assert safe_url('https://a/?q="<x>') == "https://a/?q=&quot;&lt;x&gt;"


def test_E21_json_script_escapes():
    out = json_script({"a": "</script><b>&"})
    assert out == '{"a": "\\u003c/script\\u003e\\u003cb\\u003e\\u0026"}'
    assert isinstance(out, Markup)


def test_E22_json_script_wrapped_and_id_validated():
    assert json_script({"a": 1}, element_id="boot") == '<script id="boot" type="application/json">{"a": 1}</script>'
    with pytest.raises(ValueError):
        json_script({"a": 1}, element_id="x y")


def test_E23_error_response_escapes():
    res = ErrorResponse(404, "<img src=x onerror=alert(1)>")
    assert b"&lt;img src=x onerror=alert(1)&gt;" in res.body
    assert b"<img" not in res.body
    assert ("Content-Type", "text/html; charset=utf-8") in res.headers
    assert b"missing" in ErrorResponse(404, "missing").body


def test_E24_error_response_escapes_markup_too():
    res = ErrorResponse(500, Markup("<b>x</b>"))
    assert b"&lt;b&gt;x&lt;/b&gt;" in res.body
    assert b"<b>" not in res.body


def test_E25_reserved_template_name_does_not_shadow_method():
    engine = ObjectHTML(HTMLDoc("render", "<p>{{ a }}</p>"))
    assert engine.render.__name__ == "render"
    assert engine.render("render", a="1") == "<p>1</p>"


def test_E26_markup_escaped_in_attr_position_but_not_text():
    v = Markup('y" onmouseover="alert(1)')
    out = _eng('<a title="{{ v }}">x</a>').render("t", v=v)
    assert out == '<a title="y&quot; onmouseover=&quot;alert(1)">x</a>'
    assert _eng("<p>{{ v }}</p>").render("t", v=v) == '<p>y" onmouseover="alert(1)</p>'


def test_E27_attr_position_detection_tolerates_spaces_and_attr_name_slot_is_rejected():
    out = _eng("<a title = '{{ v }}'>").render("t", v=Markup("<b>"))
    assert out == "<a title = '&lt;b&gt;'>"
    # Slot in attribute-name position (IN_TAG) is rejected at load time (OH06, tokenizer rule (d)).
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        _eng('<p data-x="a" {{ v }}>')
    assert ei.value.code == "OH06" and "tag/attribute name position" in str(ei.value)


@pytest.mark.parametrize(
    "html,attr",
    [
        ('<div onclick="{{ h }}">', "onclick"),
        ('<div style="color:{{ c }}">', "style"),
        ("<iframe srcdoc='{{ d }}'>", "srcdoc"),
        ('<div  onmouseover = "x{{ h }}">', "onmouseover"),
    ],
)
def test_E28_unsafe_attribute_slots_rejected(html, attr, tmp_path):
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        ObjectHTML(HTMLDoc("t", html))
    assert ei.value.code == "OH06" and attr in str(ei.value)
    with pytest.raises(TemplateUnsafeSlotError):
        ObjectHTML(HTMLDoc("t", html), autoescape=False)
    (tmp_path / "bad.html").write_text(html, encoding="utf-8")
    with pytest.raises(TemplateUnsafeSlotError):
        ObjectHTMLTemplates(str(tmp_path))


@pytest.mark.parametrize("html", ['<div data-onx="{{ v }}">', '<p title="on{{ v }}">', '<a href="{{ u }}">'])
def test_E28_safe_lookalikes_allowed(html):
    ObjectHTML(HTMLDoc("t", html))


def test_E29_script_body_limitation_is_documented():
    # doc: no output assertion; only check the limitation is written down near ObjectHTML.
    import nexom.core.object_html_render as m

    text = (inspect.getdoc(ObjectHTML) or "") + (inspect.getdoc(m) or "")
    assert "<script>" in text and "json_script" in text


def test_E30_safe_url_decodes_char_refs():
    assert safe_url(Markup("jav&#x61;script:alert(1)")) == ""
    assert safe_url(Markup("https://a/x")) == "https://a/x"
    assert safe_url("https://a/?x=1&amp;y=2") == "https://a/?x=1&amp;y=2"
    assert safe_url('https://a/?q="') == "https://a/?q=&quot;"


# ============================================================ K: cookie


def test_K01_default_format():
    assert str(Cookie("_nxt", "abc", max_age=3600)) == "_nxt=abc; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Lax"


def test_K02_delete():
    assert (
        str(Cookie.delete("_nxt"))
        == "_nxt=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax"
    )


def test_K03_flags_off():
    c = Cookie("sid", "v", secure=False, http_only=False, same_site="Strict", domain="example.com")
    assert str(c) == "sid=v; Path=/; Domain=example.com; SameSite=Strict"
    assert c.to_header() == str(c)


def test_K04_expires_naive_and_aware():
    want = "Expires=Wed, 21 Oct 2026 12:00:00 GMT"
    assert want in str(Cookie("k", "v", expires=datetime(2026, 10, 21, 12, 0, 0)))
    jst = timezone(timedelta(hours=9))
    assert want in str(Cookie("k", "v", expires=datetime(2026, 10, 21, 21, 0, 0, tzinfo=jst)))


def test_K05_negative_max_age_is_zero():
    assert "Max-Age=0" in str(Cookie("k", "v", max_age=-5))


def test_K06_samesite_none_requires_secure():
    with pytest.raises(CookieInvalidAttributeError) as ei:
        Cookie("k", "v", same_site="None", secure=False)
    assert ei.value.code == "C02"
    assert str(Cookie("k", "v", same_site="None")).endswith("; Secure; HttpOnly; SameSite=None")


@pytest.mark.parametrize("ss", ["lax", "none", "strict"])
def test_K07_samesite_case_sensitive(ss):
    with pytest.raises(CookieInvalidAttributeError):
        Cookie("k", "v", same_site=ss)


def test_K08_attribute_injection_in_value():
    with pytest.raises(CookieInvalidValueError) as ei:
        Cookie("k", "v; Path=/evil")
    assert ei.value.code == "C01"


@pytest.mark.parametrize("v", ["a b", 'a"b', "a,b", "a\\b", "ä", "abc\r\n"])
def test_K09_bad_values(v):
    with pytest.raises(CookieInvalidValueError):
        Cookie("k", v)


def test_K09_good_values():
    for v in ["a=b", "", secrets.token_urlsafe(24)]:
        assert str(Cookie("k", v)).startswith(f"k={v}")


@pytest.mark.parametrize("n", ["my cookie", "a=b", "", "x\r\ny"])
def test_K10_bad_names(n):
    with pytest.raises(CookieInvalidValueError):
        Cookie(n, "v")


@pytest.mark.parametrize("p", ["/\r\nSet-Cookie: evil=1", "relative"])
def test_K11_bad_path(p):
    with pytest.raises(CookieInvalidAttributeError):
        Cookie("k", "v", path=p)


def test_K12_bad_domain():
    with pytest.raises(CookieInvalidAttributeError):
        Cookie("k", "v", domain="evil.com; Path=/")


@pytest.mark.parametrize("kw", [{"Path": "/"}, {"MaxAge": 0}, {"Max_Age": 1}, {"SameSite": "Lax"}])
def test_K13_legacy_kwargs_removed(kw):
    with pytest.raises(TypeError):
        Cookie("k", "v", **kw)


def test_K14_no_set_method():
    assert not hasattr(Cookie("k", "v"), "set")


def test_K15_response_cookie():
    want = ("Set-Cookie", "k=v; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert want in Response("x", cookie=Cookie("k", "v")).headers
    assert want in Response("x", cookie=str(Cookie("k", "v"))).headers


def test_K16_cookie_response():
    r = Cookie("k", "v").response("body")
    assert isinstance(r, Response) and r.status_code == 200
    assert len([h for h in r.headers if h[0] == "Set-Cookie"]) == 1


# ============================================================ H / R


def test_H01_json_response_header_list_exact():
    h = JsonResponse({"a": "<b>"}, headers=[("X-A", "1")]).headers
    assert h == [("Content-Type", "application/json; charset=utf-8")] + SEC_HEADERS + [("X-A", "1"), ("Content-Length", "12")]


def test_H02_html_response_headers():
    h = HtmlResponse("<p>", headers=[("X-A", "1")]).headers
    assert ("Content-Type", "text/html; charset=utf-8") in h
    assert ("X-A", "1") in h and ("Content-Length", "3") in h


def test_H03_security_headers_default():
    h = Response(b"x").headers
    for pair in SEC_HEADERS:
        assert pair in h
    assert not any(k.lower() == "strict-transport-security" for k, _ in h)


def test_H04_caller_overrides_security_header():
    h = Response(b"x", headers=[("X-Frame-Options", "SAMEORIGIN")]).headers
    xfo = [v for k, v in h if k.lower() == "x-frame-options"]
    assert xfo == ["SAMEORIGIN"]


def test_H05_content_type_override_case_insensitive():
    h = Response(b"x", headers=[("content-type", "text/csv")]).headers
    assert [x for x in h if x[0].lower() == "content-type"] == [("content-type", "text/csv")]


def test_H06_security_headers_off():
    h = Response(b"x", security_headers=False).headers
    names = {k.lower() for k, _ in h}
    for k, _ in SEC_HEADERS:
        assert k.lower() not in names
    assert "content-type" in names and "content-length" in names


def test_H07_process_wide_dict_pop(monkeypatch):
    d = dict(Response.security_headers)
    d.pop("Content-Security-Policy")
    monkeypatch.setattr(Response, "security_headers", d)
    assert not any(k == "Content-Security-Policy" for k, _ in Response(b"x").headers)


def test_H07_subclass_override_only_affects_subclass():
    class Sub(Response):
        security_headers = {"X-Custom": "1"}

    assert ("X-Custom", "1") in Sub(b"x").headers
    assert ("X-Custom", "1") not in Response(b"x").headers


def test_H08_crlf_value_rejected():
    with pytest.raises(ResponseHeaderInvalidError) as ei:
        Response(b"x", headers=[("X-A", "a\r\nb")])
    assert ei.value.code == "RS01"
    assert "a\r\nb" not in str(ei.value)


@pytest.mark.parametrize("name", ["Bad Name", "X:A"])
def test_H09_bad_header_names(name):
    with pytest.raises(ResponseHeaderInvalidError):
        Response(b"x", headers=[(name, "v")])


def test_H10_append_header_validated():
    r = Response(b"x")
    with pytest.raises(ResponseHeaderInvalidError):
        r.append_header("X-A", "v\n")
    r.append_header("X-A", "a\tb")
    assert ("X-A", "a\tb") in r.headers


def test_H11_non_latin1_rejected():
    with pytest.raises(ResponseHeaderInvalidError):
        Response(b"x", headers=[("X-A", "日本語")])


def test_H12_duplicate_set_cookie_kept():
    h = Response(b"x", headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]).headers
    assert [v for k, v in h if k == "Set-Cookie"] == ["a=1", "b=2"]


def test_H13_existing_response_behaviour():
    res = Response("hello")
    assert res.status_code == 200 and ("Content-Length", "5") in res.headers
    assert Redirect("/next").status_code == 302


def test_R01_redirect_local():
    r = Redirect("/next")
    assert r.status_code == 302 and ("Location", "/next") in r.headers
    for pair in SEC_HEADERS:
        assert pair in r.headers


@pytest.mark.parametrize("loc", ["//evil.example", "/\\evil.example", "\\\\evil.example", "///evil", "https://x", "http:evil", "javascript:alert(1)"])
def test_R02_external_rejected(loc):
    with pytest.raises(ResponseRedirectExternalError) as ei:
        Redirect(loc)
    assert ei.value.code == "RS02"


def test_R03_allow_external():
    r = Redirect("https://apps.example", allow_external=True)
    assert r.status_code == 302 and ("Location", "https://apps.example") in r.headers


def test_R04_crlf_location():
    with pytest.raises(ResponseHeaderInvalidError):
        Redirect("/x\r\nSet-Cookie: a=b")


def test_R05_status():
    assert Redirect("/x", status=308).status_code == 308
    with pytest.raises(ValueError):
        Redirect("/x", status=200)


@pytest.mark.parametrize("loc", ["next", "?a=1", "/x?u=https://ok"])
def test_R06_local_ok(loc):
    assert ("Location", loc) in Redirect(loc).headers


# ============================================================ Q: request


def _mp(parts: list[tuple[str, bytes, str | None, str | None]], boundary="bnd"):
    out = b""
    for name, data, filename, ctype in parts:
        disp = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        out += f"--{boundary}\r\nContent-Disposition: {disp}\r\n".encode()
        if ctype:
            out += f"Content-Type: {ctype}\r\n".encode()
        out += b"\r\n" + data + b"\r\n"
    return out + f"--{boundary}--\r\n".encode()


def _mp_env(body: bytes, boundary="bnd", drop_cl=False):
    env = make_environ(method="POST", path="/", body=body, content_type=f"multipart/form-data; boundary={boundary}")
    if drop_cl:
        env.pop("CONTENT_LENGTH")
    return env


def _big():
    return _mp([("file", b"x" * (12 * MiB), "big.bin", "application/octet-stream")])


def test_Q01_oversize_multipart_rejected_without_reading():
    env = _mp_env(_big())
    with pytest.raises(RequestEntityTooLargeError):
        Request(env).files()
    assert env["wsgi.input"].tell() == 0


def test_Q02_oversize_without_content_length():
    env = _mp_env(_big(), drop_cl=True)
    with pytest.raises(RequestEntityTooLargeError):
        Request(env).files()
    assert env["wsgi.input"].tell() <= 10 * MiB + 1


def test_Q03_raised_limit_succeeds_with_size():
    form = Request(_mp_env(_big()), max_body_size=16 * MiB).files()
    f = form["file"]
    assert isinstance(f, File) and f.size == 12 * MiB
    assert len(f.file.read()) == 12 * MiB


def test_Q04_part_count_limit():
    mk = lambda n: _mp([(f"p{i}", b"1", None, None) for i in range(n)])
    with pytest.raises(RequestEntityTooLargeError):
        Request(_mp_env(mk(65))).files()
    assert Request(_mp_env(mk(64))).files() is not None


def test_Q05_custom_part_limit():
    body = _mp([(f"p{i}", b"1", None, None) for i in range(3)])
    with pytest.raises(RequestEntityTooLargeError):
        Request(_mp_env(body), max_multipart_parts=2).files()


def test_Q06_garbage_multipart():
    with pytest.raises(RequestParseError) as ei:
        Request(_mp_env(b"garbage")).files()
    assert ei.value.code == "RQ02"


def test_Q07_missing_boundary():
    env = make_environ(method="POST", path="/", body=b"x", content_type="multipart/form-data")
    with pytest.raises(RequestParseError):
        Request(env).files()


def test_Q08_Q20_file_size_and_content_type():
    body = _mp([("public_id", b"abc", None, None), ("file", b"hello", "a.txt", "text/plain")])
    form = Request(_mp_env(body)).files()
    assert form["public_id"] == "abc" and isinstance(form["public_id"], str)
    assert form["file"].size == 5
    assert form["file"].content_type == "text/plain"
    body2 = _mp([("file", b"hello", "a.txt", None)])
    assert Request(_mp_env(body2)).files()["file"].content_type == "application/octet-stream"


@pytest.mark.parametrize("cl", ["abc", "-5", "1e3"])
def test_Q09_invalid_content_length_at_construction(cl):
    env = make_environ(method="POST", path="/", body=b"abc")
    env["CONTENT_LENGTH"] = cl
    with pytest.raises(RequestParseError):
        Request(env)


def test_Q09_padded_content_length_ok():
    env = make_environ(method="POST", path="/", body=b"abc")
    env["CONTENT_LENGTH"] = " 3"
    assert Request(env).body == b"abc"


def test_Q10_declared_length_too_large():
    env = make_environ(method="POST", path="/", body=b"12345")
    env["CONTENT_LENGTH"] = str(20 * MiB)
    with pytest.raises(RequestEntityTooLargeError) as ei:
        Request(env).body
    assert ei.value.code == "RQ01"


def test_Q11_no_content_length_overflow():
    env = make_environ(method="POST", path="/", body=b"a" * (10 * MiB + 1))
    env.pop("CONTENT_LENGTH")
    with pytest.raises(RequestEntityTooLargeError):
        Request(env).body


@pytest.mark.parametrize("body", [b"{bad", b"\xff"])
def test_Q12_bad_json(body):
    env = make_environ(method="POST", path="/", body=body, content_type="application/json")
    with pytest.raises(RequestParseError):
        Request(env).json()


def test_Q13_json_none_cases():
    env = make_environ(method="POST", path="/", body=b'{"a":1}', content_type="text/plain")
    assert Request(env).json() is None
    env = make_environ(method="POST", path="/", body=b"", content_type="application/json")
    assert Request(env).json() is None


def test_Q14_form_field_limit():
    body = "&".join(["a=1"] * 1001).encode()
    env = make_environ(method="POST", path="/", body=body, content_type="application/x-www-form-urlencoded")
    with pytest.raises(RequestParseError):
        Request(env).form()
    ok = make_environ(method="POST", path="/", body=b"a=1&b=2&b=3", content_type="application/x-www-form-urlencoded")
    assert Request(ok).form() == {"a": ["1"], "b": ["2", "3"]}


def test_Q15_cookie_bad_piece_dropped():
    req = Request(make_environ(headers={"Cookie": "a=b; bad\x7fname=1; c=d"}))
    assert req.cookie == {"a": "b", "c": "d"}


def test_Q16_cookie_bad_name_only():
    req = Request(make_environ(headers={"Cookie": "a<b=1"}))
    assert req.cookie is not None and req.cookie == {}


def test_Q17_cookie_quotes_and_first_wins():
    req = Request(make_environ(headers={"Cookie": 'k="quoted"; k=second'}))
    assert req.cookie["k"] == "quoted"


def test_Q18_no_cookie_header():
    assert Request(make_environ()).cookie is None


def test_Q19_remote_addr():
    env = make_environ()
    env.pop("REMOTE_ADDR")  # make_environ の既定は 127.0.0.1 (auth doc §9.1)
    assert Request(env).remote_addr == ""
    env["REMOTE_ADDR"] = "10.1.2.3"
    assert Request(env).remote_addr == "10.1.2.3"


# ============================================================ X: client_ip


def _xenv(xff=None, remote="127.0.0.1"):
    env = make_environ()
    env.pop("REMOTE_ADDR", None)
    if remote is not None:
        env["REMOTE_ADDR"] = remote
    if xff is not None:
        env["HTTP_X_FORWARDED_FOR"] = xff
    return env


@pytest.mark.parametrize(
    "n,want",
    [(0, "127.0.0.1"), (1, "203.0.113.9"), (2, "1.1.1.1"), (3, "127.0.0.1")],
    ids=["X1", "X2", "X3", "X4"],
)
def test_X1_to_X4_depth(n, want):
    assert client_ip_fn(_xenv("1.1.1.1, 203.0.113.9"), trusted_proxy_count=n) == want


def test_X05_garbage_falls_back():
    assert client_ip_fn(_xenv("FAKE LOG\nLINE"), trusted_proxy_count=1) == "127.0.0.1"


def test_X06_no_xff():
    assert client_ip_fn(_xenv(), trusted_proxy_count=1) == "127.0.0.1"


def test_X07_ipv6():
    assert client_ip_fn(_xenv("2001:db8::1"), trusted_proxy_count=1) == "2001:db8::1"


def test_X08_strip_and_empty_elements():
    assert client_ip_fn(_xenv(" 10.0.0.1 ,, 10.0.0.2 "), trusted_proxy_count=1) == "10.0.0.2"


def test_X09_no_remote_addr():
    assert client_ip_fn(_xenv(remote=None)) == "-"
    assert client_ip(_xenv(remote=None), trusted_proxy_count=0) == "-"


def test_X10_default_ignores_xff():
    req = Request(_xenv("6.6.6.6"))
    assert req.client_ip == "127.0.0.1" and req.remote_addr == "127.0.0.1"


def test_X11_spoofed_left_side_not_taken():
    assert Request(_xenv("6.6.6.6, 203.0.113.9"), trusted_proxy_count=1).client_ip == "203.0.113.9"
    assert Request(_xenv("6.6.6.6"), trusted_proxy_count=1).client_ip == "6.6.6.6"


def test_X12_garbage_and_missing():
    assert Request(_xenv("garbage"), trusted_proxy_count=1).client_ip == "127.0.0.1"
    env = make_environ()
    env.pop("REMOTE_ADDR")
    r = Request(env)
    assert r.client_ip == "-" and r.remote_addr == ""


# ============================================================ S: static


@pytest.fixture
def sroot(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "outside.txt").write_text("OUTSIDE", encoding="utf-8")
    (outside / "hosts").write_text("H", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("OUTSIDE", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")
    (root / ".env").write_text("SECRET=1", encoding="utf-8")
    (root / "up.html").write_text("<p>u</p>", encoding="utf-8")
    (root / "sub").mkdir()
    os.symlink(outside / "outside.txt", root / "sub" / "index.html")
    os.symlink(outside / "outside.txt", root / "link.txt")
    os.symlink(outside, root / "etcdir")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "x.txt").write_text("x", encoding="utf-8")
    (root / "d").mkdir()
    (root / "sub2").mkdir()
    (root / "sub2" / "index.html").write_text("<p>i</p>", encoding="utf-8")
    return root


def _get(router, path, method="GET"):
    return router.handle(Request(make_environ(method=method, path=path)))


def _static(root, **kw):
    return Router(Static("static/", str(root), "Static", **kw))


@pytest.mark.parametrize("p", ["/static/sub/", "/static/sub"])
def test_S01_symlinked_index_outside_root(sroot, p):
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot), p)


@pytest.mark.parametrize("p", ["/static/link.txt", "/static/../outside.txt", "/static/etcdir/hosts"])
def test_S02_symlink_and_traversal(sroot, p):
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot), p)


def test_S03_dotfile_blocked_and_opt_in(sroot):
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot), "/static/.env")
    res = _get(_static(sroot, allow_dotfiles=True), "/static/.env")
    assert res.status_code == 200 and res.body == b"SECRET=1"


def test_S04_dot_directory_blocked(sroot):
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot), "/static/.hidden/x.txt")


def test_S05_plain_file(sroot):
    res = _get(_static(sroot), "/static/a.txt")
    assert res.status_code == 200 and res.body == b"A"
    assert ("Content-Type", "text/plain; charset=utf-8") in res.headers
    assert ("X-Content-Type-Options", "nosniff") in res.headers


def test_S06_html_mime(sroot):
    res = _get(_static(sroot), "/static/up.html")
    assert res.status_code == 200 and ("Content-Type", "text/html; charset=utf-8") in res.headers


def test_S07_directory_without_index_and_index_none(sroot):
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot), "/static/d/")
    assert _get(_static(sroot), "/static/sub2/").body == b"<p>i</p>"
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot, index_file=None), "/static/sub2/")


def test_S08_methods(sroot):
    r = _static(sroot)
    with pytest.raises(PathMethodNotAllowedError) as ei:
        _get(r, "/static/a.txt", "POST")
    assert ei.value.allow_header == "GET, HEAD, OPTIONS"
    assert _get(r, "/static/a.txt", "HEAD").status_code == 200


def test_S09_nul_and_deep_paths(sroot):
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot), "/static/a\x00.txt")
    with pytest.raises(PathNotFoundError):
        _get(_static(sroot), "/static/" + "/".join(["x"] * 12))


# ============================================================ C: CORS


def _cors_env(origin, method="GET"):
    return make_environ(method=method, path="/", headers={"Origin": origin})


def _ok(req, args):
    return Response("ok")


@pytest.mark.parametrize(
    "kw",
    [
        {},
        {"allowed_origins": ["*"]},
        {"allowed_origins": ["https://a", "*"]},
        {"allowed_origins": ["null"]},
    ],
    ids=["C1-default", "C2-star", "C2-mixed", "C2-null"],
)
def test_C01_C02_credentials_with_wildcard(kw):
    with pytest.raises(ValueError):
        CORSMiddleware(access_control_allow_credentials=True, **kw)


def test_C03_explicit_origin_with_credentials():
    cors = CORSMiddleware(allowed_origins=["https://app.example"], access_control_allow_credentials=True)
    h = dict(cors(Request(_cors_env("https://app.example")), {}, _ok).headers)
    assert h["Access-Control-Allow-Origin"] == "https://app.example"
    assert h["Access-Control-Allow-Credentials"] == "true"
    assert h["Vary"] == "Origin"


@pytest.mark.parametrize("origin", ["https://app.example.evil", "null"])
def test_C04_other_origins_get_nothing(origin):
    cors = CORSMiddleware(allowed_origins=["https://app.example"], access_control_allow_credentials=True)
    h = cors(Request(_cors_env(origin)), {}, _ok).headers
    assert not [k for k, _ in h if k.lower().startswith("access-control")]


def test_C05_null_origin_with_wildcard_returns_star():
    h = dict(CORSMiddleware()(Request(_cors_env("null")), {}, _ok).headers)
    assert h["Access-Control-Allow-Origin"] == "*"


def test_C06_null_explicit():
    h = dict(CORSMiddleware(allowed_origins=["null"])(Request(_cors_env("null")), {}, _ok).headers)
    assert h["Access-Control-Allow-Origin"] == "null"


def test_C07_existing_cors_preflight():
    env = make_environ(method="OPTIONS", path="/", headers={"Origin": "https://example.com", "Access-Control-Request-Method": "POST"})
    h = dict(CORSMiddleware()(Request(env), {}, _ok).headers)
    assert h.get("Access-Control-Allow-Origin") == "*"


def test_C08_preflight_through_router():
    calls = []

    def h(req, args):
        calls.append(1)
        return Response("x")

    r = Router(Post("submit/", h, "S"))
    r.add_middleware(CORSMiddleware(allowed_origins=["https://a"]))
    env = make_environ(
        method="OPTIONS", path="/submit/",
        headers={"Origin": "https://a", "Access-Control-Request-Method": "POST"},
    )
    res = r.handle(Request(env))
    hd = dict(res.headers)
    assert res.status_code == 204
    assert hd["Access-Control-Allow-Origin"] == "https://a"
    assert "POST" in hd["Allow"]
    assert calls == []


# ============================================================ M: methods


def _router():
    calls = []

    def h(req, args):
        calls.append(req.method)
        return Response("ok")

    return Router(Get("ping/", h, "Ping"), Post("submit/", h, "Submit")), calls


def test_M01_options_not_delivered_to_handler():
    r, calls = _router()
    res = _get(r, "/submit/", "OPTIONS")
    assert res.status_code == 204 and ("Allow", "OPTIONS, POST") in res.headers
    assert calls == []


@pytest.mark.parametrize("m", ["PUT", "DELETE", "GET"])
def test_M02_405(m):
    r, _ = _router()
    with pytest.raises(PathMethodNotAllowedError) as ei:
        _get(r, "/submit/", m)
    e = ei.value
    assert e.allowed == frozenset({"POST", "OPTIONS"})
    assert e.allow_header == "OPTIONS, POST" and e.http_status == 405


def test_M03_head_on_get():
    r, calls = _router()
    assert _get(r, "/ping/", "HEAD").status_code == 200
    assert calls == ["HEAD"]
    with pytest.raises(PathMethodNotAllowedError) as ei:
        _get(r, "/ping/", "POST")
    assert ei.value.allow_header == "GET, HEAD, OPTIONS"


def test_M03_head_on_generic_path_with_get():
    r = Router(Path("g/", lambda q, a: Response("ok"), "G", methods={"GET"}))
    assert _get(r, "/g/", "HEAD").status_code == 200


@pytest.mark.parametrize("m", ["OPTIONS", "HEAD", "PUT"])
def test_M04_methodless_path_gets_everything(m):
    seen = []
    r = Router(Path("any/", lambda q, a: (seen.append(q.method), Response("ok"))[1], "A"))
    assert _get(r, "/any/", m).status_code == 200
    assert seen == [m]


def test_M05_same_path_get_and_post():
    r = Router(
        Get("x/", lambda q, a: Response("h1"), "G"),
        Post("x/", lambda q, a: Response("h2"), "P"),
    )
    assert _get(r, "/x/").body == b"h1"
    assert _get(r, "/x/", "POST").body == b"h2"
    res = _get(r, "/x/", "OPTIONS")
    assert res.status_code == 204 and ("Allow", "GET, HEAD, OPTIONS, POST") in res.headers


def test_M06_agnostic_fallback():
    r = Router(Path("x/{a}", lambda q, a: Response("agn"), "Any"), Get("x/fixed", lambda q, a: Response("get"), "G"))
    assert _get(r, "/x/fixed", "POST").body == b"agn"


def test_M07_get_without_method_returns_path():
    r, _ = _router()
    p = r.get("/submit/")
    assert isinstance(p, Post)


def test_M08_raise_if_not_exist_flag():
    r, _ = _router()
    r.raise_if_not_exist = False
    assert r.get("/nope/", method="GET") is None
    assert r.get("/submit/", method="GET") is None


def test_M09_methods_sets():
    h = lambda q, a: Response("")
    assert Post("x/", h, "P").methods == {"POST"}
    assert Get("x/", h, "G").methods == {"GET"}


def test_M10_unknown_path_404():
    r, _ = _router()
    with pytest.raises(PathNotFoundError):
        _get(r, "/nope/")


# ============================================================ G: scaffolding / CLI / errors


def test_G01_app_config_template(tmp_path):
    cfg = (create_app(tmp_path, "banana") / "config.py").read_text(encoding="utf-8")
    assert 'ADDRESS: str = "127.0.0.1"' in cfg
    assert "MAX_BODY_SIZE: int = 10 * 1024 * 1024" in cfg
    assert "TRUSTED_PROXY_COUNT: int = 0" in cfg
    assert "__g_trusted_proxies__" not in cfg


def test_G02_wsgi_template(tmp_path):
    w = (create_app(tmp_path, "banana") / "wsgi.py").read_text(encoding="utf-8")
    for s in [
        "req.client_ip", "sanitize_log_field(", "PathMethodNotAllowedError", "RequestEntityTooLargeError",
        "max_body_size=MAX_BODY_SIZE, trusted_proxy_count=TRUSTED_PROXY_COUNT",
    ]:
        assert s in w, s
    for s in ["HTTP_X_FORWARDED_FOR", "AuthLogger", "logger.warn("]:
        assert s not in w, s


def test_G03_default_page_uses_markup(tmp_path):
    t = (create_app(tmp_path, "banana") / "pages" / "default.py").read_text(encoding="utf-8")
    assert "Markup(" in t and 'f"Hello <i>' not in t


def test_G04_build_option_default():
    assert AppBuildOptions().address == "127.0.0.1"
    assert AppBuildOptions(port=7070).address == "127.0.0.1"


def _help(capsys, argv):
    from nexom.__main__ import main

    with pytest.raises(SystemExit):
        main(argv)
    return " ".join(capsys.readouterr().out.split())


@pytest.mark.parametrize("sub", ["start-project", "create-app", "create-auth", "create-config"])
def test_G05_help_default_address(capsys, sub):
    out = _help(capsys, [sub, "--help"])
    assert "default: 127.0.0.1" in out
    assert "default: 0.0.0.0" not in out


def test_G06_path_method_not_allowed_error():
    e = PathMethodNotAllowedError("/x", {"POST", "OPTIONS"})
    assert e.allowed == frozenset({"POST", "OPTIONS"})
    assert e.allow_header == "OPTIONS, POST"
    assert str(e) == "P05 -> Method is not allowed for this path. '/x'"
    assert e.http_status == 405
    assert PathMethodNotAllowedError("/x", {"POST"}).allow_header == "POST"


def test_G07_codes_and_statuses():
    assert RequestEntityTooLargeError().code == "RQ01" and RequestEntityTooLargeError().http_status == 413
    assert RequestParseError("x").code == "RQ02" and RequestParseError("x").http_status == 400
    assert PathNotFoundError("/").http_status == 404
    assert NexomError("X", "y").http_status == 500


def test_G08_more_codes():
    assert ResponseHeaderInvalidError("X-A").code == "RS01"
    assert ResponseRedirectExternalError("//e").code == "RS02"
    assert CookieInvalidAttributeError("path", "d").code == "C02"


def test_G09_existing_core_tests_untouched_marker():
    # G9 is satisfied by the existing test_core.py running green in the same session.
    assert FsPath(__file__).with_name("test_core.py").exists()


def test_G10_public_exports():
    import nexom.app as app

    for n in ["Markup", "escape", "safe_url", "json_script", "CORSMiddleware", "client_ip", "File"]:
        assert hasattr(app, n)
        assert n in app.__all__


def test_G11_trusted_proxy_derivation_create_app(tmp_path):
    (tmp_path / "gateway").mkdir()
    cfg = (create_app(tmp_path, "b", gateway_config="nginx") / "config.py").read_text(encoding="utf-8")
    assert "TRUSTED_PROXY_COUNT: int = 1" in cfg
    cfg2 = (
        create_app(tmp_path, "c", options=AppBuildOptions(trusted_proxy_count=2), gateway_config="nginx") / "config.py"
    ).read_text(encoding="utf-8")
    assert "TRUSTED_PROXY_COUNT: int = 2" in cfg2
    with pytest.raises(ValueError):
        create_app(tmp_path, "e", options=AppBuildOptions(trusted_proxy_count=-1))


def test_G12_start_project_proxy_count(tmp_path):
    t1 = tmp_path / "p1"
    t2 = tmp_path / "p2"
    t1.mkdir()
    t2.mkdir()
    start_project(project_root=t1, gateway="nginx")
    assert "TRUSTED_PROXY_COUNT: int = 1" in (t1 / "app" / "config.py").read_text(encoding="utf-8")
    assert "__g_trusted_proxies__" not in (t1 / "auth" / "config.py").read_text(encoding="utf-8")
    assert (t1 / "gateway" / "app.nginx.conf").exists()
    start_project(project_root=t2, gateway="none")
    assert "TRUSTED_PROXY_COUNT: int = 0" in (t2 / "app" / "config.py").read_text(encoding="utf-8")
    assert "__g_trusted_proxies__" not in (t2 / "auth" / "config.py").read_text(encoding="utf-8")


def test_G13_cli_trusted_proxy_flags(tmp_path, capsys):
    from nexom.__main__ import main

    main(["create-app", "d", "--out", str(tmp_path), "--trusted-proxy-count", "3"])
    assert "TRUSTED_PROXY_COUNT: int = 3" in (tmp_path / "d" / "config.py").read_text(encoding="utf-8")
    t3 = tmp_path / "t3"
    t3.mkdir()
    main(["start-project", "--root", str(t3), "--gateway", "apache"])
    assert "TRUSTED_PROXY_COUNT: int = 1" in (t3 / "app" / "config.py").read_text(encoding="utf-8")
    capsys.readouterr()
    out = _help(capsys, ["start-project", "--help"])
    assert "--trusted-proxy-count" in out and "--auth-trusted-proxy-count" in out


def test_G14_prog_name(capsys):
    from nexom.__main__ import main

    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert out.startswith("usage: nexom") and "naxom" not in out


# ============================================================ negative controls (old behaviour modelled by input)


def test_NC_autoescape_default_differs_from_legacy():
    payload = "</h2><script>alert(1)</script>"
    legacy = _eng("<h2>{{ v }}</h2>", autoescape=False).render("t", v=payload)
    safe = _eng("<h2>{{ v }}</h2>").render("t", v=payload)
    assert "<script>" in legacy          # old behaviour: payload passes through
    assert "<script>" not in safe        # new default: neutralised
    assert legacy != safe


def test_NC_static_fixture_really_escapes_root(sroot):
    # The 1.1.41 check only inspected the pre-index target. Prove that check would have passed.
    root = sroot.resolve()
    pre = (root / "sub").resolve()
    assert pre == root / "sub" or pre.is_relative_to(root)           # old check: inside root -> allowed
    post = (pre / "index.html").resolve()
    assert not post.is_relative_to(root)                             # but the re-resolved target is outside
    with pytest.raises(PathNotFoundError):                            # the guard must catch it
        _get(_static(sroot), "/static/sub/")


def test_NC_cookie_naive_concat_would_inject_but_validation_rejects():
    value = "v; Path=/evil"
    naive = f"k={value}; Path=/; HttpOnly; Secure;"        # 1.1.41 style output
    assert naive.count("Path=") == 2                         # injection visible in the old shape
    with pytest.raises(CookieInvalidValueError):
        Cookie("k", value)
    assert str(Cookie("k", "v")).count("Path=") == 1

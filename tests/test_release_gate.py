"""Nexom 1.2.0 release-gate: reproduction tests for Codex findings RG01..RG11.

Each test asserts the DESIRED behaviour: RED = Codex's claim is confirmed,
GREEN = claim refuted. Do not fix implementation here.
"""
from __future__ import annotations

import gc
import hashlib
import importlib
import os
import secrets
import sqlite3
import sys
import warnings
from html.parser import HTMLParser
from pathlib import Path

import pytest

from conftest import make_environ

from nexom.app import Markup, safe_url
from nexom.app.auth import AuthDBM, AuthPolicy, AuthService
from nexom.app.parallel_storage import MultiPartUploader
from nexom.app.response import Redirect, Response
from nexom.core.error import (
    AuthInvalidCredentialsError,
    AuthInvalidFieldError,
    PsChunkSizeMismatchError,
    ResponseRedirectExternalError,
    TemplateUnsafeSlotError,
)
from nexom.core.object_html_render import HTMLDoc, ObjectHTML

MIB = 1024 * 1024


def _fast(**kw) -> AuthPolicy:
    base = dict(pbkdf2_iterations=1000, hash_busy_ratio=None, signup_ip_threshold=10_000)
    base.update(kw)
    return AuthPolicy(**base)


def _insert_legacy(db_path: str, user_id: str, pw: str) -> str:
    salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
    uid = secrets.token_urlsafe(18)
    con = sqlite3.connect(db_path)
    con.execute("INSERT INTO users(uid,user_id,public_name,password_hash,password_salt,is_active,is_master) "
                "VALUES(?,?,?,?,?,1,0)", (uid, user_id, "Legacy", h, salt))
    con.commit()
    con.close()
    return uid


# ---------------------------------------------------------------- RG01
def verifier_sessions(db: str, uid: str) -> int:
    con = sqlite3.connect(db)
    try:
        return con.execute("SELECT COUNT(*) FROM sessions WHERE uid=? AND revoked_at IS NULL", (uid,)).fetchone()[0]
    finally:
        con.close()


def test_RG01_login_rehash_does_not_clobber_concurrent_password_change(tmp_path):
    db, log = str(tmp_path / "a.db"), str(tmp_path / "a.log")
    old_pw, new_pw = "legacy-pass-9", "brand-new-pass-1"
    svc = AuthService(db, log, master_login_password="master-pass-123456", policy=_fast())
    uid = _insert_legacy(db, "legacy_bob", old_pw)
    other = AuthDBM(db, policy=_fast())  # independent connection

    orig = svc.dbm._hash_password
    fired = {"n": 0}

    def racing_hash(password):
        h = orig(password)  # login's rehash computed; UPDATE not yet executed
        if not fired["n"]:
            fired["n"] += 1
            other.update_password(uid=uid, current_password=old_pw, new_password=new_pw, client_ip="127.0.0.1")
        return h

    svc.dbm._hash_password = racing_hash
    # Round 3 (RG01 residual): the stale verification must not issue a session either.
    # The credentials are re-read inside the session-issuing transaction -> A03.
    with pytest.raises(AuthInvalidCredentialsError):
        svc.dbm.login("legacy_bob", old_pw, client_ip="127.0.0.1", user_agent=None, ttl_sec=60)
    assert fired["n"] == 1, "race hook did not fire (login did not rehash)"
    assert verifier_sessions(db, uid) == 0, "session issued from a stale verification"

    verifier = AuthDBM(db, policy=_fast())
    row = verifier.execute("SELECT password_hash,password_salt FROM users WHERE uid=?", uid)[0]
    new_ok, _ = verifier._verify_password(new_pw, row[0], row[1])
    old_ok, _ = verifier._verify_password(old_pw, row[0], row[1])
    assert new_ok and not old_ok, f"old password resurrected: new_ok={new_ok} old_ok={old_ok}"


# ---------------------------------------------------------------- RG02
class _Attrs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_RG02_markup_into_prefixed_attribute_slot_cannot_inject_attribute():
    inner = ObjectHTML(HTMLDoc("inner", '<span data-x="{{x}}">ok</span>'))
    payload = inner.inner(x=" onmouseover=alert(1) ")
    outer = ObjectHTML(HTMLDoc("outer", '<div title="prefix {{x}}">z</div>'))
    out = outer.outer(x=payload)
    p = _Attrs()
    p.feed(str(out))
    div_attrs = next(a for t, a in p.tags if t == "div")
    assert "onmouseover" not in div_attrs, f"injected attribute on div: {div_attrs} / {out}"


# ---------------------------------------------------------------- RG03
@pytest.mark.parametrize("html", [
    '<p ONCLICK="{{x}}">a</p>',
    '<p onclick="if (\'x\') {{x}}">a</p>',
], ids=["uppercase", "mixed-quotes-in-value"])
def test_RG03_load_time_unsafe_slot_check_not_bypassable(html):
    with pytest.raises(TemplateUnsafeSlotError):
        ObjectHTML(HTMLDoc("t", html))


# ---------------------------------------------------------------- RG04
@pytest.mark.parametrize("loc", [" /\\evil.example", "\t/\\evil.example"], ids=["space", "tab"])
def test_RG04_redirect_leading_whitespace_backslash_rejected(loc):
    with pytest.raises(ResponseRedirectExternalError):
        Redirect(loc)


# ---------------------------------------------------------------- RG05
def test_RG05_content_type_crlf_rejected():
    try:
        r = Response("x", content_type="text/plain\r\nX-Evil: 1")
    except Exception:
        return
    bad = [h for h in r.headers if "\r" in h[1] or "\n" in h[1]]
    assert not bad, f"CRLF header generated: {bad}"


# ---------------------------------------------------------------- RG06
def test_RG06_max_active_uploads_not_exceeded_by_concurrent_register(tmp_path):
    kw = dict(min_chunk_size=1)
    mk = lambda: MultiPartUploader(str(tmp_path / "ps.db"), str(tmp_path / "w"), str(tmp_path / "c"), **kw)
    a, b = mk(), mk()
    sha = hashlib.sha256(b"x").hexdigest()
    for i in range(7):
        a.register(f"f{i}.bin", 10, "P", 1, sha)
    assert a._PSDBM.count_active("P") == 7

    orig = a._PSDBM.count_active
    fired = {"n": 0}

    def racing_count(pid):
        n = orig(pid)  # A sees 7
        if not fired["n"]:
            fired["n"] += 1
            b.register("race.bin", 10, "P", 1, sha)  # B sees 7 too and registers -> 8
        return n

    a._PSDBM.count_active = racing_count
    try:
        a.register("late.bin", 10, "P", 1, sha)
    except Exception:
        pass
    total = b._PSDBM.count_active("P")
    assert total <= a.max_active_uploads_per_pid, f"active={total} > max={a.max_active_uploads_per_pid}"


# ---------------------------------------------------------------- RG07
def test_RG07_safe_url_in_href_slot_escaped_once():
    eng = ObjectHTML(HTMLDoc("t", '<a href="{{u}}">l</a>'))
    out = str(eng.t(u=safe_url("/?a=1&b=2")))
    assert 'href="/?a=1&amp;b=2"' in out, out


# ---------------------------------------------------------------- RG08
def test_RG08_generated_auth_wsgi_bad_content_length(tmp_path):
    from nexom.buildTools.build import create_auth

    create_auth(tmp_path)
    sys.path.insert(0, str(tmp_path))
    for m in [m for m in sys.modules if m == "auth" or m.startswith("auth.")]:
        del sys.modules[m]
    try:
        wsgi = importlib.import_module("auth.wsgi")
        got = {}

        def sr(status, headers, exc=None):
            got["status"] = status

        def call(remote):
            env = make_environ(method="POST", path="/login", body=b"{}", content_type="application/json")
            env["CONTENT_LENGTH"] = "abc"
            env["REMOTE_ADDR"] = remote
            body = b"".join(wsgi.app(env, sr))
            return got["status"], body

        st, body = call("127.0.0.1")
        assert st.startswith("400"), (st, body)
        st, body = call("203.0.113.9")
        assert st.startswith("403"), ("non-allowed client must get 403 before parse", st, body)
    finally:
        sys.path.remove(str(tmp_path))
        for m in [m for m in sys.modules if m == "auth" or m.startswith("auth.")]:
            del sys.modules[m]


# ---------------------------------------------------------------- RG09
def test_RG09_authservice_init_failure_closes_sqlite_connection(tmp_path, monkeypatch):
    import nexom.app.db as dbmod

    conns = []
    real_connect = dbmod.connect

    def spy(*a, **k):
        c = real_connect(*a, **k)
        conns.append(c)
        return c

    monkeypatch.setattr(dbmod, "connect", spy)
    with pytest.raises(Exception):
        AuthService(str(tmp_path / "a.db"), str(tmp_path / "a.log"), master_login_password="", policy=_fast())
    assert conns, "no connection observed"
    still_open = []
    for c in conns:
        try:
            c.execute("SELECT 1")
            still_open.append(c)
        except sqlite3.ProgrammingError:
            pass
    assert not still_open, f"{len(still_open)} sqlite connection(s) left open after failed init"


def test_RG09b_authservice_init_failure_no_resourcewarning(tmp_path):
    gc.collect()  # flush leaks from other tests so only this init is measured
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        with pytest.raises(Exception):
            AuthService(str(tmp_path / "a.db"), str(tmp_path / "a.log"), master_login_password="", policy=_fast())
        gc.collect()
    rw = [x for x in w if issubclass(x.category, ResourceWarning)]
    assert not rw, [str(x.message) for x in rw]


# ---------------------------------------------------------------- RG10
def test_RG10_legacy_chunk_split_4MiB_in_2_accepts_3MiB_first_chunk(tmp_path):
    up = MultiPartUploader(str(tmp_path / "ps.db"), str(tmp_path / "w"), str(tmp_path / "c"), min_chunk_size=1)
    pub = up.register("f.bin", 4 * MIB, "P", 2, hashlib.sha256(b"x").hexdigest())
    blob = b"a" * (3 * MIB)
    # Design: equal split (2 MiB) + remainder; legacy 3 MiB first chunk is rejected.
    with pytest.raises(PsChunkSizeMismatchError):
        up.parts_upload("P", pub, 0, blob, hashlib.sha256(blob).hexdigest())


# ---------------------------------------------------------------- RG11
def test_RG11a_legacy_user_id_over_256_can_still_login(tmp_path):
    db, log = str(tmp_path / "a.db"), str(tmp_path / "a.log")
    svc = AuthService(db, log, master_login_password="master-pass-123456", policy=_fast())
    uid_str = "u" * 300
    _insert_legacy(db, uid_str, "legacy-pass-9")
    s = svc.dbm.login(uid_str, "legacy-pass-9", client_ip="127.0.0.1", user_agent=None, ttl_sec=60)
    assert s.token


def test_RG11b_legacy_password_over_256_bytes_can_still_login(tmp_path):
    db, log = str(tmp_path / "a.db"), str(tmp_path / "a.log")
    svc = AuthService(db, log, master_login_password="master-pass-123456", policy=_fast())
    pw = "p" * 300
    _insert_legacy(db, "legacy_long", pw)
    s = svc.dbm.login("legacy_long", pw, client_ip="127.0.0.1", user_agent=None, ttl_sec=60)
    assert s.token


# =====================================================================================
# Rounds 2-3 regression additions (written from the design docs only; IDs in test names)
# =====================================================================================
import json
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import nexom.app as _nexom_app
import nexom.app.template as _nexom_template
from nexom.app.cookie import RequestCookies
from nexom.app.db import DatabaseManager
from nexom.app.path import Get, Post, Router
from nexom.app.request import Request
from nexom.app.parallel_storage import ParallelStorage
from nexom.templates.auth import AuthPages
from nexom.core.error import (
    PathMethodNotAllowedError,
    PathNotFoundError,
    PsArgmentsError,
    PsDataCorruotedError,
    PsPermissionError,
    PsTooManyActiveUploadsError,
)

from test_auth_hardening import Env as _AuthEnv, fast as _afast, PW as _PW


def _t(html: str, **kw) -> ObjectHTML:
    return ObjectHTML(HTMLDoc("t", html), **kw)


def _tag_attrs(html: str, tag: str) -> dict:
    p = _Attrs()
    p.feed(html)
    return next(a for t, a in p.tags if t == tag)


# ---------------------------------------------------------------- E27b (tokenizer: attr-value position)
def test_RG_E27b_prefixed_attr_value_is_attr_position_markup_escaped():
    x = Markup('y" onmouseover="alert(1)')
    out = str(_t('<div title="prefix {{ x }}">z</div>').t(x=x))
    assert out == '<div title="prefix y&quot; onmouseover=&quot;alert(1)">z</div>'


def test_RG_E27b_gt_inside_quotes_does_not_close_tag():
    out = str(_t('<a title="a>b {{ v }}">x</a>').t(v=Markup("<b>")))
    assert out == '<a title="a&gt;b &lt;b&gt;">x</a>'.replace("a&gt;b", "a>b")


def test_RG_E27b_after_tag_closed_body_position_passthrough():
    out = str(_t('<a href="x">{{ v }}</a>').t(v=Markup("<b>")))
    assert out == '<a href="x"><b></a>'


# negative control: SAME value, SAME template, attribute slot escapes while body slot passes through
@pytest.mark.parametrize("tpl", [
    '<div title="{{ v }}">{{ v }}</div>',
    '<div title="a / > {{ v }}">{{ v }}</div>',
    "<div title='a \" {{ v }}'>{{ v }}</div>",
    '<!-- <a title=" --><div title="{{ v }}">{{ v }}</div>',
    '<script>var a="<b>";</script><div title="{{ v }}">{{ v }}</div>',
    '<script src="{{ v }}"></script><div>{{ v }}</div>',
    '<style>p{}</style  ><div title="{{ v }}">{{ v }}</div>',
])
def test_RG_E27b_E31_negative_control_attr_escapes_body_passes(tpl):
    out = str(_t(tpl).t(v=Markup('<i>"q"</i>')))
    assert "&lt;i&gt;&quot;q&quot;&lt;/i&gt;" in out, out      # attribute position: escaped
    body = out.rsplit("</", 1)[0] if tpl.endswith("</div>") else out
    assert '<i>"q"</i>' in out, out                              # body position: raw Markup survives
    # and the raw form must appear exactly once (the body one), never inside the attribute
    assert out.count('<i>"q"</i>') == 1, out


# ---------------------------------------------------------------- E27c (_AttrSafe)
def test_RG_E27c_safe_url_in_href_single_escape_and_markup_still_escaped():
    t = _t('<a href="{{ u }}">')
    assert str(t.t(u=safe_url("/?a=1&b=2"))) == '<a href="/?a=1&amp;b=2">'
    assert str(t.t(u=Markup("/?a=1&b=2"))) == '<a href="/?a=1&amp;b=2">'
    out = str(t.t(u=Markup('x" onclick="a')))
    assert "&quot;" in out and 'onclick="a' not in out


def test_RG_E27c_attrsafe_type_is_private_but_markup():
    u = safe_url("/x")
    assert isinstance(u, Markup)
    assert type(u).__name__ == "_AttrSafe"
    assert "_AttrSafe" not in getattr(_nexom_app, "__all__", [])
    assert not hasattr(_nexom_app, "AttrSafe")
    assert not hasattr(_nexom_app, "_AttrSafe")
    assert not hasattr(_nexom_template, "_AttrSafe")
    assert not hasattr(_nexom_template, "AttrSafe")
    # plain Markup / str / render output / + / join / format never become _AttrSafe
    for v in (Markup("a"), Markup("a") + "b", Markup("").join(["a"]), Markup("{}").format("a"), str(u)):
        assert type(v).__name__ != "_AttrSafe"


# ---------------------------------------------------------------- E29 (script/style body -> OH06)
@pytest.mark.parametrize("html", [
    "<script>let x={{ x }}</script>",
    "<script>var a = {{x}}</script>",
    "<SCRIPT>{{x}}</SCRIPT>",
    "<style>p{color:{{c}}}</style>",
    '<script type="text/javascript">"</script>{{ ok }}<script>"{{x}}"</script>',
    "<script>if (a < b) { x = '{{ x }}' }</script>",
])
def test_RG_E29_rawtext_slots_rejected_at_load(html):
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        ObjectHTML(HTMLDoc("t", html))
    assert ei.value.code == "OH06" and "script/style body" in str(ei.value)
    with pytest.raises(TemplateUnsafeSlotError):
        ObjectHTML(HTMLDoc("t", html), autoescape=False)


@pytest.mark.parametrize("html", [
    '<script src="{{ s }}"></script><p>{{ y }}</p>',
    "<script></script>{{x}}",
    "<style></style >{{x}}",
    '<script>var a = 1;</script  ><p>{{ y }}</p>',
])
def test_RG_E29_outside_rawtext_allowed(html):
    ObjectHTML(HTMLDoc("t", html))


# ---------------------------------------------------------------- E31 (Codex bypasses)
@pytest.mark.parametrize("tpl", [
    '<div title="a < {{ x }}">z</div>',
    '<div title="a <!-- {{ x }}">z</div>',
    '<a title="a <span {{ x }}">z</a>',
])
def test_RG_E31_lt_inside_quoted_attr_does_not_reset_state(tpl):
    x = Markup(' onmouseover="alert(1)" ')
    out = str(_t(tpl).t(x=x))
    assert "onmouseover=&quot;alert(1)&quot;" in out, out
    assert 'onmouseover="alert(1)"' not in out, out
    tag = "a" if tpl.startswith("<a") else "div"
    assert "onmouseover" not in _tag_attrs(out, tag), out


@pytest.mark.parametrize("html,reason", [
    ('<p/onclick="{{ x }}">', "onclick"),
    ('<iframe/srcdoc="{{ x }}">', "srcdoc"),
    ('<p / ONCLICK="{{ x }}">', "onclick"),
    ("<{{ t }}>", "tag/attribute name position"),
    ("<p {{ a }}>", "tag/attribute name position"),
    ("<p/{{ a }}>", "tag/attribute name position"),
    ("<!-- {{ x }} -->", "comment"),
    ("<p>a</p><!-- <b> \" {{ x }} -->", "comment"),
    ("<a title={{ x }}>", "unquoted attribute"),
    ("<a title = {{ x }}>", "unquoted attribute"),
])
def test_RG_E31_rejected_positions(html, reason):
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        ObjectHTML(HTMLDoc("t", html))
    assert ei.value.code == "OH06"
    assert reason.lower() in str(ei.value).lower()


# ---------------------------------------------------------------- R7..R9 (Redirect)
@pytest.mark.parametrize("loc", [" /\\evil.example", "\t/next", "", " /next"])
@pytest.mark.parametrize("ext", [False, True])
def test_RG_R7_leading_space_tab_or_empty_rejected_rs02_even_if_external_allowed(loc, ext):
    with pytest.raises(ResponseRedirectExternalError):
        Redirect(loc, allow_external=ext)


def test_RG_R7_leading_space_external_rejected_with_allow_external():
    with pytest.raises(ResponseRedirectExternalError):
        Redirect(" https://x", allow_external=True)


@pytest.mark.parametrize("loc,ext", [
    ("/\t\\evil.example", False),
    ("https://ok.example/\tx", True),
])
def test_RG_R9_tab_anywhere_rejected_with_rs02(loc, ext):
    with pytest.raises(ResponseRedirectExternalError) as ei:
        Redirect(loc, allow_external=ext)
    assert ei.value.code == "RS02"


# R10: header-illegal characters (CR / LF / NUL / DEL) -> RS01 (header validation runs first), with or without allow_external
@pytest.mark.parametrize("ext", [False, True])
@pytest.mark.parametrize("loc", ["/ne\x7fxt", "/a\nb", "/a\x00b", "/x\r\nSet-Cookie: a=b", "https://ok.example/\x7f"])
def test_RG_R10_header_illegal_chars_rs01(loc, ext):
    from nexom.core.error import ResponseHeaderInvalidError

    with pytest.raises(ResponseHeaderInvalidError) as ei:
        Redirect(loc, allow_external=ext)
    assert ei.value.code == "RS01"


def test_RG_R8_inner_space_allowed():
    r = Redirect("/a b")
    assert r.status_code == 302 and ("Location", "/a b") in r.headers


# ---------------------------------------------------------------- M8 / M11 (Router.get None contract)
def _mk_router():
    calls = []

    def h(req, args):
        calls.append(req.method)
        return Response("ok")

    return Router(Get("ping/", h, "Ping"), Post("submit/", h, "Submit")), calls


def _req(method, path, **kw):
    return Request(make_environ(method=method, path=path, **kw))


def test_RG_M8_default_flag_raises_404_and_405():
    r, _ = _mk_router()
    with pytest.raises(PathNotFoundError):
        r.get("/nope/", method="GET")
    with pytest.raises(PathMethodNotAllowedError):
        r.get("/submit/", method="GET")


def test_RG_M8_flag_false_returns_none_for_both_404_and_405():
    r, _ = _mk_router()
    r.raise_if_not_exist = False
    assert r.get("/nope/", method="GET") is None
    assert r.get("/submit/", method="GET") is None
    assert r.get("/submit/", method="PUT") is None
    # a satisfiable lookup still returns the Path, with and without method
    assert isinstance(r.get("/submit/", method="POST"), Post)
    assert isinstance(r.get("/submit/"), Post)
    assert isinstance(r.get("/ping/", method="HEAD"), Get)


def test_RG_M11_handle_ignores_flag():
    r, calls = _mk_router()
    r.raise_if_not_exist = False
    with pytest.raises(PathMethodNotAllowedError) as ei:
        r.handle(_req("GET", "/submit/"))
    assert ei.value.http_status == 405
    res = r.handle(_req("OPTIONS", "/submit/"))
    assert res.status_code == 204 and ("Allow", "OPTIONS, POST") in res.headers
    with pytest.raises(PathNotFoundError):
        r.handle(_req("GET", "/nope/"))
    assert calls == []


# ---------------------------------------------------------------- Q21 (RequestCookies)
def test_RG_Q21_cookie_named_self_is_parsed_and_typed():
    req = Request(make_environ(headers={"Cookie": "self=1; a=b"}))
    assert isinstance(req.cookie, RequestCookies)
    assert req.cookie == {"self": "1", "a": "b"}
    assert req.cookie.get("self") == "1"
    assert req.cookie.get("missing") is None


def test_RG_Q21_requestcookies_constructor_contract():
    assert RequestCookies({"a": "b"}) == {"a": "b"}
    assert RequestCookies() == {}
    with pytest.raises(TypeError):
        RequestCookies(a="b")


@pytest.mark.parametrize("name", ["default", "get", "keys", "items", "__class__"])
def test_RG_Q21_dict_method_named_cookies_do_not_break(name):
    req = Request(make_environ(headers={"Cookie": f"{name}=x; a=b"}))
    assert isinstance(req.cookie, RequestCookies)
    assert req.cookie["a"] == "b"


# ---------------------------------------------------------------- L-18b (differences over RG01)
def test_RG_L18b_interrupted_rehash_login_is_a03_no_session_old_pw_dead_new_pw_works(tmp_path):
    from nexom.app.auth import AuthDBM

    e = _AuthEnv(tmp_path)
    uid = e.insert_legacy("legacy_bob", "legacy-pass-9")
    other = AuthDBM(e.db, policy=_afast())
    orig = e.svc.dbm._hash_password
    fired = {"n": 0}

    def racing(password):
        h = orig(password)
        if not fired["n"]:
            fired["n"] += 1
            other.update_password(uid=uid, current_password="legacy-pass-9",
                                  new_password="brand-new-99", client_ip="127.0.0.1")
        return h

    e.svc.dbm._hash_password = racing
    st, d, _ = e.login("legacy_bob", "legacy-pass-9")
    e.svc.dbm._hash_password = orig
    assert fired["n"] == 1, "race hook did not fire"
    assert (st, d.get("error")) == (401, "A03"), (st, d)
    assert "token" not in (d or {})
    assert e.q("SELECT COUNT(*) FROM sessions WHERE uid=?", (uid,))[0][0] == 0
    row = e.attempt("login_user:legacy_bob")                    # doc: +1; H-1 reset by the interleaved update may erase it
    assert row is None or row[0] == 1
    st, d, _ = e.login("legacy_bob", "legacy-pass-9")
    assert (st, d.get("error")) == (401, "A03")
    st, d, _ = e.login("legacy_bob", "brand-new-99")
    assert st == 200 and d["token"]


# ---------------------------------------------------------------- L-5 (cap follows policy)
def test_RG_L5_password_max_bytes_2048_signup_and_login_agree(tmp_path):
    e = _AuthEnv(tmp_path, policy=_afast(password_max_bytes=2048))
    for i, n in enumerate((1025, 2048)):
        pw = "a" * n
        st, _, _ = e.signup(f"longpw{i}", pw)
        assert st == 201, n
        st, d, _ = e.login(f"longpw{i}", pw)
        assert st == 200 and d["token"], n
    st, d, _ = e.login("longpw0", "a" * 2049)
    assert (st, d["error"], d.get("field")) == (400, "A12", "password")
    st, d, _ = e.signup("longpw9", "a" * 2049)
    assert (st, d["error"], d.get("field")) == (400, "A12", "password")


def test_RG_L5_default_policy_login_cap_is_1024_even_though_signup_cap_is_lower(tmp_path):
    e = _AuthEnv(tmp_path)
    st, d, _ = e.login("nobody", "a" * 1025)
    assert (st, d["error"], d.get("field")) == (400, "A12", "password")
    st, d, _ = e.login("nobody", "a" * 1024)
    assert (st, d["error"]) == (401, "A03")


# ---------------------------------------------------------------- K-5b / K-6b (form logout never shows JSON)
class _Count:
    def __init__(self, status=200, body=b'{"ok": true}'):
        self.n = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                outer.n += 1
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _hdr(res, name):
    return [v for k, v in res.headers if k.lower() == name.lower()]


def _logout(pages, *, form, cookie):
    h = {"Cookie": f"_nxt={'a' * 43}"} if cookie else None
    ct = "application/x-www-form-urlencoded" if form else "application/json"
    raw = b"" if form else b"{}"
    return pages.call_handler(Request(make_environ(method="POST", path="/user/logout/", body=raw,
                                                   content_type=ct, headers=h)), {})


def test_RG_K5b_form_logout_without_cookie_redirects_no_backend_call():
    srv = _Count()
    try:
        pages = AuthPages("user/", srv.url, client_ip=lambda r: "203.0.113.7")
        res = _logout(pages, form=True, cookie=False)
        assert res.status_code == 302
        assert _hdr(res, "Location") == ["/"]
        assert _hdr(res, "Set-Cookie")[0].startswith("_nxt=; Max-Age=0")
        assert b'"ok"' not in res.body
        assert srv.n == 0
        # json variant stays JSON (K-5), proving the branch is on Content-Type
        res = _logout(pages, form=False, cookie=False)
        assert res.status_code == 200 and json.loads(res.body.decode()) == {"ok": True}
        assert srv.n == 0
    finally:
        srv.close()


@pytest.mark.parametrize("backend", ["down", "bad_gateway"])
def test_RG_K6b_form_logout_backend_failure_still_redirects_and_clears_cookie(backend):
    srv = None
    if backend == "down":
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{s.getsockname()[1]}"
        s.close()
    else:
        srv = _Count(status=502, body=b"<html>bad gateway</html>")
        url = srv.url
    try:
        pages = AuthPages("user/", url, client_ip=lambda r: "203.0.113.7")
        res = _logout(pages, form=True, cookie=True)
        assert res.status_code == 302
        assert _hdr(res, "Location") == ["/"]
        assert _hdr(res, "Set-Cookie")[0].startswith("_nxt=; Max-Age=0")
        assert b"A09" not in res.body and b'"error"' not in res.body
        res = _logout(pages, form=False, cookie=True)               # K-6 unchanged for JSON
        assert res.status_code == 503 and json.loads(res.body.decode()) == {"ok": False, "error": "A09"}
        assert _hdr(res, "Set-Cookie")[0].startswith("_nxt=; Max-Age=0")
    finally:
        if srv:
            srv.close()


# ---------------------------------------------------------------- §6.3 / §6.4 data-page-path
@pytest.mark.parametrize("page", ["login", "signup"])
def test_RG_6_4_auth_pages_use_data_page_path_and_no_slot_in_script(page):
    pages = AuthPages("user/", "http://127.0.0.1:1", client_ip=lambda r: "203.0.113.7")
    res = pages.call_handler(Request(make_environ(method="GET", path=f"/user/{page}/")), {})
    assert res.status_code == 200
    html = res.body.decode()
    assert re.search(rf'<body[^>]*data-page-path="/?user/{page}/"', html), re.findall(r"<body[^>]*>", html)
    assert "{{" not in html
    assert 'const PAGE_PATH = "/{{' not in html
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script\s*>", html, flags=re.S | re.I)
    assert scripts and all("{{" not in s for s in scripts)
    assert "dataset.pagePath" in html
    assert "PAGE_PATH" in html


# ---------------------------------------------------------------- storage: E-2a / E-8a / E-8b / A-5a / A-5b
def _rg_sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rg_up(tmp_path, **kw):
    return MultiPartUploader(str(tmp_path / "ps.db"), str(tmp_path / "w"), str(tmp_path / "c"),
                             min_chunk_size=1, **kw)


def test_RG_E2a_total_chunks_with_nonpositive_last_chunk_rejected_no_row(tmp_path):
    up = _rg_up(tmp_path)
    with pytest.raises(PsArgmentsError) as ei:
        up.register("f.bin", 5, "A", 4, _rg_sha(b"x"))
    assert "total_chunks" in str(ei.value)
    assert up._PSDBM.count_active("A") == 0
    w = tmp_path / "w"
    assert not w.exists() or list(w.iterdir()) == []
    up.register("f.bin", 5, "A", 3, _rg_sha(b"x"))     # 3 chunks of 2,2,1 is fine


def test_RG_E8b_error_uploads_do_not_count_as_active(tmp_path):
    up = _rg_up(tmp_path, max_active_uploads_per_pid=2)
    for _ in range(2):
        data = b"hello-world-012345"
        pub = up.register("f.txt", len(data), "A", 2, _rg_sha(b"different"))
        up.parts_upload("A", pub, 0, data[:9], _rg_sha(data[:9]))
        up.parts_upload("A", pub, 1, data[9:], _rg_sha(data[9:]))
        with pytest.raises(PsDataCorruotedError):
            up.commit("A", pub)
    assert up._PSDBM.count_active("A") == 0
    up.register("f.bin", 10, "A", 1, _rg_sha(b"x"))
    up.register("f.bin", 10, "A", 1, _rg_sha(b"x"))
    with pytest.raises(PsTooManyActiveUploadsError):
        up.register("f.bin", 10, "A", 1, _rg_sha(b"x"))


def test_RG_E8a_two_connections_registering_concurrently_never_exceed_limit(tmp_path):
    for rnd in range(5):
        pid = f"P{rnd}"
        seed = _rg_up(tmp_path)
        for i in range(7):
            seed.register(f"f{i}.bin", 10, pid, 1, _rg_sha(b"x"))
        assert seed._PSDBM.count_active(pid) == 7
        barrier = threading.Barrier(2, timeout=15)
        results = []

        def worker(k):
            up = _rg_up(tmp_path)               # own connection, created in this thread
            try:
                barrier.wait()
                up.register(f"r{k}.bin", 10, pid, 1, _rg_sha(b"x"))
                results.append(("ok", None))
            except PsTooManyActiveUploadsError as e:
                results.append(("full", e))
            except BaseException as e:           # noqa: BLE001
                results.append(("err", e))

        ts = [threading.Thread(target=worker, args=(k,)) for k in range(2)]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
        kinds = sorted(k for k, _ in results)
        assert kinds == ["full", "ok"], (rnd, results)
        assert "8" in str(next(e for k, e in results if k == "full"))
        assert _rg_up(tmp_path)._PSDBM.count_active(pid) == 8


def _png() -> bytes:
    from io import BytesIO
    from PIL import Image

    b = BytesIO()
    Image.new("RGB", (10, 10), (255, 0, 0)).save(b, format="PNG")
    return b.getvalue()


def _rg_committed_png_with_cache(tmp_path, pid="A"):
    up = _rg_up(tmp_path)
    ps = ParallelStorage(str(tmp_path / "ps.db"), str(tmp_path / "c"), str(tmp_path / "w"))
    data = _png()
    pub = up.register("a.png", len(data), pid, 1, _rg_sha(data))
    up.parts_upload(pid, pub, 0, data, _rg_sha(data))
    meta = up.commit(pid, pub)
    cache = ps.comp_img(pid, meta.public_id, 8, 8, 80)
    assert cache.exists()
    return up, ps, meta


def _contents(tmp_path):
    c = tmp_path / "c"
    return sorted(p.name for p in c.iterdir()) if c.exists() else []


def test_RG_A5a_force_delete_with_none_pid_removes_everything(tmp_path):
    up, ps, meta = _rg_committed_png_with_cache(tmp_path)
    assert len(_contents(tmp_path)) >= 2          # original + cached variant
    ps.delete(None, meta.public_id, force=True)
    assert not any("__PSC_" in n for n in _contents(tmp_path))
    with pytest.raises(Exception):
        ps.getMeta(None, meta.public_id)


@pytest.mark.parametrize("who", [None, "", "B"])
def test_RG_A5b_denied_delete_is_atomic_files_and_row_remain(tmp_path, who):
    up, ps, meta = _rg_committed_png_with_cache(tmp_path)
    before = _contents(tmp_path)
    assert len(before) >= 2
    with pytest.raises(PsPermissionError):
        ps.delete(who, meta.public_id)
    assert _contents(tmp_path) == before
    assert ps.getMeta(None, meta.public_id).public_id == meta.public_id
    assert ps.getMeta("A", meta.public_id).status == "COMMITTED"


@pytest.mark.parametrize("who", [None, ""])
def test_RG_A5b_denied_delete_atomic_whatever_the_error_type(tmp_path, who):
    from nexom.core.error import NexomError

    up, ps, meta = _rg_committed_png_with_cache(tmp_path)
    before = _contents(tmp_path)
    with pytest.raises(NexomError):
        ps.delete(who, meta.public_id)
    assert _contents(tmp_path) == before
    assert ps.getMeta("A", meta.public_id).status == "COMMITTED"


# ---------------------------------------------------------------- DB-1 / DB-1a / DB-4a / DB-9 / DB-9a / DB-9b
def _fmode(p) -> int:
    return os.stat(p).st_mode & 0o777


def test_RG_DB1_new_db_file_is_0600_under_umask_022(tmp_path):
    old = os.umask(0o022)
    try:
        p = tmp_path / "a.db"
        d = DatabaseManager(str(p))
        d.execute("CREATE TABLE t(x)")
        d.execute("INSERT INTO t VALUES (1)")
        assert _fmode(p) == 0o600
        for s in ("-wal", "-shm"):
            side = Path(str(p) + s)
            if side.exists():
                assert _fmode(side) == 0o600
    finally:
        os.umask(old)


def test_RG_DB1a_existing_0644_db_is_left_alone(tmp_path):
    p = tmp_path / "a.db"
    sqlite3.connect(str(p)).close()
    os.chmod(p, 0o644)
    d = DatabaseManager(str(p))
    d.execute("CREATE TABLE t(x)")
    assert _fmode(p) == 0o644


def test_RG_DB4a_init_failure_closes_connection_and_leaves_path_openable(tmp_path):
    seen = []

    class Boom(DatabaseManager):
        def __init__(self, *a, **k):
            seen.append(self)
            super().__init__(*a, **k)

        def _init(self, *a, **k):
            raise RuntimeError("boom")

    p = tmp_path / "a.db"
    with pytest.raises(RuntimeError):
        Boom(str(p))
    assert seen and seen[0]._conn is None
    other = DatabaseManager(str(p))
    other.execute("PRAGMA journal_mode")
    other.execute("CREATE TABLE t(x)")


def _ps_rows(db) -> int:
    con = sqlite3.connect(str(db))
    try:
        return con.execute("SELECT COUNT(*) FROM parallel_storage").fetchone()[0]
    finally:
        con.close()


def test_RG_DB9_register_inside_failed_outer_tx_leaves_no_row(tmp_path):
    up = _rg_up(tmp_path)
    dbm = up._PSDBM
    base = _ps_rows(tmp_path / "ps.db")
    with pytest.raises(RuntimeError):
        with dbm.immediate_transaction():
            up.register("f.bin", 10, "A", 1, _rg_sha(b"x"))
            raise RuntimeError("outer fails")
    assert _ps_rows(tmp_path / "ps.db") == base
    assert dbm.count_active("A") == 0
    up.register("f.bin", 10, "A", 1, _rg_sha(b"x"))          # connection still usable
    assert _ps_rows(tmp_path / "ps.db") == base + 1


def _xs(db):
    con = sqlite3.connect(str(db))
    try:
        return sorted(r[0] for r in con.execute("SELECT x FROM t"))
    finally:
        con.close()


def test_RG_DB9a_nested_transactions_commit_together(tmp_path):
    p = tmp_path / "a.db"
    d = DatabaseManager(str(p))
    d.execute("CREATE TABLE t(x)")
    with d.immediate_transaction():
        with d.immediate_transaction():
            d.execute("INSERT INTO t VALUES (1)")
        assert _xs(p) == []                      # not yet visible: outer still open
    assert _xs(p) == [1]


def test_RG_DB9b_inner_failure_rolls_back_only_inner_work(tmp_path):
    p = tmp_path / "a.db"
    d = DatabaseManager(str(p))
    d.execute("CREATE TABLE t(x)")
    with d.immediate_transaction():
        d.execute("INSERT INTO t VALUES (1)")
        try:
            with d.immediate_transaction():
                d.execute("INSERT INTO t VALUES (2)")
                raise ValueError("inner")
        except ValueError:
            pass
        d.execute("INSERT INTO t VALUES (3)")
    assert _xs(p) == [1, 3]


def test_RG_DB9b_outer_failure_discards_released_inner_work(tmp_path):
    p = tmp_path / "a.db"
    d = DatabaseManager(str(p))
    d.execute("CREATE TABLE t(x)")
    with pytest.raises(RuntimeError):
        with d.immediate_transaction():
            with d.immediate_transaction():
                d.execute("INSERT INTO t VALUES (1)")
            raise RuntimeError
    assert _xs(p) == []


# ================================================================ E32 / E33 / E34 (tokenizer rounds 4-5, doc-only regression)
_E_X = "<i>&"
_E_ESC = "&lt;i&gt;&amp;"

_E32_SCRIPT_BODY = [
    "<svg><foreignObject><script>//</foreignObject>{{x}}</script></foreignObject></svg>",
    "<!--><script>//-->{{x}}</script>",
    "<!---><script>//-->{{x}}</script>",
    "<svg><![cdata[><script>//]]>{{x}}</script></svg>",
    "<script><!--<script>//</script>{{x}}</script>",
    "<SCRIPT><!--<SCRIPT>//</SCRIPT>{{x}}</SCRIPT>",
    "<svg><p><script>//</svg>{{x}}</script>",
    "<svg><desc><script>{{x}}</script></desc></svg>",
    "<math><mi><script>//</mi>{{x}}</script></math>",
    "<!-- a --!><script>//-->{{x}}</script>",
    '<!x a="><script>">{{x}}</script>',
]


@pytest.mark.parametrize("html", _E32_SCRIPT_BODY)
def test_RG_E32_script_body_bypasses_rejected_at_load(html):
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        ObjectHTML(HTMLDoc("t", html))
    assert ei.value.code == "OH06" and "script/style body" in str(ei.value)


@pytest.mark.parametrize("html", [
    "<svg><script><![CDATA[//</script>{{x}}]]></script></svg>",
    "<svg><![CDATA[{{x}}]]></svg>",
])
def test_RG_E32_cdata_slots_rejected_at_load(html):
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        ObjectHTML(HTMLDoc("t", html))
    assert ei.value.code == "OH06" and "cdata" in str(ei.value).lower()


@pytest.mark.parametrize("html", [
    "<svg><foreignObject><script>//</foreignObject>{{x}}</script></foreignObject></svg>",
    "<!--><script>//-->{{x}}</script>",
    "<svg><![cdata[><script>//]]>{{x}}</script></svg>",
    "<svg><![CDATA[{{x}}]]></svg>",
    "<script><!--<script>//</script>{{x}}</script>",
    '<textarea><b a="</textarea><script>">{{x}}</script>',
    "<xmp>{{x}}</xmp>",
])
def test_RG_E32_E_R9_rejected_even_with_autoescape_false(html):
    with pytest.raises(TemplateUnsafeSlotError):
        ObjectHTML(HTMLDoc("t", html), autoescape=False)


# ---- E34 negatives
@pytest.mark.parametrize("tag", ["textarea", "title", "xmp", "iframe", "noembed", "noscript"])
def test_RG_E34_fake_attr_in_rcdata_rawtext_then_script_rejected(tag):
    html = f'<{tag}><b a="</{tag}><script>">{{{{x}}}}</script>'
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        ObjectHTML(HTMLDoc("t", html))
    assert ei.value.code == "OH06"
    msg = str(ei.value).lower()
    assert "script/style body" in msg or "rawtext body" in msg


@pytest.mark.parametrize("html", [
    "<noscript>{{x}}</noscript>",
    "<xmp>{{x}}</xmp>",
    "<plaintext>{{x}}",
])
def test_RG_E34_rawtext_body_rejected(html):
    with pytest.raises(TemplateUnsafeSlotError) as ei:
        ObjectHTML(HTMLDoc("t", html))
    assert ei.value.code == "OH06" and "rawtext body" in str(ei.value).lower()


# ---- E33 / E34 positives (accepted, DATA/RCDATA => escaped) + negative control
@pytest.mark.parametrize("html,pre,post", [
    ("<script>a<!--b</script><p>{{x}}</p>", "<script>a<!--b</script><p>", "</p>"),
    ("<script><!--<script></script>--></script><p>{{x}}</p>", "<script><!--<script></script>--></script><p>", "</p>"),
    ("<svg><title>{{x}}</title></svg>", "<svg><title>", "</title></svg>"),
    ("<svg><foreignObject><p>{{x}}</p></foreignObject></svg>", "<svg><foreignObject><p>", "</p></foreignObject></svg>"),
    ("<svg><p>{{x}}</p></svg>", "<svg><p>", "</p></svg>"),
    ("<textarea>{{x}}</textarea>", "<textarea>", "</textarea>"),
    ("<title>{{x}}</title>", "<title>", "</title>"),
    ("<xmp></xmp>{{x}}", "<xmp></xmp>", ""),
    ("<TEXTAREA>a</TEXTAREA >{{x}}", "<TEXTAREA>a</TEXTAREA >", ""),
    ("<!DOCTYPE html><p>{{x}}</p>", "<!DOCTYPE html><p>", "</p>"),
    ('<?xml version="1.0"?><p>{{x}}</p>', '<?xml version="1.0"?><p>', "</p>"),
    ('<script src="x.js"></script><p>{{x}}</p>', '<script src="x.js"></script><p>', "</p>"),
])
def test_RG_E33_E34_accepted_and_value_escaped(html, pre, post):
    out = str(_t(html).t(x=_E_X))
    assert out == pre + _E_ESC + post, out
    assert _E_X not in out


def test_RG_E34_negative_control_body_and_textarea_both_escape_same_value():
    body = str(_t("<p>{{x}}</p>").t(x=_E_X))
    ta = str(_t("<textarea>{{x}}</textarea>").t(x=_E_X))
    assert body == "<p>&lt;i&gt;&amp;</p>"
    assert ta == "<textarea>&lt;i&gt;&amp;</textarea>"
    assert "&lt;" in ta and "<i>" not in ta

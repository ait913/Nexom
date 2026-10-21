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

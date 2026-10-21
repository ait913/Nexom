"""Reviewer-generated tests for the 1.2.0 auth-hardening design doc.

Source of truth: .designs/20261021-auth-hardening.md (+ Leader amendments).
Written without reading src/nexom/**.  Test names carry the design-doc IDs.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import secrets
import socket
import sqlite3
import statistics
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

import pytest

from nexom.app.auth import (
    AuthClient,
    AuthDBM,
    AuthPolicy,
    AuthService,
    is_same_origin,
)
from nexom.app.request import Request
from nexom.app.user import UserDatabaseManager
from nexom.core.error import (
    AuthForbiddenError,
    AuthInvalidFieldError,
    AuthServiceUnavailableError,
    AuthTooManyAttemptsError,
    PathNotFoundError,
)
from nexom.templates.auth import AuthPages

from conftest import make_environ

IP = "203.0.113.7"
IP2 = "203.0.113.8"
PW = "correct-horse-8"
MASTER_PW = "master-login-pw-1"
T0 = 1_800_000_000
JSON_CT = "application/json"
DEFAULT = AuthPolicy()


def fast(**kw) -> AuthPolicy:
    base = dict(pbkdf2_iterations=1000, hash_busy_ratio=None, signup_ip_threshold=10_000)
    base.update(kw)
    return AuthPolicy(**base)


class Env:
    """AuthService + helpers (fake clock, sqlite peeking, log reading)."""

    def __init__(self, tmp_path: Path, policy: AuthPolicy | None = None, **svc_kw):
        self.tmp = tmp_path
        self.db = str(tmp_path / "auth.db")
        self.log = str(tmp_path / "auth.log")
        self.t = [T0]
        self.policy = policy if policy is not None else fast()
        self.svc_kw = svc_kw
        self.svc = self.new_service()

    def clock(self) -> int:
        return self.t[0]

    def advance(self, sec: int) -> None:
        self.t[0] += sec

    def new_service(self, policy: AuthPolicy | None = None, **kw) -> AuthService:
        args = dict(master_login_password=MASTER_PW, policy=policy or self.policy, clock=self.clock)
        args.update(self.svc_kw)
        args.update(kw)
        return AuthService(self.db, self.log, **args)

    # --- requests ---------------------------------------------------
    def call(self, path, body=None, *, method="POST", remote="127.0.0.1", headers=None,
             raw: bytes | None = None, content_type=JSON_CT, svc=None):
        data = raw if raw is not None else json.dumps(body if body is not None else {}).encode()
        env = make_environ(method=method, path=path, body=data, content_type=content_type, headers=headers)
        if remote is None:
            env.pop("REMOTE_ADDR", None)
        else:
            env["REMOTE_ADDR"] = remote
        res = (svc or self.svc).handler(env)
        try:
            payload = json.loads(res.body.decode("utf-8"))
        except Exception:
            payload = None
        return res.status_code, payload, res

    def signup(self, uid, pw=PW, name=None, ip=IP, svc=None):
        return self.call("/signup", {"user_id": uid, "public_name": name or uid.title(), "password": pw,
                                      "client_ip": ip}, svc=svc)

    def login(self, uid, pw=PW, ip=IP, svc=None, **extra):
        body = {"user_id": uid, "password": pw, "client_ip": ip}
        body.update(extra)
        return self.call("/login", body, svc=svc)

    def user(self, uid, pw=PW, ip=IP):
        """signup + login. returns login payload."""
        st, _, _ = self.signup(uid, pw, ip=ip)
        assert st == 201
        st, d, _ = self.login(uid, pw, ip=ip)
        assert st == 200, d
        return d

    def master_token(self) -> str:
        st, d, _ = self.login("master_user", MASTER_PW, ip="127.0.0.1")
        assert st == 200, d
        return d["token"]

    def verify(self, token, svc=None):
        return self.call("/verify", {"token": token}, svc=svc)[1]

    # --- sqlite peeking -----------------------------------------------
    def q(self, sql, args=()):
        con = sqlite3.connect(self.db)
        try:
            cur = con.execute(sql, args)
            rows = cur.fetchall()
            con.commit()
            return rows
        finally:
            con.close()

    def attempt(self, key):
        rows = self.q("SELECT count, window_start, locked_until FROM auth_attempts WHERE key=?", (key,))
        return rows[0] if rows else None

    def attempts_all(self):
        return sorted(self.q("SELECT key, count, window_start, locked_until FROM auth_attempts"))

    def logtext(self) -> str:
        p = Path(self.log)
        return p.read_text(encoding="utf-8") if p.exists() else ""

    def uid_of(self, user_id):
        return self.q("SELECT uid FROM users WHERE user_id=?", (user_id,))[0][0]

    def insert_legacy(self, user_id, pw, active=1, public_name="Legacy"):
        salt = os.urandom(16).hex()
        h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
        uid = secrets.token_urlsafe(18)
        self.q("INSERT INTO users(uid,user_id,public_name,password_hash,password_salt,is_active,is_master) "
               "VALUES(?,?,?,?,?,?,0)", (uid, user_id, public_name, h, salt, active))
        return uid

    def set_attempt(self, key, count, locked_until=None, window_start=None):
        self.q("INSERT OR REPLACE INTO auth_attempts(key,count,window_start,locked_until) VALUES(?,?,?,?)",
               (key, count, self.t[0] if window_start is None else window_start, locked_until))


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def err(payload):
    return payload.get("error")


# ===================================================================== G
def test_G1_loopback_v4_passes(env):
    st, d, _ = env.call("/verify", {"token": "x"}, remote="127.0.0.1")
    assert st == 200 and d == {"active": False}


def test_G2_loopback_v6_passes(env):
    st, d, _ = env.call("/verify", {"token": "x"}, remote="::1")
    assert st == 200


def test_G3_external_forbidden_and_logged_no_db_change(env):
    st, d, _ = env.signup("carol", ip=IP, svc=None) if False else (None, None, None)
    st, d, _ = env.call("/signup", {"user_id": "carol", "public_name": "Carol", "password": PW,
                                    "client_ip": IP}, remote="10.0.0.5")
    assert st == 403 and d == {"ok": False, "error": "A13"}
    assert env.q("SELECT COUNT(*) FROM users WHERE user_id='carol'")[0][0] == 0
    assert env.attempts_all() == []
    assert re.search(r"\[FORBIDDEN_CLIENT\].*subject=10\.0\.0\.5", env.logtext())


def test_G4_missing_remote_addr_fail_closed(env):
    st, d, _ = env.call("/verify", {"token": "x"}, remote=None)
    assert st == 403 and err(d) == "A13"
    assert re.search(r"\[FORBIDDEN_CLIENT\].*subject=-", env.logtext())


def test_G5_garbage_remote_addr(env):
    st, d, _ = env.call("/verify", {"token": "x"}, remote="not-an-ip")
    assert st == 403 and err(d) == "A13"


def test_G6_custom_allowed_clients_replaces_default(tmp_path):
    e = Env(tmp_path, allowed_clients=("10.0.0.5",))
    assert e.call("/verify", {"token": "x"}, remote="10.0.0.5")[0] == 200
    st, d, _ = e.call("/verify", {"token": "x"}, remote="127.0.0.1")
    assert st == 403 and err(d) == "A13"


def test_G7_allowed_clients_none_disables_guard(tmp_path):
    e = Env(tmp_path, allowed_clients=None)
    assert e.call("/verify", {"token": "x"}, remote="198.51.100.9")[0] == 200


def test_G8_guard_precedes_routing(env):
    st, d, _ = env.call("/no/such/path", {}, remote="203.0.113.5")
    assert st == 403 and err(d) == "A13"
    st, d, _ = env.call("/no/such/path", {}, remote="127.0.0.1")
    assert st == 404


def test_G8b_guard_with_prefix(tmp_path):
    e = Env(tmp_path, prefix="/auth")
    st, d, _ = e.call("/elsewhere", {}, remote="203.0.113.5")
    assert st == 403
    st, d, _ = e.call("/auth/verify", {"token": "x"}, remote="203.0.113.5")
    assert st == 403
    st, d, _ = e.call("/auth/verify", {"token": "x"}, remote="127.0.0.1")
    assert st == 200


def test_M13_master_password_arg_removed(tmp_path):
    with pytest.raises(TypeError):
        AuthService(str(tmp_path / "a.db"), str(tmp_path / "a.log"), master_login_password=MASTER_PW,
                    master_password="x")


# ===================================================================== L
def test_L1_login_ok_shape_and_side_effects(env):
    env.signup("alice")
    st, d, _ = env.login("alice")
    assert st == 200
    assert d["ok"] is True and d["user_id"] == "alice" and d["public_name"]
    assert isinstance(d["token"], str) and len(d["token"]) == 43 and re.fullmatch(r"[A-Za-z0-9_-]{43}", d["token"])
    assert d["expires_at"] == T0 + 60 * 60 * 24 * 7
    assert "user_agent" in d and d["user_agent"] is None
    assert d["pid"] == env.uid_of("alice")
    rows = env.q("SELECT created_at, revoked_at FROM sessions WHERE uid=?", (d["pid"],))
    assert rows == [(T0, None)]
    assert re.search(rf"\[LOGIN_OK\] subject=alice ip={re.escape(IP)}", env.logtext())
    assert env.attempt("login_user:alice") is None
    assert env.attempt(f"login_ip:{IP}") is None


def test_L2_user_agent_body_wins_header_fallback(env):
    env.signup("alice")
    st, d, _ = env.login("alice", user_agent="Mozilla/5.0")
    assert d["user_agent"] == "Mozilla/5.0"
    assert env.verify(d["token"])["user_agent"] == "Mozilla/5.0"
    st, d, _ = env.call("/login", {"user_id": "alice", "password": PW, "client_ip": IP},
                        headers={"User-Agent": "HdrUA/1"})
    assert d["user_agent"] == "HdrUA/1"
    st, d, _ = env.call("/login", {"user_id": "alice", "password": PW, "client_ip": IP, "user_agent": "Body"},
                        headers={"User-Agent": "HdrUA/1"})
    assert d["user_agent"] == "Body"


def test_L3_client_ip_missing(env):
    env.signup("alice")
    st, d, _ = env.call("/login", {"user_id": "alice", "password": PW})
    assert st == 400 and d == {"ok": False, "error": "A01", "field": "client_ip"}
    assert env.attempts_all() == []


def test_L4_client_ip_invalid(env):
    env.signup("alice")
    st, d, _ = env.login("alice", ip="999.1.1.1")
    assert st == 400 and err(d) == "A12" and d.get("field") == "client_ip"
    assert env.attempts_all() == []


def test_L5_length_caps_cheap_reject(env):
    env.signup("alice")
    st, d, _ = env.login("a" * 257)
    assert st == 400 and err(d) == "A12" and d["field"] == "user_id"
    st, d, _ = env.login("alice", "p" * 257)
    assert st == 400 and err(d) == "A12" and d["field"] == "password"
    st, d, _ = env.login("alice", "あ" * 86)  # 258 bytes
    assert st == 400 and err(d) == "A12" and d["field"] == "password"
    assert env.attempts_all() == []


def test_L6_unknown_user_a03_and_reserved(env):
    st, d, _ = env.login("nobody", "whatever-pass")
    assert st == 401 and d == {"ok": False, "error": "A03"}
    assert env.attempt("login_user:nobody")[0] == 1
    assert env.attempt(f"login_ip:{IP}")[0] == 1
    assert re.search(rf"\[LOGIN_NG\] subject=nobody ip={re.escape(IP)} detail=reason=invalid", env.logtext())


def test_L7_known_wrong_pw_same_shape_as_unknown(env):
    env.signup("alice")
    s1, d1, _ = env.login("alice", "wrong-password-1")
    s2, d2, _ = env.login("nobody", "wrong-password-1")
    assert (s1, d1) == (s2, d2) == (401, {"ok": False, "error": "A03"})
    assert env.attempt("login_user:alice")[0] == 1


def test_L7_timing_known_vs_unknown_similar(tmp_path):
    pol = AuthPolicy(hash_busy_ratio=None, account_lock_threshold=10_000, ip_fail_threshold=10_000)
    e = Env(tmp_path, policy=pol)
    e.signup("alice")
    kn, un = [], []
    for i in range(20):
        t = time.perf_counter()
        e.login("alice", "wrong-password-1", ip=f"198.51.100.{i + 1}")
        kn.append(time.perf_counter() - t)
        t = time.perf_counter()
        e.login(f"nobody{i}", "wrong-password-1", ip=f"198.51.100.{i + 1}")
        un.append(time.perf_counter() - t)
    ratio = statistics.median(un) / statistics.median(kn)
    assert 0.5 <= ratio <= 2.0, ratio


def _concurrent_patch(monkeypatch, inner):
    orig = AuthDBM._timed_hash
    state = {"entered": False, "calls": 0, "inner": None}

    def wrapper(self, fn):
        state["calls"] += 1
        if not state["entered"]:
            state["entered"] = True
            state["inner"] = inner()
        return orig(self, fn)

    monkeypatch.setattr(AuthDBM, "_timed_hash", wrapper)
    return state


def test_L7b_reservation_strict_upper_bound(env, monkeypatch):
    env.signup("alice")
    for _ in range(DEFAULT.account_lock_threshold - 1):
        assert env.login("alice", "wrong-password-1")[0] == 401
    assert env.attempt("login_user:alice")[0] == DEFAULT.account_lock_threshold - 1
    svc2 = env.new_service()
    state = _concurrent_patch(monkeypatch, lambda: env.login("alice", "wrong-password-2", ip=IP2, svc=svc2))
    st, d, _ = env.login("alice", "wrong-password-3")
    inner_st, inner_d, _ = state["inner"]
    assert (st, err(d)) == (401, "A03")
    assert (inner_st, err(inner_d)) == (429, "A11")
    assert state["calls"] == 1  # inner never hashed
    cnt, _, locked = env.attempt("login_user:alice")
    assert cnt == DEFAULT.account_lock_threshold and locked == T0 + DEFAULT.account_lock_sec


def test_L8_disabled_user_wrong_pw_is_a03(env):
    env.signup("dave", "dave-pass-123")
    env.q("UPDATE users SET is_active=0 WHERE user_id='dave'")
    st, d, _ = env.login("dave", "totally-wrong-1")
    assert (st, d) == (401, {"ok": False, "error": "A03"})


def test_L9_disabled_user_right_pw_a04(env):
    env.signup("dave", "dave-pass-123")
    env.q("UPDATE users SET is_active=0 WHERE user_id='dave'")
    st, d, _ = env.login("dave", "dave-pass-123")
    assert st == 403 and err(d) == "A04"
    assert env.attempt("login_user:dave")[0] == 1
    assert env.attempt(f"login_ip:{IP}")[0] == 1
    assert re.search(r"\[LOGIN_NG\] subject=dave .*detail=reason=disabled", env.logtext())


def _lock_alice(env):
    env.signup("alice")
    for i in range(DEFAULT.account_lock_threshold):
        st, d, _ = env.login("alice", f"wrong-password-{i}")
        if i < DEFAULT.account_lock_threshold - 1:
            assert st == 401
    return st, d


def test_L10_fifth_failure_401_then_locked(env):
    st, d = _lock_alice(env)
    assert (st, err(d)) == (401, "A03")
    cnt, _, locked = env.attempt("login_user:alice")
    assert cnt == DEFAULT.account_lock_threshold and locked == T0 + DEFAULT.account_lock_sec
    assert re.search(rf"\[LOCKOUT\] subject=login_user:alice.*detail=until={locked}", env.logtext())


def test_L11_locked_even_with_correct_pw_and_no_extension(env):
    _lock_alice(env)
    before = env.attempt("login_user:alice")
    ip_before = env.attempt(f"login_ip:{IP}")
    st, d, _ = env.login("alice", PW)
    assert (st, d) == (429, {"ok": False, "error": "A11"})
    assert env.attempt("login_user:alice") == before
    assert env.attempt(f"login_ip:{IP}") == ip_before
    assert re.search(r"\[RATE_LIMITED\] subject=login_user:alice.*detail=reason=locked", env.logtext())


def test_L12_unlocks_after_window_and_clears_row(env):
    _lock_alice(env)
    assert env.login("alice", PW)[0] == 429
    env.advance(DEFAULT.account_lock_sec + 1)
    st, d, _ = env.login("alice", PW)
    assert st == 200
    assert env.attempt("login_user:alice") is None


def test_L12b_not_unlocked_just_before_expiry(env):
    _lock_alice(env)
    env.advance(DEFAULT.account_lock_sec - 5)
    assert env.login("alice", PW)[0] == 429


def test_L13_window_reset(env):
    env.signup("alice")
    for _ in range(DEFAULT.account_lock_threshold - 1):
        env.login("alice", "wrong-password-1")
    env.advance(DEFAULT.account_window_sec + 1)
    assert env.login("alice", "wrong-password-1")[0] == 401
    cnt, _, locked = env.attempt("login_user:alice")
    assert cnt == 1 and locked is None


def test_L14_success_resets_account_counter(env):
    env.signup("alice")
    n = DEFAULT.account_lock_threshold - 1
    for _ in range(n):
        env.login("alice", "wrong-password-1")
    assert env.login("alice", PW)[0] == 200
    for _ in range(n):
        assert env.login("alice", "wrong-password-1")[0] == 401
    assert env.attempt("login_user:alice")[2] is None


def test_L15_ip_axis_locks_on_failures_only(env):
    env.signup("alice")
    n = DEFAULT.ip_fail_threshold
    for i in range(n):
        st, _, _ = env.login(f"ghost{i:03d}", "whatever-pass")
        assert st == 401, i
    cnt, _, locked = env.attempt(f"login_ip:{IP}")
    assert cnt == n and locked == T0 + DEFAULT.ip_lock_sec
    assert re.search(rf"\[LOCKOUT\] subject=login_ip:{re.escape(IP)}", env.logtext())
    st, d, _ = env.login("alice", PW)
    assert (st, err(d)) == (429, "A11")
    assert env.login("alice", PW, ip=IP2)[0] == 200


def test_L16_success_not_counted_on_ip_axis(env):
    env.signup("alice")
    for _ in range(100):
        assert env.login("alice", PW)[0] == 200
    assert env.attempt(f"login_ip:{IP}") is None
    assert env.attempt("login_user:alice") is None


def _gauge_env(tmp_path, window=1.0):
    e = Env(tmp_path)
    gp = fast(hash_busy_ratio=0.0, hash_window_sec=window)
    return e, e.new_service(policy=gp)


def test_L17_gauge_ratio_zero_blocks_second_hash(tmp_path):
    e, g = _gauge_env(tmp_path, window=0.5)
    st, d, _ = e.login("nobody", "whatever-pass", svc=g)
    assert (st, err(d)) == (401, "A03")
    snap = e.attempts_all()
    assert [r[0] for r in snap] == sorted(["login_user:nobody", f"login_ip:{IP}"])
    for _ in range(2):
        st, d, _ = e.login("nobody", "whatever-pass", svc=g)
        assert (st, d) == (429, {"ok": False, "error": "A11"})
    assert e.attempts_all() == snap
    assert re.search(r"\[RATE_LIMITED\] subject=gauge.*detail=reason=busy", e.logtext())
    time.sleep(0.6)
    st, d, _ = e.login("nobody", "whatever-pass", svc=g)
    assert (st, err(d)) == (401, "A03")


def test_L17_startup_master_hash_not_counted(tmp_path):
    e, g = _gauge_env(tmp_path, window=5.0)
    # fresh service with ratio 0.0: first failure must be 401 (not 429)
    st, d, _ = e.login("nobody", "whatever-pass", svc=g)
    assert st == 401


def test_V4_verify_independent_of_gauge(tmp_path):
    e = Env(tmp_path)
    e.signup("alice")
    tok = e.login("alice")[1]["token"]
    g = e.new_service(policy=fast(hash_busy_ratio=0.0, hash_window_sec=5.0))
    assert e.login("nobody", "whatever-pass", svc=g)[0] == 401
    assert e.login("nobody", "whatever-pass", svc=g)[0] == 429
    st, d, _ = e.call("/verify", {"token": tok}, svc=g)
    assert st == 200 and d["active"] is True


def test_L17b_default_gauge_count_matches_machine(tmp_path):
    e = Env(tmp_path, policy=AuthPolicy(account_lock_threshold=10_000, ip_fail_threshold=10_000))
    e.signup("alice")  # warms nothing; gauge is bypassed? use fresh service below
    e.advance(0)
    svc = e.new_service(policy=AuthPolicy(account_lock_threshold=10_000, ip_fail_threshold=10_000))
    t = time.perf_counter()
    hashlib.pbkdf2_hmac("sha256", b"x", b"y" * 16, DEFAULT.pbkdf2_iterations)
    d_ms = (time.perf_counter() - t) * 1000
    expected = math.floor(500 / d_ms) + 1
    passed = 0
    blocked_at = None
    for i in range(expected + 6):
        st, _, _ = e.login(f"ghost{i:03d}", "whatever-pass", svc=svc)
        if st == 401:
            passed += 1
        else:
            assert st == 429
            blocked_at = i
            break
    assert blocked_at is not None, "gauge never engaged"
    assert abs(passed - expected) <= 1, (passed, expected, d_ms)


def test_L18_legacy_transparent_rehash(tmp_path):
    e = Env(tmp_path, policy=AuthPolicy(hash_busy_ratio=None))
    e.insert_legacy("legacy_bob", "legacy-pass-9")
    st, d, _ = e.login("legacy_bob", "legacy-pass-9")
    assert st == 200
    h, s = e.q("SELECT password_hash, password_salt FROM users WHERE user_id='legacy_bob'")[0]
    assert h.startswith("pbkdf2_sha256$600000$") and s == ""
    assert re.fullmatch(r"pbkdf2_sha256\$600000\$[0-9a-f]+\$[0-9a-f]+", h)
    assert e.login("legacy_bob", "legacy-pass-9")[0] == 200
    assert e.q("SELECT password_hash FROM users WHERE user_id='legacy_bob'")[0][0] == h


def test_L19_legacy_wrong_pw_unchanged(env):
    env.insert_legacy("legacy_bob", "legacy-pass-9")
    before = env.q("SELECT password_hash, password_salt FROM users WHERE user_id='legacy_bob'")
    st, d, _ = env.login("legacy_bob", "not-the-password")
    assert (st, err(d)) == (401, "A03")
    assert env.q("SELECT password_hash, password_salt FROM users WHERE user_id='legacy_bob'") == before
    assert "$" not in before[0][0]


def test_L20_session_cap_20(env):
    env.signup("alice")
    toks = []
    for _ in range(21):
        env.advance(1)
        toks.append(env.login("alice")[1]["token"])
    uid = env.uid_of("alice")
    assert env.q("SELECT COUNT(*) FROM sessions WHERE uid=?", (uid,))[0][0] == DEFAULT.max_sessions_per_user
    assert env.verify(toks[0])["active"] is False
    assert env.verify(toks[-1])["active"] is True


def test_L21_sweeps_expired_and_revoked_only_for_user(env):
    env.signup("alice")
    env.signup("bobby")
    a, b = env.uid_of("alice"), env.uid_of("bobby")
    for i in range(3):
        env.q("INSERT INTO sessions(sid,uid,token_hash,expires_at,revoked_at,user_agent,created_at) VALUES(?,?,?,?,NULL,NULL,1)",
              (f"ea{i}", a, f"hea{i}", T0 - 10))
    for i in range(2):
        env.q("INSERT INTO sessions(sid,uid,token_hash,expires_at,revoked_at,user_agent,created_at) VALUES(?,?,?,?,?,NULL,1)",
              (f"ra{i}", a, f"hra{i}", T0 + 9999, T0 - 5))
    env.q("INSERT INTO sessions(sid,uid,token_hash,expires_at,revoked_at,user_agent,created_at) VALUES(?,?,?,?,NULL,NULL,1)",
          ("eb0", b, "heb0", T0 - 10))
    assert env.login("alice")[0] == 200
    sids = {r[0] for r in env.q("SELECT sid FROM sessions")}
    assert not ({"ea0", "ea1", "ea2", "ra0", "ra1"} & sids)
    assert "eb0" in sids


def test_L22_form_body_rejected(env):
    env.signup("alice")
    st, d, _ = env.call("/login", raw=b"user_id=alice&password=x&client_ip=1.2.3.4",
                        content_type="application/x-www-form-urlencoded")
    assert st == 400 and d == {"ok": False, "error": "A01", "field": "body"}


def test_L23_invalid_json_400(env):
    for raw in (b"{not json", b"[1,2]", b'"str"', b""):
        st, d, _ = env.call("/login", raw=raw)
        assert st == 400 and d == {"ok": False, "error": "A01", "field": "body"}, raw


def test_login_non_post_405(env):
    st, d, _ = env.call("/login", method="GET")
    assert st == 405 and d == {"ok": False, "error": "MethodNotAllowed"}


# ===================================================================== S
PW_HASH_RE = re.compile(r"pbkdf2_sha256\$\d+\$[0-9a-f]+\$[0-9a-f]+")


def test_S1_signup_ok_row_shape(tmp_path):
    e = Env(tmp_path, policy=AuthPolicy(hash_busy_ratio=None))
    st, d, _ = e.signup("carol", "carol-pass-1")
    assert st == 201 and d == {"ok": True}
    h, s, created, master = e.q("SELECT password_hash, password_salt, created_at, is_master FROM users WHERE user_id='carol'")[0]
    assert PW_HASH_RE.fullmatch(h) and h.split("$")[1] == "600000"
    assert s == "" and created is not None and master == 0
    assert e.attempt(f"signup_ip:{IP}")[0] == 1
    assert re.search(r"\[SIGNUP\] subject=carol", e.logtext())


def test_S2_weak_password_a12_no_attempt_row(env):
    st, d, _ = env.call("/signup", {"user_id": "carol", "public_name": "Carol", "password": "1", "client_ip": IP})
    assert st == 400 and d == {"ok": False, "error": "A12", "field": "password"}
    assert env.attempts_all() == []
    assert env.q("SELECT COUNT(*) FROM users WHERE user_id='carol'")[0][0] == 0
    assert re.search(r"\[SIGNUP_NG\].*reason=A12:password", env.logtext())


def test_S3_password_min_boundary(env):
    n = DEFAULT.password_min_len
    st, d, _ = env.signup("carol", "p" * (n - 1))
    assert st == 400 and err(d) == "A12" and d["field"] == "password"
    assert env.signup("carol", "p" * n)[0] == 201


def test_S4_password_byte_boundary(env):
    mx = DEFAULT.password_max_bytes
    st, d, _ = env.signup("carol", "a" * (mx + 1))
    assert st == 400 and err(d) == "A12"
    assert env.signup("carol", "a" * mx)[0] == 201
    # multibyte: 86 chars * 3 bytes = 258 > 256
    st, d, _ = env.signup("carold", "あ" * 86)
    assert st == 400 and err(d) == "A12"
    assert env.signup("carole", "あ" * 85)[0] == 201  # 255 bytes


def test_S5_whitespace_password_ok_and_not_stripped(env):
    assert env.signup("carol", "        ")[0] == 201
    assert env.login("carol", "        ")[0] == 200
    assert env.login("carol", "       ")[0] == 401


def test_S6_html_user_id_rejected(env):
    st, d, _ = env.signup("<img src=x onerror=alert(1)>")
    assert st == 400 and err(d) == "A12" and d["field"] == "user_id"


@pytest.mark.parametrize("uid,ok", [
    ("ab", False), ("abc", True), ("a" * 32, True), ("a" * 33, False),
    ("Alice", False), ("_al", False), ("al.i-ce_9", True), ("al ice", False),
])
def test_S7_user_id_pattern(env, uid, ok):
    st, d, _ = env.signup(uid)
    if ok:
        assert st == 201
    else:
        assert st == 400 and err(d) == "A12" and d["field"] == "user_id"


def test_S8_duplicate_409(env):
    env.signup("alice")
    st, d, _ = env.signup("alice")
    assert st == 409 and err(d) == "A02"
    assert re.search(r"\[SIGNUP_NG\].*reason=A02", env.logtext())


def test_S9_case_insensitive_collision(env):
    env.insert_legacy("Admin", "legacy-pass-9")
    st, d, _ = env.signup("admin")
    assert st == 409 and err(d) == "A02"
    assert env.q("SELECT COUNT(*) FROM users WHERE lower(user_id)='admin'")[0][0] == 1


def test_S10_public_name_angle_brackets(env):
    st, d, _ = env.call("/signup", {"user_id": "carol", "public_name": "<script>1</script>",
                                    "password": PW, "client_ip": IP})
    assert st == 400 and err(d) == "A12" and d["field"] == "public_name"


@pytest.mark.parametrize("name,expect", [
    ("山田 太郎", 201), ("Tom & Jerry", 201), ("a\u0000b", 400), ("​x", 400),
    ("x" * 64, 201), ("x" * 65, 400), ("  ", 400),
])
def test_S11_public_name_cases(env, name, expect):
    st, d, _ = env.call("/signup", {"user_id": "carol", "public_name": name, "password": PW, "client_ip": IP})
    assert st == expect, d
    if name == "  ":
        assert err(d) == "A01" and d.get("field") == "public_name"
    elif expect == 400:
        assert err(d) == "A12" and d["field"] == "public_name"


def test_S12_nfc_not_nfkc(env):
    name = "ｱｲｳ" + "Ａ" + "é"
    st, _, _ = env.call("/signup", {"user_id": "carol", "public_name": name, "password": PW, "client_ip": IP})
    assert st == 201
    saved = env.q("SELECT public_name FROM users WHERE user_id='carol'")[0][0]
    assert saved == unicodedata.normalize("NFC", name)
    assert "ｱｲｳ" in saved and "Ａ" in saved


def test_S13_signup_ip_rate_limit(tmp_path):
    e = Env(tmp_path, policy=fast())
    e.svc = e.new_service(policy=fast(signup_ip_threshold=DEFAULT.signup_ip_threshold))
    n = DEFAULT.signup_ip_threshold
    for i in range(n):
        assert e.signup(f"usr{i:02d}", svc=e.svc)[0] == 201, i
    cnt, _, locked = e.attempt(f"signup_ip:{IP}")
    assert cnt == n and locked == T0 + DEFAULT.signup_lock_sec
    assert re.search(rf"\[LOCKOUT\] subject=signup_ip:{re.escape(IP)}", e.logtext())
    snap = e.attempts_all()
    st, d, _ = e.signup("usr99", svc=e.svc)
    assert (st, err(d)) == (429, "A11")
    assert e.attempts_all() == snap
    assert e.signup("usr98", ip=IP2, svc=e.svc)[0] == 201
    e.advance(DEFAULT.signup_lock_sec + 1)
    assert e.signup("usr97", svc=e.svc)[0] == 201  # S-14


def test_S13_collisions_also_count(tmp_path):
    e = Env(tmp_path)
    e.svc = e.new_service(policy=fast(signup_ip_threshold=3))
    e.signup("alice", svc=e.svc)
    for _ in range(2):
        assert e.signup("alice", svc=e.svc)[0] == 409
    assert e.attempt(f"signup_ip:{IP}")[0] == 3
    assert e.signup("fresh1", svc=e.svc)[0] == 429


def test_S13b_concurrent_signup_threshold(tmp_path, monkeypatch):
    e = Env(tmp_path)
    thr = DEFAULT.signup_ip_threshold
    e.svc = e.new_service(policy=fast(signup_ip_threshold=thr))
    e.set_attempt(f"signup_ip:{IP}", thr - 1)
    state = _concurrent_patch(monkeypatch, lambda: e.signup("inner1", svc=e.new_service(policy=fast(signup_ip_threshold=thr))))
    st, d, _ = e.signup("outer1", svc=e.svc)
    inner_st, inner_d, _ = state["inner"] or (None, None, None)
    results = sorted([st, inner_st])
    assert results == [201, 429], (st, inner_st)
    assert e.q("SELECT COUNT(*) FROM users WHERE user_id IN ('outer1','inner1')")[0][0] == 1


def test_S15_signup_client_ip_missing(env):
    st, d, _ = env.call("/signup", {"user_id": "carol", "public_name": "Carol", "password": PW})
    assert st == 400 and d == {"ok": False, "error": "A01", "field": "client_ip"}
    assert env.attempts_all() == []


def test_S16_signup_blocked_by_gauge(tmp_path):
    e, g = _gauge_env(tmp_path, window=5.0)
    assert e.login("nobody", "whatever-pass", svc=g)[0] == 401
    snap = e.attempts_all()
    st, d, _ = e.signup("carol", svc=g)
    assert (st, err(d)) == (429, "A11")
    assert e.q("SELECT COUNT(*) FROM users WHERE user_id='carol'")[0][0] == 0
    assert e.attempts_all() == snap


def test_S_non_post_405(env):
    st, d, _ = env.call("/signup", method="GET")
    assert st == 405


# ===================================================================== V / O / T
def test_V1_verify_active_shape(env):
    d = env.user("alice")
    v = env.verify(d["token"])
    assert v["active"] is True and v["pid"] == d["pid"] and v["user_id"] == "alice"
    assert {"public_name", "expires_at", "user_agent"} <= set(v)


def test_V2_verify_inactive_variants_silent(env):
    d = env.user("alice")
    env.call("/logout", {"token": d["token"]})
    before = env.logtext()
    for tok in ("unknown-token", "", d["token"]):
        st, r, _ = env.call("/verify", {"token": tok})
        assert st == 200 and r == {"active": False}
    expired = env.login("alice")[1]["token"]
    env.advance(60 * 60 * 24 * 7 + 5)
    assert env.verify(expired) == {"active": False}
    assert env.logtext() == before
    assert env.attempts_all() == []


def test_V3_verify_inactive_when_owner_disabled(env):
    d = env.user("alice")
    env.q("UPDATE users SET is_active=0 WHERE user_id='alice'")
    assert env.verify(d["token"]) == {"active": False}


def test_O1_logout_revokes_and_logs(env):
    d = env.user("alice")
    st, r, _ = env.call("/logout", {"token": d["token"], "client_ip": IP})
    assert st == 200 and r == {"ok": True}
    assert env.q("SELECT revoked_at FROM sessions WHERE uid=?", (d["pid"],))[0][0] == T0
    assert re.search(rf"\[LOGOUT\] subject=alice ip={re.escape(IP)}", env.logtext())
    assert env.verify(d["token"]) == {"active": False}


def test_O1b_logout_without_ip_dash(env):
    d = env.user("alice")
    env.call("/logout", {"token": d["token"]})
    assert re.search(r"\[LOGOUT\] subject=alice ip=-", env.logtext())


def test_O2_O3_logout_idempotent_silent(env):
    env.user("alice")
    before = env.logtext()
    for tok in ("unknown", ""):
        st, r, _ = env.call("/logout", {"token": tok})
        assert st == 200 and r == {"ok": True}
    assert env.logtext() == before


def test_T1_resolve_pid_removed(env):
    for body in ({}, {"user_id": "alice"}, {"token": "x", "user_id": "alice"}):
        st, d, _ = env.call("/resolve/pid", body)
        assert st == 404 and d == {"ok": False, "error": "NotFound"}


TOKEN_ENDPOINTS = [
    ("/convert/pid", {"user_id": "alice"}),
    ("/convert/user-id", {"pid": "x" * 20}),
    ("/update/public-name", {"public_name": "X"}),
    ("/update/password", {"current_password": PW, "new_password": "new-pass-123", "client_ip": IP}),
    ("/permissions/group/create", {"group_id": "g1", "name": "G"}),
    ("/permissions/group/delete", {"group_id": "g1"}),
    ("/permissions/group/member/upsert", {"group_id": "g1", "user_id": "alice", "level": 1}),
    ("/permissions/group/member/delete", {"group_id": "g1", "user_id": "alice"}),
    ("/permissions/group/auth", {"group_id": "g1", "pid": "x" * 20}),
    ("/permissions/groups/mine", {}),
    ("/master/users/list", {}),
    ("/master/users/deactivate", {"target_user_id": "alice", "login_password": MASTER_PW, "client_ip": IP}),
    ("/master/users/activate", {"target_user_id": "alice", "login_password": MASTER_PW, "client_ip": IP}),
]


@pytest.mark.parametrize("path,body", TOKEN_ENDPOINTS)
def test_T2_invalid_token_a06_logged(env, path, body):
    st, d, _ = env.call(path, dict(body, token="Z" * 43))
    assert st == 401 and err(d) == "A06"
    assert re.search(r"\[TOKEN_INVALID\] subject=ZZZZZZZZ\.\.\.", env.logtext())


@pytest.mark.parametrize("path,body", TOKEN_ENDPOINTS)
def test_T3_missing_token_a05_silent(env, path, body):
    before = env.logtext()
    st, d, _ = env.call(path, dict(body))
    assert st == 401 and err(d) == "A05"
    assert env.logtext() == before


def test_T4_convert_pid_unknown_user_a03(env):
    d = env.user("alice")
    st, r, _ = env.call("/convert/pid", {"token": d["token"], "user_id": "nonexistent"})
    assert st == 401 and err(r) == "A03"
    st, r, _ = env.call("/convert/pid", {"token": d["token"], "user_id": "alice"})
    assert st == 200


# ===================================================================== H
def test_H1_password_change(env):
    d = env.user("alice")
    env.login("alice")  # second session
    st, r, _ = env.call("/update/password", {"token": d["token"], "current_password": PW,
                                              "new_password": "new-pass-123", "client_ip": IP})
    assert st == 200 and r["ok"] is True
    assert env.q("SELECT COUNT(*) FROM sessions WHERE uid=? AND revoked_at IS NULL", (d["pid"],))[0][0] == 0
    assert PW_HASH_RE.fullmatch(env.q("SELECT password_hash FROM users WHERE user_id='alice'")[0][0])
    assert re.search(r"\[PASSWORD_CHANGE\] subject=alice", env.logtext())
    assert env.attempt("login_user:alice") is None
    assert env.attempt(f"login_ip:{IP}") is None
    assert env.login("alice", "new-pass-123")[0] == 200


def test_H1b_client_ip_missing_before_token_check(env):
    d = env.user("alice")
    st, r, _ = env.call("/update/password", {"token": d["token"], "current_password": PW, "new_password": "new-pass-123"})
    assert st == 400 and r == {"ok": False, "error": "A01", "field": "client_ip"}
    st, r, _ = env.call("/update/password", {"token": "bad-token", "current_password": PW, "new_password": "new-pass-123"})
    assert st == 400 and r.get("field") == "client_ip"


def test_H2_short_new_password(env):
    d = env.user("alice")
    before = env.q("SELECT password_hash FROM users WHERE user_id='alice'")
    st, r, _ = env.call("/update/password", {"token": d["token"], "current_password": "WRONG-current-1",
                                              "new_password": "short", "client_ip": IP})
    assert st == 400 and err(r) == "A12" and r["field"] == "new_password"
    assert env.attempts_all() == []
    assert env.q("SELECT password_hash FROM users WHERE user_id='alice'") == before


def test_H2b_current_password_too_long(env):
    d = env.user("alice")
    st, r, _ = env.call("/update/password", {"token": d["token"], "current_password": "p" * 257,
                                              "new_password": "new-pass-123", "client_ip": IP})
    assert st == 400 and err(r) == "A12" and r["field"] == "current_password"
    assert env.attempts_all() == []


def _reauth_body(tok, cur):
    return {"token": tok, "current_password": cur, "new_password": "new-pass-123", "client_ip": IP}


def test_H3_wrong_current_counts_and_logs(env):
    d = env.user("alice")
    st, r, _ = env.call("/update/password", _reauth_body(d["token"], "wrong-current-1"))
    assert (st, err(r)) == (401, "A03")
    assert env.attempt("login_user:alice")[0] == 1
    assert env.attempt(f"login_ip:{IP}")[0] == 1
    assert re.search(rf"\[LOGIN_NG\] subject=alice ip={re.escape(IP)} detail=reason=reauth", env.logtext())
    assert env.verify(d["token"])["active"] is True


def test_H3_five_reauth_failures_lock_login_too(env):
    d = env.user("alice")
    for _ in range(DEFAULT.account_lock_threshold):
        assert env.call("/update/password", _reauth_body(d["token"], "wrong-current-1"))[0] == 401
    assert env.attempt("login_user:alice")[2] is not None
    assert env.login("alice", PW)[0] == 429
    assert re.search(r"\[LOCKOUT\] subject=login_user:alice", env.logtext())


def test_H3b_login_lock_blocks_reauth(env):
    d = env.user("alice")
    env.set_attempt("login_user:alice", DEFAULT.account_lock_threshold, locked_until=T0 + 900)
    snap = env.attempts_all()
    st, r, _ = env.call("/update/password", _reauth_body(d["token"], PW))
    assert (st, err(r)) == (429, "A11")
    assert env.attempts_all() == snap
    assert env.q("SELECT revoked_at FROM sessions WHERE uid=?", (d["pid"],))[0][0] is None


def test_H3c_ip_lock_blocks_reauth(env):
    d = env.user("alice")
    env.set_attempt(f"login_ip:{IP}", DEFAULT.ip_fail_threshold, locked_until=T0 + 900)
    snap = env.attempts_all()
    st, r, _ = env.call("/update/password", _reauth_body(d["token"], PW))
    assert (st, err(r)) == (429, "A11")
    assert env.attempts_all() == snap


def test_H3d_gauge_blocks_reauth(tmp_path):
    e = Env(tmp_path)
    d = e.user("alice")
    g = e.new_service(policy=fast(hash_busy_ratio=0.0, hash_window_sec=5.0))
    assert e.login("nobody", "whatever-pass", svc=g)[0] == 401
    snap = e.attempts_all()
    st, r, _ = e.call("/update/password", _reauth_body(d["token"], PW), svc=g)
    assert (st, err(r)) == (429, "A11")
    assert e.attempts_all() == snap
    assert e.verify(d["token"], svc=g)["active"] is True


def test_H4_legacy_user_password_change(tmp_path):
    e = Env(tmp_path)
    e.insert_legacy("legacy_bob", "legacy-pass-9")
    d = e.login("legacy_bob", "legacy-pass-9")[1]
    # login already upgraded; force legacy again to exercise the update path
    e.insert_legacy("legacy_old", "legacy-pass-9")
    d2 = e.login("legacy_old", "legacy-pass-9")[1]
    st, r, _ = e.call("/update/password", {"token": d2["token"], "current_password": "legacy-pass-9",
                                            "new_password": "new-pass-123", "client_ip": IP})
    assert st == 200
    h = e.q("SELECT password_hash FROM users WHERE user_id='legacy_old'")[0][0]
    assert PW_HASH_RE.fullmatch(h)


def test_H5_public_name_html_rejected(env):
    d = env.user("alice")
    st, r, _ = env.call("/update/public-name", {"token": d["token"], "public_name": "<b>x</b>"})
    assert st == 400 and err(r) == "A12" and r["field"] == "public_name"


def test_H6_public_name_stripped_and_logged(env):
    d = env.user("carol")
    st, r, _ = env.call("/update/public-name", {"token": d["token"], "public_name": "  Carol  "})
    assert st == 200 and r == {"ok": True, "public_name": "Carol"}
    assert env.verify(d["token"])["public_name"] == "Carol"
    assert re.search(r"\[PUBLIC_NAME_CHANGE\] subject=carol", env.logtext())


# ===================================================================== P
def _group_env(env):
    owner = env.user("owner1")
    member = env.user("member1")
    outsider = env.user("outsider")
    st, _, _ = env.call("/permissions/group/create", {"token": owner["token"], "group_id": "g1", "name": "Group1"})
    assert st == 200
    return owner, member, outsider


def _upsert(env, owner, user_id, level, group="g1"):
    return env.call("/permissions/group/member/upsert",
                    {"token": owner["token"], "group_id": group, "user_id": user_id, "level": level})


def test_P1_create_logged_owner_100(env):
    owner, *_ = _group_env(env)
    st, r, _ = env.call("/permissions/group/auth", {"token": owner["token"], "group_id": "g1", "pid": owner["pid"]})
    assert r["level"] == 100
    assert re.search(r"\[GROUP_CREATE\] subject=g1 .*detail=by=owner1", env.logtext())


@pytest.mark.parametrize("gid,ok", [("g 1", False), ("-g", False), ("a" * 65, False), ("team:admin", True)])
def test_P2_group_id_pattern(env, gid, ok):
    d = env.user("owner1")
    st, r, _ = env.call("/permissions/group/create", {"token": d["token"], "group_id": gid, "name": "Name"})
    if ok:
        assert st == 200
    else:
        assert st == 400 and err(r) == "A12" and r["field"] == "group_id"


def test_P2b_group_name_rules(env):
    d = env.user("owner1")
    st, r, _ = env.call("/permissions/group/create", {"token": d["token"], "group_id": "g9", "name": "<b>x</b>"})
    assert st == 400 and err(r) == "A12" and r["field"] == "name"


def test_P3_level_bool_rejected(env):
    owner, member, _ = _group_env(env)
    st, r, _ = _upsert(env, owner, "member1", True)
    assert st == 400 and err(r) == "A12" and r["field"] == "level"
    st, r, _ = env.call("/permissions/group/auth", {"token": owner["token"], "group_id": "g1", "pid": member["pid"]})
    assert r["level"] == 0


@pytest.mark.parametrize("lv", [101, -1, "7", None])
def test_P4_level_invalid(env, lv):
    owner, *_ = _group_env(env)
    st, r, _ = _upsert(env, owner, "member1", lv)
    assert st == 400 and err(r) == "A12" and r["field"] == "level"


def test_P4b_level_boundaries_ok(env):
    owner, *_ = _group_env(env)
    assert _upsert(env, owner, "member1", 1)[0] == 200
    assert _upsert(env, owner, "member1", 100)[0] == 200


def test_P5_non_owner_upsert_delete_403(env):
    owner, member, outsider = _group_env(env)
    _upsert(env, owner, "member1", 7)
    for who in (member, outsider):
        st, r, _ = env.call("/permissions/group/member/upsert",
                            {"token": who["token"], "group_id": "g1", "user_id": "outsider", "level": 5})
        assert (st, err(r)) == (403, "A13")
        st, r, _ = env.call("/permissions/group/member/delete",
                            {"token": who["token"], "group_id": "g1", "user_id": "member1"})
        assert (st, err(r)) == (403, "A13")


def test_P6_upsert_unknown_group(env):
    owner, *_ = _group_env(env)
    st, r, _ = _upsert(env, owner, "member1", 5, group="nogroup")
    assert st == 400 and err(r) == "A12" and r["field"] == "group_id"


def test_P7_group_delete_permissions_and_log(env):
    owner, member, _ = _group_env(env)
    _upsert(env, owner, "member1", 7)
    before = env.logtext()
    st, r, _ = env.call("/permissions/group/delete", {"token": member["token"], "group_id": "g1"})
    assert (st, err(r)) == (403, "A13")
    assert "GROUP_DELETE" not in env.logtext()
    st, r, _ = env.call("/permissions/group/delete", {"token": owner["token"], "group_id": "g1"})
    assert st == 200
    assert re.search(r"\[GROUP_DELETE\] subject=g1 .*detail=by=owner1", env.logtext())


def test_A12_delete_missing_group(env):
    d = env.user("owner1")
    st, r, _ = env.call("/permissions/group/delete", {"token": d["token"], "group_id": "ghostgroup"})
    assert st == 400 and err(r) == "A12" and r.get("field") == "group_id"


def test_P8_group_auth_self_nonmember_level0(env):
    owner, member, outsider = _group_env(env)
    st, r, _ = env.call("/permissions/group/auth", {"token": outsider["token"], "group_id": "g1", "pid": outsider["pid"]})
    assert st == 200 and r["level"] == 0


def test_P9_member_can_query_others(env):
    owner, member, outsider = _group_env(env)
    _upsert(env, owner, "member1", 7)
    st, r, _ = env.call("/permissions/group/auth", {"token": member["token"], "group_id": "g1", "pid": owner["pid"]})
    assert st == 200 and r["level"] == 100


def test_P10_nonmember_cannot_query_others(env):
    owner, member, outsider = _group_env(env)
    st, r, _ = env.call("/permissions/group/auth", {"token": outsider["token"], "group_id": "g1", "pid": owner["pid"]})
    assert (st, err(r)) == (403, "A13")


def test_P11_nonexistent_group(env):
    owner, member, outsider = _group_env(env)
    st, r, _ = env.call("/permissions/group/auth", {"token": outsider["token"], "group_id": "nogroup", "pid": outsider["pid"]})
    assert st == 200 and r["level"] == 0
    st, r, _ = env.call("/permissions/group/auth", {"token": outsider["token"], "group_id": "nogroup", "pid": owner["pid"]})
    assert (st, err(r)) == (403, "A13")


def test_P12_upsert_delete_logs(env):
    owner, *_ = _group_env(env)
    _upsert(env, owner, "member1", 7)
    assert re.search(r"\[PERM_UPSERT\] subject=g1 .*detail=by=owner1 target=member1 level=7", env.logtext())
    st, _, _ = env.call("/permissions/group/member/delete", {"token": owner["token"], "group_id": "g1", "user_id": "member1"})
    assert st == 200
    assert re.search(r"\[PERM_DELETE\] subject=g1 .*detail=by=owner1 target=member1", env.logtext())


# ===================================================================== M
def test_M1_self_heal_and_single_master(tmp_path):
    e = Env(tmp_path)
    e.signup("alice")
    e.q("UPDATE users SET is_active=0, is_master=0 WHERE user_id='master_user'")
    e.q("UPDATE users SET is_master=1 WHERE user_id='alice'")
    old_hash = e.q("SELECT password_hash FROM users WHERE user_id='master_user'")[0][0]
    e.new_service()
    assert e.q("SELECT is_active, is_master FROM users WHERE user_id='master_user'")[0] == (1, 1)
    assert e.q("SELECT is_master FROM users WHERE user_id='alice'")[0][0] == 0
    assert e.q("SELECT password_hash FROM users WHERE user_id='master_user'")[0][0] == old_hash
    assert e.login("master_user", MASTER_PW, ip="127.0.0.1")[0] == 200


def test_M2_no_master_no_password_fails_closed(tmp_path):
    with pytest.raises(AuthServiceUnavailableError):
        AuthService(str(tmp_path / "a.db"), str(tmp_path / "a.log"), master_login_password="", policy=fast())


def test_M3_weak_master_password_fails_startup(tmp_path):
    with pytest.raises(AuthInvalidFieldError) as ei:
        AuthService(str(tmp_path / "a.db"), str(tmp_path / "a.log"), master_login_password="short", policy=fast())
    assert ei.value.field == "master_login_password"


def test_M3_master_created_with_v2_hash(tmp_path):
    e = Env(tmp_path)
    row = e.q("SELECT is_master, is_active, created_at, password_hash FROM users WHERE user_id='master_user'")[0]
    assert row[0] == 1 and row[1] == 1 and row[2] is not None and PW_HASH_RE.fullmatch(row[3])


def test_M4_master_list(env):
    env.user("alice")
    t = env.master_token()
    st, r, _ = env.call("/master/users/list", {"token": t})
    assert st == 200 and r["ok"] is True
    ids = [u.get("user_id") for u in r["users"]]
    assert "alice" in ids and "master_user" in ids


def test_M5_non_master_list_403(env):
    d = env.user("alice")
    st, r, _ = env.call("/master/users/list", {"token": d["token"]})
    assert (st, err(r)) == (403, "A13")


def _deact(env, tok, target, pw=MASTER_PW, path="/master/users/deactivate", ip=IP):
    return env.call(path, {"token": tok, "target_user_id": target, "login_password": pw, "client_ip": ip})


def test_M6_deactivate_ok(env):
    c = env.user("carol")
    t = env.master_token()
    st, r, _ = _deact(env, t, "carol")
    assert st == 200
    assert env.q("SELECT is_active FROM users WHERE user_id='carol'")[0][0] == 0
    assert env.q("SELECT COUNT(*) FROM sessions WHERE uid=? AND revoked_at IS NULL", (c["pid"],))[0][0] == 0
    assert re.search(r"\[MASTER_DEACTIVATE\] subject=carol .*detail=by=master_user", env.logtext())
    assert env.attempt("login_user:master_user") is None
    assert env.attempt(f"login_ip:{IP}") is None


def test_M7_wrong_login_password(env):
    env.user("carol")
    t = env.master_token()
    st, r, _ = _deact(env, t, "carol", pw="wrong-master-pw")
    assert (st, err(r)) == (401, "A03")
    assert env.attempt("login_user:master_user")[0] == 1
    assert env.attempt(f"login_ip:{IP}")[0] == 1
    assert env.q("SELECT is_active FROM users WHERE user_id='carol'")[0][0] == 1
    assert re.search(rf"\[LOGIN_NG\] subject=master_user ip={re.escape(IP)} detail=reason=reauth", env.logtext())


def test_M7_five_failures_lock_master_login(env):
    env.user("carol")
    t = env.master_token()
    for _ in range(DEFAULT.account_lock_threshold):
        assert _deact(env, t, "carol", pw="wrong-master-pw")[0] == 401
    assert env.login("master_user", MASTER_PW, ip="127.0.0.1")[0] == 429


def test_M7b_locked_blocks_reauth_even_when_correct(env):
    env.user("carol")
    t = env.master_token()
    env.set_attempt("login_user:master_user", DEFAULT.account_lock_threshold, locked_until=T0 + 900)
    snap = env.attempts_all()
    st, r, _ = _deact(env, t, "carol")
    assert (st, err(r)) == (429, "A11")
    assert env.attempts_all() == snap
    assert env.q("SELECT is_active FROM users WHERE user_id='carol'")[0][0] == 1


def test_M7b_ip_lock_blocks(env):
    env.user("carol")
    t = env.master_token()
    env.set_attempt(f"login_ip:{IP}", DEFAULT.ip_fail_threshold, locked_until=T0 + 900)
    assert _deact(env, t, "carol")[0] == 429


def test_M7b_gauge_blocks(tmp_path):
    e = Env(tmp_path)
    e.user("carol")
    t = e.master_token()
    g = e.new_service(policy=fast(hash_busy_ratio=0.0, hash_window_sec=5.0))
    assert e.login("nobody", "whatever-pass", svc=g)[0] == 401
    st, r, _ = e.call("/master/users/deactivate", {"token": t, "target_user_id": "carol",
                                                     "login_password": MASTER_PW, "client_ip": IP}, svc=g)
    assert (st, err(r)) == (429, "A11")
    assert e.q("SELECT is_active FROM users WHERE user_id='carol'")[0][0] == 1


def test_M7c_login_password_too_long(env):
    env.user("carol")
    t = env.master_token()
    st, r, _ = _deact(env, t, "carol", pw="p" * 257)
    assert st == 400 and err(r) == "A12" and r["field"] == "login_password"
    assert env.attempts_all() == []


def test_M8_legacy_master_password_key(env):
    env.user("carol")
    t = env.master_token()
    st, r, _ = env.call("/master/users/deactivate", {"token": t, "target_user_id": "carol",
                                                      "master_password": "NexomWebFramework"})
    assert st == 400 and r == {"ok": False, "error": "A01", "field": "login_password"}
    assert env.q("SELECT is_active FROM users WHERE user_id='carol'")[0][0] == 1


def test_M9_cannot_deactivate_self(env):
    t = env.master_token()
    st, r, _ = _deact(env, t, "master_user")
    assert (st, err(r)) == (403, "A13")
    assert env.q("SELECT is_active FROM users WHERE user_id='master_user'")[0][0] == 1


def test_M10_unknown_target(env):
    t = env.master_token()
    st, r, _ = _deact(env, t, "ghost-user")
    assert st == 400 and err(r) == "A12" and r["field"] == "target_user_id"


def test_M11_activate(env):
    c = env.user("carol")
    t = env.master_token()
    _deact(env, t, "carol")
    st, r, _ = _deact(env, t, "carol", path="/master/users/activate")
    assert st == 200
    assert env.q("SELECT is_active FROM users WHERE user_id='carol'")[0][0] == 1
    assert env.verify(c["token"]) == {"active": False}
    assert re.search(r"\[MASTER_ACTIVATE\] subject=carol .*detail=by=master_user", env.logtext())
    assert env.login("carol")[0] == 200


def test_M12_non_master_deactivate_403_before_reauth(env):
    env.user("carol")
    d = env.user("alice")
    for path in ("/master/users/deactivate", "/master/users/activate"):
        st, r, _ = _deact(env, d["token"], "carol", pw=PW, path=path)
        assert (st, err(r)) == (403, "A13")
    assert env.attempts_all() == []
    assert env.q("SELECT is_active FROM users WHERE user_id='carol'")[0][0] == 1


# ===================================================================== U
def test_U1_valid_pid(tmp_path):
    pid = secrets.token_urlsafe(24)
    UserDatabaseManager(str(tmp_path), pid)
    assert (tmp_path / f"{pid}.db").exists()


@pytest.mark.parametrize("pid", ["../../x", "abc", "a" * 65, "abc/def" + "x" * 20, "a" * 15, "..%2f" + "a" * 20])
def test_U2_invalid_pid(tmp_path, pid):
    with pytest.raises(AuthInvalidFieldError) as ei:
        UserDatabaseManager(str(tmp_path), pid)
    assert ei.value.field == "pid"
    assert list(tmp_path.iterdir()) == []


def test_U2_boundary_lengths(tmp_path):
    UserDatabaseManager(str(tmp_path), "a" * 16)
    UserDatabaseManager(str(tmp_path), "b" * 64)


# ===================================================================== migration
def _make_v1(db_path: str):
    con = sqlite3.connect(db_path)
    con.executescript(
        """
        CREATE TABLE users (uid TEXT PRIMARY KEY, user_id TEXT UNIQUE NOT NULL, public_name TEXT NOT NULL,
          password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          is_active INTEGER NOT NULL DEFAULT 1, is_master INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE sessions (sid TEXT PRIMARY KEY, uid TEXT NOT NULL REFERENCES users(uid),
          token_hash TEXT UNIQUE NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER, user_agent TEXT);
        """
    )
    salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", b"legacy-pass-9", bytes.fromhex(salt), 200_000).hex()
    con.execute("INSERT INTO users(uid,user_id,public_name,password_hash,password_salt) VALUES('u-old','oldie','Old',?,?)", (h, salt))
    con.execute("INSERT INTO sessions VALUES('s1','u-old','th1',?,NULL,'ua')", (T0 + 1000,))
    con.commit()
    con.close()


def test_DB_migration_v1_to_v2_idempotent(tmp_path):
    db = str(tmp_path / "auth.db")
    _make_v1(db)
    AuthDBM(db)
    AuthDBM(db)  # idempotent
    con = sqlite3.connect(db)
    try:
        cols = [r[0] for r in con.execute("SELECT name FROM pragma_table_info('sessions')")]
        assert "created_at" in cols
        assert con.execute("SELECT value FROM auth_meta WHERE key='schema_version'").fetchone()[0] == "2"
        assert con.execute("SELECT created_at FROM sessions WHERE sid='s1'").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM users WHERE user_id='oldie'").fetchone()[0] == 1
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"idx_users_user_id_nocase", "idx_sessions_uid", "idx_auth_attempts_window"} <= names
        assert con.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0] == 0
    finally:
        con.close()


def test_DB_migration_legacy_row_rehashed_on_login(tmp_path):
    db = str(tmp_path / "auth.db")
    _make_v1(db)
    svc = AuthService(db, str(tmp_path / "a.log"), master_login_password=MASTER_PW,
                      policy=AuthPolicy(hash_busy_ratio=None))
    env = Env.__new__(Env)
    env.db, env.log, env.tmp = db, str(tmp_path / "a.log"), tmp_path
    env.t = [T0]
    env.svc = svc
    st, d, _ = env.login("oldie", "legacy-pass-9") if False else env.call(
        "/login", {"user_id": "oldie", "password": "legacy-pass-9", "client_ip": IP})
    assert st == 200
    h, s = env.q("SELECT password_hash, password_salt FROM users WHERE user_id='oldie'")[0]
    assert h.startswith("pbkdf2_sha256$600000$") and s == ""


def test_DB_new_schema_tables(env):
    tables = {r[0] for r in env.q("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "sessions", "auth_meta", "auth_attempts"} <= tables
    assert env.q("SELECT value FROM auth_meta WHERE key='schema_version'")[0][0] == "2"


# ===================================================================== §8 log
def test_LOG_newline_injection_collapsed(env):
    evil = "evil\n[2026-01-01] [LOGIN_OK] subject=admin ip=1.1.1.1"
    env.login(evil, "whatever-pass")
    text = env.logtext()
    for line in text.splitlines():
        assert line.startswith("["), repr(line)
    assert not re.search(r"^\[[^\]]*\] \[LOGIN_OK\] subject=admin", text, re.M)


def test_LOG_no_password_or_token_in_log(env):
    d = env.user("alice", "super-secret-pw-77")
    env.login("alice", "wrong-secret-pw-88")
    env.call("/logout", {"token": d["token"]})
    text = env.logtext()
    assert "super-secret-pw-77" not in text and "wrong-secret-pw-88" not in text
    assert d["token"] not in text


# ===================================================================== X is_same_origin
def _req(headers):
    return Request(make_environ(method="POST", path="/user/login/", headers=headers))


@pytest.mark.parametrize("v", ["same-origin", "same-site", "none"])
def test_X1_sec_fetch_site_ok_ignores_others(v):
    assert is_same_origin(_req({"Sec-Fetch-Site": v, "Origin": "https://evil.example", "Host": "app.example"})) is True


def test_X2_cross_site():
    assert is_same_origin(_req({"Sec-Fetch-Site": "cross-site", "Origin": "https://app.example", "Host": "app.example"})) is False


def test_X3_origin_matches_host():
    assert is_same_origin(_req({"Origin": "https://app.example", "Host": "app.example"})) is True
    assert is_same_origin(_req({"Origin": "https://APP.example", "Host": "app.example"})) is True


def test_X4_origin_mismatch():
    assert is_same_origin(_req({"Origin": "https://evil.example", "Host": "app.example"})) is False


def test_X5_origin_null():
    assert is_same_origin(_req({"Origin": "null", "Host": "app.example"})) is False


def test_X6_referer():
    assert is_same_origin(_req({"Referer": "https://app.example/user/login/", "Host": "app.example"})) is True
    assert is_same_origin(_req({"Referer": "https://evil.example/", "Host": "app.example"})) is False


def test_X7_no_headers_true():
    assert is_same_origin(_req({"Host": "app.example"})) is True


def test_X8_origin_without_host_false():
    req = Request(make_environ(method="POST", path="/", headers={"Origin": "https://app.example"}))
    req.environ.pop("HTTP_HOST", None)
    assert is_same_origin(req) is False


# ===================================================================== C AuthClient
class _Srv:
    def __init__(self, fn):
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                outer.requests.append((self.path, body))
                status, headers, data = fn(self.path, body)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve():
    servers = []

    def _mk(fn):
        s = _Srv(fn)
        servers.append(s)
        return s

    yield _mk
    for s in servers:
        s.close()


def _js(obj, status=200):
    return (status, {"Content-Type": "application/json"}, json.dumps(obj).encode())


def _login_call(c):
    return c.login(user_id="alice", password=PW, client_ip=IP)


def test_C0_login_happy_path(serve):
    ok = {"ok": True, "pid": "p" * 20, "user_id": "alice", "public_name": "A", "token": "t" * 43,
          "expires_at": 123, "user_agent": None}
    s = serve(lambda p, b: _js(ok))
    sess = _login_call(AuthClient(s.url))
    assert sess.token == "t" * 43 and sess.user_agent is None
    sent = json.loads(s.requests[0][1])
    assert sent["client_ip"] == IP and sent["user_id"] == "alice"


def test_C1_missing_keys_a09(serve):
    s = serve(lambda p, b: _js({"ok": True}))
    with pytest.raises(AuthServiceUnavailableError):
        _login_call(AuthClient(s.url))


@pytest.mark.parametrize("data", [b"[1,2,3]", b"<html>nope</html>", b"", b'"str"'])
def test_C2_non_object_a09(serve, data):
    s = serve(lambda p, b: (200, {"Content-Type": "application/json"}, data))
    with pytest.raises(AuthServiceUnavailableError):
        _login_call(AuthClient(s.url))


def test_C3_redirect_not_followed(serve):
    ok = {"ok": True, "pid": "p" * 20, "user_id": "alice", "public_name": "A", "token": "t" * 43,
          "expires_at": 123, "user_agent": None}

    def fn(path, body):
        if path == "/elsewhere":
            return _js(ok)
        return (302, {"Location": "/elsewhere"}, b"")

    s = serve(fn)
    with pytest.raises(AuthServiceUnavailableError):
        _login_call(AuthClient(s.url))
    assert all(p != "/elsewhere" for p, _ in s.requests)


def test_C4_verify_user_agent_none_preserved(serve):
    s = serve(lambda p, b: _js({"active": True, "pid": "p" * 20, "user_id": "alice", "public_name": "A",
                                "expires_at": 99, "user_agent": None}))
    sess = AuthClient(s.url).verify_token("tok")
    assert sess is not None and sess.user_agent is None


def test_C4b_verify_inactive_is_none(serve):
    s = serve(lambda p, b: _js({"active": False}))
    assert AuthClient(s.url).verify_token("tok") is None


def test_C5_error_code_mapping(serve):
    s = serve(lambda p, b: _js({"ok": False, "error": "A12", "field": "password"}, 400))
    with pytest.raises(AuthInvalidFieldError) as ei:
        _login_call(AuthClient(s.url))
    assert ei.value.field == "password"
    s2 = serve(lambda p, b: _js({"ok": False, "error": "A11"}, 429))
    with pytest.raises(AuthTooManyAttemptsError):
        _login_call(AuthClient(s2.url))
    s3 = serve(lambda p, b: _js({"ok": False, "error": "A13"}, 403))
    with pytest.raises(AuthForbiddenError):
        _login_call(AuthClient(s3.url))


@pytest.mark.parametrize("code,status", [("A99", 400), ("HTTP_502", 502)])
def test_C6_unknown_code_a09(serve, code, status):
    s = serve(lambda p, b: _js({"ok": False, "error": code}, status))
    with pytest.raises(AuthServiceUnavailableError):
        _login_call(AuthClient(s.url))


def test_C7_resolve_pid_removed():
    assert not hasattr(AuthClient("http://127.0.0.1:1"), "resolve_pid")


def test_C8_client_ip_required_keyword():
    c = AuthClient("http://127.0.0.1:1")
    with pytest.raises(TypeError):
        c.login(user_id="a", password="b")
    with pytest.raises(TypeError):
        c.signup(user_id="a", public_name="A", password="b")
    with pytest.raises(TypeError):
        c.update_password(token="t", current_password="a", new_password="b")
    with pytest.raises(TypeError):
        c.master_users_deactivate(token="t", target_user_id="a", login_password="b")
    with pytest.raises(TypeError):
        c.master_users_activate(token="t", target_user_id="a", login_password="b")
    with pytest.raises(TypeError):
        c.master_users_deactivate(token="t", target_user_id="a", master_password="b", client_ip=IP)


def test_C9_connection_refused_and_timeout(serve):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(AuthServiceUnavailableError):
        _login_call(AuthClient(f"http://127.0.0.1:{port}"))

    def slow(path, body):
        time.sleep(1.0)
        return _js({"ok": True})

    s = serve(slow)
    with pytest.raises(AuthServiceUnavailableError):
        _login_call(AuthClient(s.url, timeout=0.2))


# ===================================================================== K AuthPages
class _Quiet(WSGIRequestHandler):
    def log_message(self, *a):
        pass


@pytest.fixture
def live(tmp_path):
    e = Env(tmp_path)
    e.svc = AuthService(e.db, e.log, master_login_password=MASTER_PW, policy=fast())  # real clock

    def app(environ, start_response):
        res = e.svc.handler(environ)
        start_response(res.status_text, res.headers)
        return [res.body]

    httpd = make_server("127.0.0.1", 0, app, handler_class=_Quiet)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    e.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield e
    httpd.shutdown()
    httpd.server_close()


def _page_post(pages, path, body=None, *, ct=JSON_CT, headers=None, raw=None, method="POST"):
    data = raw if raw is not None else json.dumps(body if body is not None else {}).encode()
    req = Request(make_environ(method=method, path=path, body=data, content_type=ct, headers=headers))
    res = pages.call_handler(req, {})
    try:
        payload = json.loads(res.body.decode())
    except Exception:
        payload = None
    return res, payload


def _hdrs(res, name):
    return [v for k, v in res.headers if k.lower() == name.lower()]


def _pages(live, ip=lambda r: IP):
    return AuthPages("user/", live.url, client_ip=ip)


def _real_signup(live, uid="alice", pw=PW):
    st, _, _ = live.call("/signup", {"user_id": uid, "public_name": uid.title(), "password": pw, "client_ip": IP})
    assert st == 201


def test_K1_login_cookie_and_body(live):
    _real_signup(live)
    res, d = _page_post(_pages(live), "/user/login/", {"user_id": "alice", "password": PW})
    assert res.status_code == 200
    assert d["ok"] is True and d["user_id"] == "alice" and "public_name" in d and "expires_at" in d
    assert "token" not in d
    sc = _hdrs(res, "Set-Cookie")
    assert len(sc) == 1
    m = re.fullmatch(r"_nxt=([A-Za-z0-9_-]{43}); Max-Age=(\d+); Path=/; Secure; HttpOnly; SameSite=Lax", sc[0])
    assert m, sc[0]
    ttl = 60 * 60 * 24 * 7
    assert ttl - 30 <= int(m.group(2)) <= ttl
    assert m.group(1) not in res.body.decode()
    # not an absolute epoch
    assert int(m.group(2)) < 10 ** 8
    assert live.verify(m.group(1))["active"] is True


def test_K2_logout_json_deletes_cookie_and_revokes(live):
    _real_signup(live)
    tok = live.login("alice")[1]["token"]
    res, d = _page_post(_pages(live), "/user/logout/", {}, headers={"Cookie": f"_nxt={tok}"})
    assert res.status_code == 200 and d == {"ok": True}
    sc = _hdrs(res, "Set-Cookie")
    assert len(sc) == 1 and sc[0].startswith("_nxt=; Max-Age=0") and "Path=/" in sc[0]
    assert live.verify(tok) == {"active": False}


def test_K3_logout_form_redirects_root_ignoring_referer(live):
    _real_signup(live)
    tok = live.login("alice")[1]["token"]
    res, _ = _page_post(_pages(live), "/user/logout/", raw=b"", ct="application/x-www-form-urlencoded",
                        headers={"Cookie": f"_nxt={tok}", "Referer": "https://evil.example/x"})
    assert res.status_code == 302
    assert _hdrs(res, "Location") == ["/"]
    assert _hdrs(res, "Set-Cookie")[0].startswith("_nxt=; Max-Age=0")
    assert live.verify(tok) == {"active": False}


def test_K4_logout_get_405_allow_post(live):
    _real_signup(live)
    tok = live.login("alice")[1]["token"]
    req = Request(make_environ(method="GET", path="/user/logout/", headers={"Cookie": f"_nxt={tok}"}))
    res = _pages(live).call_handler(req, {})
    assert res.status_code == 405
    assert json.loads(res.body.decode()) == {"ok": False, "error": "MethodNotAllowed"}
    assert _hdrs(res, "Allow") == ["POST"]
    assert _hdrs(res, "Set-Cookie") == []
    assert live.verify(tok)["active"] is True


def test_K5_logout_without_cookie_idempotent(live):
    res, d = _page_post(_pages(live), "/user/logout/", {})
    assert res.status_code == 200 and d == {"ok": True}
    assert _hdrs(res, "Set-Cookie")[0].startswith("_nxt=; Max-Age=0")


def test_K6_logout_backend_down_still_clears_cookie(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    pages = AuthPages("user/", f"http://127.0.0.1:{port}", client_ip=lambda r: IP)
    res, d = _page_post(pages, "/user/logout/", {}, headers={"Cookie": "_nxt=" + "a" * 43})
    assert res.status_code == 503 and d == {"ok": False, "error": "A09"}
    assert _hdrs(res, "Set-Cookie")[0].startswith("_nxt=; Max-Age=0")


def test_K7_login_errors_passthrough(live):
    _real_signup(live)
    pages = _pages(live)
    res, d = _page_post(pages, "/user/login/", {"user_id": "alice", "password": "p" * 257})
    assert res.status_code == 400 and d == {"ok": False, "error": "A12", "field": "password"}
    assert _hdrs(res, "Set-Cookie") == []
    for _ in range(DEFAULT.account_lock_threshold):
        r, d = _page_post(pages, "/user/login/", {"user_id": "alice", "password": "wrong-password-1"})
        assert r.status_code == 401
    res, d = _page_post(pages, "/user/login/", {"user_id": "alice", "password": PW})
    assert res.status_code == 429 and d == {"ok": False, "error": "A11"}
    assert _hdrs(res, "Set-Cookie") == []


def test_K8_login_form_body_rejected(live):
    res, d = _page_post(_pages(live), "/user/login/", raw=b"user_id=alice&password=x",
                        ct="application/x-www-form-urlencoded")
    assert res.status_code == 400 and d == {"ok": False, "error": "A01", "field": "body"}


def test_K9_get_pages_html(live):
    for p in ("/user/login/", "/user/signup/"):
        res = _pages(live).call_handler(Request(make_environ(method="GET", path=p)), {})
        assert res.status_code == 200
        assert b"<html" in res.body.lower() or b"<!doctype" in res.body.lower()


def test_K10_unknown_path_raises_not_found(live):
    with pytest.raises(PathNotFoundError):
        _pages(live).call_handler(Request(make_environ(method="GET", path="/user/unknown/")), {})


def test_K11_signup_via_pages(live):
    res, d = _page_post(_pages(live), "/user/signup/",
                        {"user_id": "carol", "public_name": "Carol", "password": "carol-pass-1"})
    assert res.status_code == 201 and d == {"ok": True}
    assert live.attempt(f"signup_ip:{IP}")[0] == 1


def test_K12_client_ip_default_uses_request_client_ip(live):
    _real_signup(live)
    pages = AuthPages("user/", live.url)  # client_ip=None -> req.client_ip (REMOTE_ADDR=127.0.0.1 here)
    res, d = _page_post(pages, "/user/login/", {"user_id": "alice", "password": "wrong-password-1"})
    assert res.status_code == 401
    assert live.attempt("login_ip:127.0.0.1")[0] == 1
    assert live.attempt(f"login_ip:{IP}") is None


def test_K_callable_client_ip_is_used(live):
    _real_signup(live)
    res, d = _page_post(_pages(live, ip=lambda r: "198.51.100.77"), "/user/login/",
                        {"user_id": "alice", "password": "wrong-password-1"})
    assert res.status_code == 401
    assert live.attempt("login_ip:198.51.100.77")[0] == 1


@pytest.mark.parametrize("path", ["/user/login/", "/user/signup/", "/user/logout/"])
def test_X_cross_site_post_forbidden(live, path):
    _real_signup(live)
    tok = live.login("alice")[1]["token"]
    body = {"user_id": "zed", "public_name": "Z", "password": PW, "token": tok}
    res, d = _page_post(_pages(live), path, body, headers={"Sec-Fetch-Site": "cross-site", "Cookie": f"_nxt={tok}"})
    assert res.status_code == 403 and d == {"ok": False, "error": "A13"}
    assert live.verify(tok)["active"] is True
    assert live.q("SELECT COUNT(*) FROM users WHERE user_id='zed'")[0][0] == 0


def test_X_foreign_origin_post_forbidden(live):
    _real_signup(live)
    res, d = _page_post(_pages(live), "/user/login/", {"user_id": "alice", "password": PW},
                        headers={"Origin": "https://evil.example", "Host": "app.example"})
    assert res.status_code == 403 and err(d) == "A13"
    res, d = _page_post(_pages(live), "/user/login/", {"user_id": "alice", "password": PW},
                        headers={"Origin": "https://app.example", "Host": "app.example"})
    assert res.status_code == 200


# ===================================================================== W / §6 templates
def _gen_auth(tmp_path: Path, proxy_count: int | None = None):
    from nexom.buildTools.build import create_auth

    root = create_auth(tmp_path)
    if proxy_count is not None:
        cfg = root / "config.py"
        txt = cfg.read_text(encoding="utf-8")
        assert "TRUSTED_PROXY_COUNT: int = 0" in txt
        cfg.write_text(txt.replace("TRUSTED_PROXY_COUNT: int = 0", f"TRUSTED_PROXY_COUNT: int = {proxy_count}"),
                       encoding="utf-8")
    return root


def test_T6_template_config_contract(tmp_path):
    root = _gen_auth(tmp_path)
    cfg = (root / "config.py").read_text(encoding="utf-8")
    assert "MASTER_PASSWORD" not in cfg
    assert "TRUSTED_PROXY_COUNT: int = 0" in cfg
    assert 'ALLOWED_CLIENTS: tuple[str, ...] | None = ("127.0.0.1", "::1")' in cfg
    assert "TRUSTED_PROXIES" not in cfg
    wsgi = (root / "wsgi.py").read_text(encoding="utf-8")
    assert "master_password" not in wsgi and "NexomWebFramework" not in wsgi + cfg


@pytest.fixture
def gen_wsgi(tmp_path):
    saved = dict(sys.modules)

    def _load(proxy_count=None):
        root = _gen_auth(tmp_path, proxy_count)
        pkg = root.name
        sys.path.insert(0, str(root.parent))
        for m in [m for m in sys.modules if m == pkg or m.startswith(pkg + ".")]:
            del sys.modules[m]
        import importlib

        cfg = importlib.import_module(f"{pkg}.config")
        wsgi = importlib.import_module(f"{pkg}.wsgi")
        return cfg, wsgi

    yield _load
    for m in [m for m in sys.modules if m not in saved]:
        del sys.modules[m]
    if sys.path and str(tmp_path) == sys.path[0]:
        sys.path.pop(0)


def _wsgi_call(app, environ):
    out = {}

    def sr(status, headers, exc_info=None):
        out["status"] = status
        out["headers"] = headers

    body = b"".join(app(environ, sr))
    return out, body


def test_W1_exceptions_become_json_500_via_start_response(gen_wsgi):
    cfg, w = gen_wsgi()
    # bad cookie must not raise out of the app (either handled or 500 JSON through start_response)
    env_bad = make_environ(method="POST", path="/verify", body=b'{"token":"x"}', content_type=JSON_CT,
                           headers={"Cookie": "a<b=1"})
    out, body = _wsgi_call(w.app, env_bad)
    assert "status" in out and int(out["status"].split()[0]) in range(200, 600)

    # forced internal failure
    def boom(environ):
        raise RuntimeError("boom-test")

    w.service.handler = boom
    out, body = _wsgi_call(w.app, make_environ(method="POST", path="/verify", body=b"{}", content_type=JSON_CT))
    assert out["status"].startswith("500")
    assert json.loads(body) == {"ok": False, "error": "InternalError"}
    err_text = Path(cfg.ERR_LOG).read_text(encoding="utf-8")
    assert "boom-test" in err_text or "RuntimeError" in err_text


def test_W2_access_log_line(gen_wsgi):
    cfg, w = gen_wsgi()
    _wsgi_call(w.app, make_environ(method="POST", path="/verify", body=b'{"token":"x"}', content_type=JSON_CT,
                                   headers={"User-Agent": "UA-test"}))
    text = Path(cfg.ACES_LOG).read_text(encoding="utf-8")
    assert re.search(r'127\.0\.0\.1 "POST /verify" 200 \d+(\.\d+)?ms "UA-test"', text), text


def test_W3_xff_ignored_when_no_trusted_proxy(gen_wsgi):
    cfg, w = gen_wsgi(proxy_count=0)
    _wsgi_call(w.app, make_environ(method="POST", path="/verify", body=b'{"token":"x"}', content_type=JSON_CT,
                                   headers={"X-Forwarded-For": "1.2.3.4"}))
    text = Path(cfg.ACES_LOG).read_text(encoding="utf-8")
    assert "127.0.0.1" in text and "1.2.3.4" not in text


def test_W3_xff_rightmost_when_one_proxy(gen_wsgi):
    cfg, w = gen_wsgi(proxy_count=1)
    _wsgi_call(w.app, make_environ(method="POST", path="/verify", body=b'{"token":"x"}', content_type=JSON_CT,
                                   headers={"X-Forwarded-For": "6.6.6.6, 1.2.3.4"}))
    text = Path(cfg.ACES_LOG).read_text(encoding="utf-8")
    assert "1.2.3.4" in text and "6.6.6.6" not in text


# ===================================================================== policy surface
def test_policy_defaults_match_doc():
    p = AuthPolicy()
    assert p.pbkdf2_iterations == 600_000 and p.account_lock_threshold == 5
    assert p.account_window_sec == 900 and p.account_lock_sec == 900
    assert p.ip_fail_threshold == 30 and p.signup_ip_threshold == 10 and p.signup_window_sec == 3600
    assert p.hash_busy_ratio == 0.5 and p.hash_window_sec == 1.0 and p.max_sessions_per_user == 20
    assert p.password_min_len == 8 and p.password_max_bytes == 256 and p.public_name_max_len == 64
    assert dataclasses.is_dataclass(p)
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.pbkdf2_iterations = 1  # type: ignore[misc]

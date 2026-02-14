from __future__ import annotations

import json

from nexom.app.auth import AuthService, AuthDBM
from nexom.app.request import Request

from conftest import make_environ


def _json_response(res) -> dict:
    return json.loads(res.body.decode("utf-8"))


def test_auth_service_signup_login_verify(tmp_path):
    db_path = tmp_path / "auth.db"
    log_path = tmp_path / "auth.log"
    svc = AuthService(str(db_path), str(log_path))

    # signup
    body = json.dumps({"user_id": "u1", "public_name": "User", "password": "pw"}).encode("utf-8")
    env = make_environ(method="POST", path="/signup", body=body, content_type="application/json")
    res = svc.handler(env)
    assert res.status_code == 201
    assert _json_response(res)["ok"] is True

    # login
    body = json.dumps({"user_id": "u1", "password": "pw"}).encode("utf-8")
    env = make_environ(method="POST", path="/login", body=body, content_type="application/json")
    res = svc.handler(env)
    data = _json_response(res)
    assert res.status_code == 200
    assert data["ok"] is True
    token = data["token"]

    # verify
    body = json.dumps({"token": token}).encode("utf-8")
    env = make_environ(method="POST", path="/verify", body=body, content_type="application/json")
    res = svc.handler(env)
    data = _json_response(res)
    assert data["active"] is True


def test_auth_dbm_basic(tmp_path):
    db_path = tmp_path / "auth.db"
    dbm = AuthDBM(str(db_path))
    dbm.signup(user_id="u2", public_name="User2", password="pw2")
    sess = dbm.login("u2", "pw2", user_agent="ua", ttl_sec=60)
    assert sess.user_id == "u2"
    v = dbm.verify(sess.token)
    assert v is not None
    dbm.logout(sess.token)
    assert dbm.verify(sess.token) is None

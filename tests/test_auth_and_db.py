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


def test_auth_service_update_public_name(tmp_path):
    db_path = tmp_path / "auth.db"
    log_path = tmp_path / "auth.log"
    svc = AuthService(str(db_path), str(log_path))

    body = json.dumps({"user_id": "u3", "public_name": "User3", "password": "pw3"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/signup", body=body, content_type="application/json"))
    assert res.status_code == 201

    body = json.dumps({"user_id": "u3", "password": "pw3"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    token = _json_response(res)["token"]

    body = json.dumps({"token": token, "public_name": "Renamed"}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/update/public-name", body=body, content_type="application/json")
    )
    data = _json_response(res)
    assert res.status_code == 200
    assert data["ok"] is True
    assert data["public_name"] == "Renamed"

    body = json.dumps({"token": token}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/verify", body=body, content_type="application/json"))
    assert _json_response(res)["public_name"] == "Renamed"


def test_auth_service_update_password_revokes_sessions(tmp_path):
    db_path = tmp_path / "auth.db"
    log_path = tmp_path / "auth.log"
    svc = AuthService(str(db_path), str(log_path))

    body = json.dumps({"user_id": "u4", "public_name": "User4", "password": "pw4"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/signup", body=body, content_type="application/json"))
    assert res.status_code == 201

    body = json.dumps({"user_id": "u4", "password": "pw4"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    token = _json_response(res)["token"]

    body = json.dumps(
        {"token": token, "current_password": "pw4", "new_password": "pw4new"}
    ).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/update/password", body=body, content_type="application/json")
    )
    assert res.status_code == 200
    assert _json_response(res)["ok"] is True

    # old token is revoked
    body = json.dumps({"token": token}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/verify", body=body, content_type="application/json"))
    assert _json_response(res)["active"] is False

    # old password fails
    body = json.dumps({"user_id": "u4", "password": "pw4"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    assert res.status_code == 401

    # new password succeeds
    body = json.dumps({"user_id": "u4", "password": "pw4new"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    assert res.status_code == 200

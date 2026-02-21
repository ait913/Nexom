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
    svc = AuthService(str(db_path), str(log_path), master_login_password="master_login_pw")

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
    svc = AuthService(str(db_path), str(log_path), master_login_password="master_login_pw")

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
    svc = AuthService(str(db_path), str(log_path), master_login_password="master_login_pw")

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


def test_permissions_group_flow(tmp_path):
    db_path = tmp_path / "auth.db"
    log_path = tmp_path / "auth.log"
    svc = AuthService(str(db_path), str(log_path), master_login_password="master_login_pw")

    # owner signup/login
    body = json.dumps({"user_id": "owner", "public_name": "Owner", "password": "pw"}).encode("utf-8")
    svc.handler(make_environ(method="POST", path="/signup", body=body, content_type="application/json"))
    body = json.dumps({"user_id": "owner", "password": "pw"}).encode("utf-8")
    owner_login = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    owner_data = _json_response(owner_login)
    owner_token = owner_data["token"]
    owner_pid = owner_data["pid"]
    owner_user_id = owner_data["user_id"]

    # member signup/login
    body = json.dumps({"user_id": "member", "public_name": "Member", "password": "pw"}).encode("utf-8")
    svc.handler(make_environ(method="POST", path="/signup", body=body, content_type="application/json"))
    body = json.dumps({"user_id": "member", "password": "pw"}).encode("utf-8")
    member_login = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    member_data = _json_response(member_login)
    member_pid = member_data["pid"]
    member_user_id = member_data["user_id"]

    # create group (owner gets level=100 automatically)
    body = json.dumps({"token": owner_token, "group_id": "g1", "name": "Group1"}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/create", body=body, content_type="application/json")
    )
    assert res.status_code == 200

    # owner has level 100 by default
    body = json.dumps({"token": owner_token, "group_id": "g1", "pid": owner_pid}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/auth", body=body, content_type="application/json")
    )
    assert _json_response(res)["level"] == 100

    # upsert member level
    body = json.dumps({"token": owner_token, "group_id": "g1", "user_id": member_user_id, "level": 7}).encode("utf-8")
    res = svc.handler(
        make_environ(
            method="POST",
            path="/permissions/group/member/upsert",
            body=body,
            content_type="application/json",
        )
    )
    assert res.status_code == 200

    # auth lookup
    body = json.dumps({"token": owner_token, "group_id": "g1", "pid": member_pid}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/auth", body=body, content_type="application/json")
    )
    assert _json_response(res)["level"] == 7

    # owner has level 100
    body = json.dumps({"token": owner_token, "group_id": "g1", "pid": owner_pid}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/auth", body=body, content_type="application/json")
    )
    assert _json_response(res)["level"] == 100

    # level > 100 should fail
    body = json.dumps({"token": owner_token, "group_id": "g1", "user_id": member_user_id, "level": 101}).encode("utf-8")
    res = svc.handler(
        make_environ(
            method="POST",
            path="/permissions/group/member/upsert",
            body=body,
            content_type="application/json",
        )
    )
    assert res.status_code == 400

    # groups mine
    body = json.dumps({"token": member_data["token"]}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/groups/mine", body=body, content_type="application/json")
    )
    groups = _json_response(res)["groups"]
    assert any(g["group_id"] == "g1" and g["level"] == 7 for g in groups)

    # delete by user_id
    body = json.dumps({"token": owner_token, "group_id": "g1", "user_id": member_user_id}).encode("utf-8")
    res = svc.handler(
        make_environ(
            method="POST",
            path="/permissions/group/member/delete",
            body=body,
            content_type="application/json",
        )
    )
    assert res.status_code == 200

    body = json.dumps({"token": owner_token, "group_id": "g1", "pid": member_pid}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/auth", body=body, content_type="application/json")
    )
    assert _json_response(res)["level"] == 0

    # non-100 user cannot delete group
    body = json.dumps({"token": member_data["token"], "group_id": "g1"}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/delete", body=body, content_type="application/json")
    )
    assert res.status_code == 401

    # owner(100) can delete group
    body = json.dumps({"token": owner_token, "group_id": "g1"}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/delete", body=body, content_type="application/json")
    )
    assert res.status_code == 200
    assert _json_response(res)["ok"] is True

    # group is gone
    body = json.dumps({"token": owner_token, "group_id": "g1", "pid": member_pid}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/auth", body=body, content_type="application/json")
    )
    assert _json_response(res)["level"] == 0


def test_master_users_list_and_deactivate(tmp_path):
    db_path = tmp_path / "auth.db"
    log_path = tmp_path / "auth.log"
    svc = AuthService(
        str(db_path),
        str(log_path),
        master_user="master_user",
        master_login_password="master_login_pw",
        master_password="NexomWebFramework",
    )

    # login as master
    body = json.dumps({"user_id": "master_user", "password": "master_login_pw"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    assert res.status_code == 200
    master_token = _json_response(res)["token"]

    # create normal user
    body = json.dumps({"user_id": "u5", "public_name": "User5", "password": "pw5"}).encode("utf-8")
    svc.handler(make_environ(method="POST", path="/signup", body=body, content_type="application/json"))

    # list all users
    body = json.dumps({"token": master_token}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/master/users/list", body=body, content_type="application/json"))
    users = _json_response(res)["users"]
    assert any(u["user_id"] == "master_user" for u in users)
    assert any(u["user_id"] == "u5" for u in users)

    # deactivate user
    body = json.dumps(
        {"token": master_token, "target_user_id": "u5", "master_password": "NexomWebFramework"}
    ).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/master/users/deactivate", body=body, content_type="application/json")
    )
    assert res.status_code == 200
    assert _json_response(res)["ok"] is True

    # deactivated user cannot login
    body = json.dumps({"user_id": "u5", "password": "pw5"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    assert res.status_code == 403


def test_auth_service_convert_user_id_and_pid(tmp_path):
    db_path = tmp_path / "auth.db"
    log_path = tmp_path / "auth.log"
    svc = AuthService(str(db_path), str(log_path), master_login_password="master_login_pw")

    body = json.dumps({"user_id": "u6", "public_name": "User6", "password": "pw6"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/signup", body=body, content_type="application/json"))
    assert res.status_code == 201

    body = json.dumps({"user_id": "u6", "password": "pw6"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    login_data = _json_response(res)
    token = login_data["token"]
    pid = login_data["pid"]

    body = json.dumps({"token": token, "pid": pid}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/convert/user-id", body=body, content_type="application/json"))
    data = _json_response(res)
    assert res.status_code == 200
    assert data["ok"] is True
    assert data["user_id"] == "u6"

    body = json.dumps({"token": token, "user_id": "u6"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/convert/pid", body=body, content_type="application/json"))
    data = _json_response(res)
    assert res.status_code == 200
    assert data["ok"] is True
    assert data["pid"] == pid

    # token-less resolve user_id -> pid
    body = json.dumps({"user_id": "u6"}).encode("utf-8")
    res = svc.handler(make_environ(method="POST", path="/resolve/pid", body=body, content_type="application/json"))
    data = _json_response(res)
    assert res.status_code == 200
    assert data["ok"] is True
    assert data["pid"] == pid


def test_permission_group_duplicate_returns_permission_error(tmp_path):
    db_path = tmp_path / "auth.db"
    log_path = tmp_path / "auth.log"
    svc = AuthService(str(db_path), str(log_path), master_login_password="master_login_pw")

    body = json.dumps({"user_id": "owner2", "public_name": "Owner2", "password": "pw"}).encode("utf-8")
    svc.handler(make_environ(method="POST", path="/signup", body=body, content_type="application/json"))
    body = json.dumps({"user_id": "owner2", "password": "pw"}).encode("utf-8")
    owner_login = svc.handler(make_environ(method="POST", path="/login", body=body, content_type="application/json"))
    owner_token = _json_response(owner_login)["token"]

    body = json.dumps({"token": owner_token, "group_id": "dup_g", "name": "Group"}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/create", body=body, content_type="application/json")
    )
    assert res.status_code == 200

    body = json.dumps({"token": owner_token, "group_id": "dup_g", "name": "Group2"}).encode("utf-8")
    res = svc.handler(
        make_environ(method="POST", path="/permissions/group/create", body=body, content_type="application/json")
    )
    data = _json_response(res)
    assert res.status_code == 409
    assert data["error"] == "A10"

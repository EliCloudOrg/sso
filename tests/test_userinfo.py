"""/userinfo 的 scope 过滤与 GET/POST 支持（docs/sso-oidc.md §2.6、§7）。

B2 决策的回归防线：**只返回标准 ``preferred_username``，不返回 ``username``**。
"""

from __future__ import annotations

from sqlalchemy import select

from app.db import session_scope
from app.models import User
from tests.helpers import (
    REDIRECT_URI,
    make_public_client,
    make_user,
    obtain_code,
    pkce_pair,
    unique,
)
from tests.test_token import token_request


def get_access_token(client, *, scopes: list[str], scope: str, with_email: bool = False) -> tuple[str, str]:
    """走完整授权码流程拿 access token，返回 (token, 该账号的邮箱或空串)。"""
    client_id = make_public_client(client, scopes=scopes)
    # username 本身就唯一，用它派生邮箱避免撞 users.email 的唯一约束
    username, _ = make_user(client)
    email = f"{username}@example.com" if with_email else ""
    if email:
        with session_scope() as session:
            user = session.scalar(select(User).where(User.username == username))
            user.email = email
            session.commit()

    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client, client_id=client_id, username=username, verifier=verifier, challenge=challenge, scope=scope
    )
    tokens = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    ).json()
    return tokens["access_token"], email


def token_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_userinfo_returns_sub_and_preferred_username(client):
    token, _ = get_access_token(client, scopes=["openid", "profile"], scope="openid profile")
    response = client.get("/v1/userinfo", headers=token_headers(token))
    assert response.status_code == 200

    body = response.json()
    assert body["sub"].startswith("user_")
    assert body["preferred_username"]
    # B2：不再返回非标准的 username
    assert "username" not in body


def test_userinfo_omits_username_without_profile_scope(client):
    token, _ = get_access_token(client, scopes=["openid"], scope="openid")
    body = client.get("/v1/userinfo", headers=token_headers(token)).json()
    assert set(body) == {"sub", "scope"}  # 只有 sub 与元信息


def test_userinfo_omits_email_without_email_scope(client):
    token, email = get_access_token(
        client, scopes=["openid", "profile"], scope="openid profile", with_email=True
    )
    assert email  # 账号确实有邮箱

    body = client.get("/v1/userinfo", headers=token_headers(token)).json()
    assert "email" not in body
    assert "email_verified" not in body


def test_userinfo_includes_email_with_email_scope(client):
    token, email = get_access_token(client, scopes=["openid", "email"], scope="openid email", with_email=True)

    body = client.get("/v1/userinfo", headers=token_headers(token)).json()
    assert body["email"] == email
    # 本平台没有邮箱验证流程 → 如实标注 false，不假装已验证
    assert body["email_verified"] is False
    # 没有 profile scope → 不给用户名
    assert "preferred_username" not in body


def test_userinfo_email_absent_when_user_has_no_email(client):
    """scope 里有 email 但账号没填邮箱 → 不返回 email（更不该返回空串）。"""
    token, _ = get_access_token(client, scopes=["openid", "email"], scope="openid email")
    body = client.get("/v1/userinfo", headers=token_headers(token)).json()
    assert "email" not in body
    assert "email_verified" not in body


def test_userinfo_accepts_post_as_well_as_get(client):
    """OIDC 要求 UserInfo 同时支持 GET 与 POST。"""
    token, _ = get_access_token(client, scopes=["openid", "profile"], scope="openid profile")

    get_body = client.get("/v1/userinfo", headers=token_headers(token)).json()
    post_response = client.post("/v1/userinfo", headers=token_headers(token))
    assert post_response.status_code == 200
    assert post_response.json() == get_body


def test_userinfo_requires_token_for_both_methods(client):
    assert client.get("/v1/userinfo").status_code == 401
    assert client.post("/v1/userinfo").status_code == 401


def test_userinfo_rejects_disabled_user(client):
    client_id = make_public_client(client, scopes=["openid"])
    username, user_id = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client, client_id=client_id, username=username, verifier=verifier, challenge=challenge, scope="openid"
    )
    access = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    ).json()["access_token"]

    with session_scope() as session:
        user = session.get(User, user_id)
        user.status = "disabled"
        session.commit()

    response = client.get("/v1/userinfo", headers=token_headers(access))
    assert response.status_code == 401

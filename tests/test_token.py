"""令牌端点（/token）的 authorization_code 分支测试：docs/sso-oidc.md §2.4a、§7。

每条校验都有一条对应的反例 —— 缺任何一条就是漏洞。
"""

from __future__ import annotations

import base64

import jwt as pyjwt
import pytest

from app.authorization import hash_authorization_code
from app.config import get_settings
from app.db import session_scope
from app.models import AuthorizationCode, RefreshToken, User
from tests.helpers import (
    PASSWORD,
    REDIRECT_URI,
    authorize_params,
    get_authorize,
    make_confidential_client,
    make_public_client,
    make_user,
    obtain_code,
    pkce_pair,
    post_login,
    redirect_query,
)


def token_request(client, data: dict[str, str], *, basic: tuple[str, str] | None = None, auth_method: str = "post"):
    """构造 /token 请求；auth_method 决定用 Basic 还是表单带凭据。"""
    form = dict(data)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if basic is not None:
        raw = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {raw}"
    return client.post("/token", data=form, headers=headers, follow_redirects=False)


# --------------------------------------------------------- 客户端认证


def test_token_requires_client_identification(client):
    response = token_request(client, {"grant_type": "authorization_code", "code": "x"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


def test_token_unknown_client(client):
    response = token_request(client, {"grant_type": "authorization_code", "code": "x", "client_id": "ghost"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


def test_public_client_must_not_send_secret(client):
    client_id = make_public_client(client)
    response = token_request(
        client,
        {"grant_type": "authorization_code", "code": "x", "client_id": client_id, "client_secret": "whatever"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


def test_confidential_client_wrong_secret_returns_401(client):
    """用 Authorization 头认证失败时按 RFC 6749 §5.2 返回 401。"""
    client_id, _ = make_confidential_client(client)
    response = token_request(
        client,
        {"grant_type": "authorization_code", "code": "x"},
        basic=(client_id, "wrong-secret"),
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert "www-authenticate" in {key.lower() for key in response.headers}


def test_confidential_client_must_use_registered_method(client):
    # 注册为 basic，却用表单提交凭据
    client_id, secret = make_confidential_client(client, auth_method="client_secret_basic")
    response = token_request(
        client,
        {"grant_type": "authorization_code", "code": "x", "client_id": client_id, "client_secret": secret},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


def test_mixing_basic_and_form_credentials_is_rejected(client):
    client_id, secret = make_confidential_client(client)
    response = token_request(
        client,
        {"grant_type": "authorization_code", "code": "x", "client_id": client_id, "client_secret": secret},
        basic=(client_id, secret),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_unsupported_and_unauthorized_grant_types(client):
    public_client = make_public_client(client)
    response = token_request(client, {"grant_type": "password", "client_id": public_client})
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"

    # 公开客户端不是 confidential，这里构造"已认证但未注册该 grant"的情况：
    # 设备码客户端未注册 authorization_code
    device_only = make_public_client(client, grant_types=["urn:ietf:params:oauth:grant-type:device_code"])
    response = token_request(
        client,
        {"grant_type": "authorization_code", "code": "x", "client_id": device_only},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"


# ------------------------------------------------------------- 正常流程


def test_authorization_code_happy_path(client, settings):
    client_id = make_public_client(client, scopes=["openid", "profile", "email"])
    username, user_id = make_user(client)
    verifier, challenge = pkce_pair()
    code, params = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"

    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == settings.access_token_ttl
    assert body["scope"] == "openid profile email"
    # 没请求 offline_access → 不发 refresh token
    assert "refresh_token" not in body

    claims = pyjwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["iss"] == settings.issuer
    # access token 的 aud 保持业务服务用的值，不被改成 client_id（§4.1）
    assert claims["aud"] == settings.audience
    assert claims["sub"] == user_id
    assert claims["client_id"] == client_id
    assert claims["scope"] == "openid profile email"


def test_offline_access_issues_refresh_token(client):
    client_id = make_public_client(client, scopes=["openid", "profile", "offline_access"])
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client,
        client_id=client_id,
        username=username,
        verifier=verifier,
        challenge=challenge,
        scope="openid profile offline_access",
    )

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200, response.text
    refresh = response.json()["refresh_token"]
    assert refresh.startswith("rt_")
    assert response.json()["scope"] == "openid profile offline_access"


def test_access_token_works_for_userinfo(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    access = response.json()["access_token"]
    info = client.get("/v1/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert info.status_code == 200
    assert info.json()["preferred_username"] == username


def test_confidential_client_can_exchange_without_pkce(client):
    client_id, secret = make_confidential_client(client)
    username, _ = make_user(client)
    # 保密客户端不强制 PKCE
    code, _ = obtain_code(client, client_id=client_id, username=username, challenge=None)

    response = token_request(
        client,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
        basic=(client_id, secret),
    )
    assert response.status_code == 200, response.text
    assert response.json()["access_token"]


def test_confidential_client_can_use_client_secret_post(client):
    client_id, secret = make_confidential_client(client, auth_method="client_secret_post")
    username, _ = make_user(client)
    code, _ = obtain_code(client, client_id=client_id, username=username, challenge=None)

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "client_secret": secret,
        },
    )
    assert response.status_code == 200, response.text


# ------------------------------------------------------------ PKCE 反例


def test_wrong_code_verifier_fails(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": "x" * 64,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_missing_code_verifier_fails(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    response = token_request(
        client,
        {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "client_id": client_id},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --------------------------------------------------------- 绑定关系反例


def test_wrong_redirect_uri_fails(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI + "/other",
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_code_from_another_client_fails(client):
    owner_id = make_public_client(client)
    other_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=owner_id, username=username, verifier=verifier, challenge=challenge)

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": other_id,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_expired_code_fails(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    with session_scope() as session:
        row = session.get(AuthorizationCode, hash_authorization_code(code))
        row.expires_at = "2020-01-01T00:00:00Z"
        session.commit()

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# ------------------------------------------------------- 一次性 / 重放


def test_code_cannot_be_used_twice(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
    }

    assert token_request(client, payload).status_code == 200
    second = token_request(client, payload)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_code_replay_revokes_derived_refresh_chain(client):
    """§7.4：已用过的码再次兑换 → 撤销它派生出的整条 refresh 链。"""
    client_id = make_public_client(client, scopes=["openid", "profile", "offline_access"])
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client,
        client_id=client_id,
        username=username,
        verifier=verifier,
        challenge=challenge,
        scope="openid profile offline_access",
    )
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
    }

    first = token_request(client, payload)
    assert first.status_code == 200
    refresh = first.json()["refresh_token"]

    replay = token_request(client, payload)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    from app.security import hash_refresh_token

    with session_scope() as session:
        row = session.query(RefreshToken).filter(RefreshToken.token_hash == hash_refresh_token(refresh)).one()
        assert row.revoked_at is not None  # 派生的链被撤销
        assert row.client_id == client_id
        assert row.scope == "openid profile offline_access"


def test_failed_exchange_burns_the_code(client):
    """一次性：即使兑换失败（verifier 错），该码也不能再被使用（防在线试错）。"""
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    wrong = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": "y" * 64,
        },
    )
    assert wrong.status_code == 400

    # 正确的 verifier 也不能再兑换
    retry = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert retry.status_code == 400
    assert retry.json()["error"] == "invalid_grant"


def test_disabled_user_cannot_exchange(client):
    client_id = make_public_client(client)
    username, user_id = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)

    with session_scope() as session:
        user = session.get(User, user_id)
        user.status = "disabled"
        session.commit()

    response = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# ------------------------------------------------------------------ 其他


def test_missing_grant_type(client):
    response = token_request(client, {"client_id": "x"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_token_errors_are_not_cacheable(client):
    response = token_request(client, {"grant_type": "authorization_code", "code": "x", "client_id": "ghost"})
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("use_basic", [True, False])
def test_confidential_client_both_methods_work(client, use_basic):
    method = "client_secret_basic" if use_basic else "client_secret_post"
    client_id, secret = make_confidential_client(client, auth_method=method)
    username, _ = make_user(client)
    code, _ = obtain_code(client, client_id=client_id, username=username, challenge=None)

    if use_basic:
        response = token_request(
            client,
            {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
            basic=(client_id, secret),
        )
    else:
        response = token_request(
            client,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "client_secret": secret,
            },
        )
    assert response.status_code == 200, response.text

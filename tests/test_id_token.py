"""id_token 测试（docs/sso-oidc.md §4.2、§11）。

最容易搞混的一点：**id_token 的 aud 是 client_id，access token 的 aud 是业务 audience**。
"""

from __future__ import annotations

import json

import jwt as pyjwt
import pytest
from jwt.algorithms import RSAAlgorithm

from tests.helpers import (
    REDIRECT_URI,
    make_public_client,
    make_user,
    obtain_code,
    pkce_pair,
)
from tests.test_token import token_request


def exchange(client, client_id: str, code: str, verifier: str | None):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
    }
    if verifier:
        data["code_verifier"] = verifier
    return token_request(client, data)


def get_tokens(client, *, scopes: list[str], scope: str, email: str | None = None) -> tuple[dict, str, str]:
    client_id = make_public_client(client, scopes=scopes)
    username, user_id = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client,
        client_id=client_id,
        username=username,
        verifier=verifier,
        challenge=challenge,
        scope=scope,
    )
    response = exchange(client, client_id, code, verifier)
    assert response.status_code == 200, response.text
    return response.json(), client_id, username


def decode_with_jwks(client, token: str, *, audience: str):
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    header = pyjwt.get_unverified_header(token)
    jwk = next(key for key in keys if key["kid"] == header["kid"])
    return pyjwt.decode(
        token,
        RSAAlgorithm.from_jwk(json.dumps(jwk)),
        algorithms=["RS256"],
        audience=audience,
        issuer=client.app.state.settings.issuer,
    )


def test_id_token_issued_with_client_audience(client, settings):
    tokens, client_id, username = get_tokens(
        client, scopes=["openid", "profile", "email"], scope="openid profile email"
    )
    assert "id_token" in tokens

    claims = decode_with_jwks(client, tokens["id_token"], audience=client_id)
    assert claims["iss"] == settings.issuer
    assert claims["aud"] == client_id  # ← 与 access token 不同
    assert claims["sub"].startswith("user_")
    assert claims["preferred_username"] == username
    assert claims["auth_time"] > 0
    assert claims["exp"] - claims["iat"] == settings.id_token_ttl
    # 一期不实现这些（§13）
    assert "at_hash" not in claims
    assert "c_hash" not in claims


def test_access_token_keeps_service_audience_while_id_token_uses_client(client, settings):
    tokens, client_id, _ = get_tokens(client, scopes=["openid"], scope="openid")

    access = pyjwt.decode(tokens["access_token"], options={"verify_signature": False})
    id_token = pyjwt.decode(tokens["id_token"], options={"verify_signature": False})

    assert access["aud"] == settings.audience  # 业务服务按它校验，不能被改成 client_id
    assert id_token["aud"] == client_id
    assert access["client_id"] == client_id


def test_nonce_is_echoed_into_id_token(client):
    client_id = make_public_client(client, scopes=["openid"])
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client,
        client_id=client_id,
        username=username,
        verifier=verifier,
        challenge=challenge,
        scope="openid",
        nonce="nonce-from-client",
    )
    tokens = exchange(client, client_id, code, verifier).json()
    claims = pyjwt.decode(tokens["id_token"], options={"verify_signature": False})
    assert claims["nonce"] == "nonce-from-client"


def test_nonce_absent_when_not_requested(client):
    client_id = make_public_client(client, scopes=["openid"])
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client,
        client_id=client_id,
        username=username,
        verifier=verifier,
        challenge=challenge,
        scope="openid",
        nonce=None,
    )
    tokens = exchange(client, client_id, code, verifier).json()
    claims = pyjwt.decode(tokens["id_token"], options={"verify_signature": False})
    assert "nonce" not in claims


def test_id_token_claims_follow_scope(client):
    # 只给 openid：没有 preferred_username / email
    tokens, _, _ = get_tokens(client, scopes=["openid"], scope="openid")
    claims = pyjwt.decode(tokens["id_token"], options={"verify_signature": False})
    assert "preferred_username" not in claims
    assert "email" not in claims
    assert "username" not in claims  # B2：非标准名不出现


def test_id_token_includes_email_and_email_verified_false(client):
    client_id = make_public_client(client, scopes=["openid", "email"])
    username, _ = make_user(client)
    from app.db import session_scope
    from app.models import User
    from sqlalchemy import select

    with session_scope() as session:
        user = session.scalar(select(User).where(User.username == username))
        user.email = f"{username}@example.com"
        session.commit()

    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client, client_id=client_id, username=username, verifier=verifier, challenge=challenge, scope="openid email"
    )
    tokens = exchange(client, client_id, code, verifier).json()
    claims = pyjwt.decode(tokens["id_token"], options={"verify_signature": False})

    assert claims["email"] == f"{username}@example.com"
    # 本平台没有邮箱验证流程 → 如实标注 false，不假装已验证
    assert claims["email_verified"] is False
    assert "preferred_username" not in claims


def test_id_token_cannot_be_used_as_access_token(client):
    """id_token 的 aud 是 client_id，业务 API 必须拒绝它。"""
    tokens, _, _ = get_tokens(client, scopes=["openid"], scope="openid")
    response = client.get("/v1/userinfo", headers={"Authorization": f"Bearer {tokens['id_token']}"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_id_token_kid_matches_jwks(client):
    tokens, _, _ = get_tokens(client, scopes=["openid"], scope="openid")
    header = pyjwt.get_unverified_header(tokens["id_token"])
    kids = {key["kid"] for key in client.get("/.well-known/jwks.json").json()["keys"]}
    assert header["kid"] in kids


def test_authorize_requires_openid_so_id_token_is_always_issued(client):
    """§2.3 要求 scope 必须含 openid，因此授权码流程**总是**会拿到 id_token。

    这条顺带证明了"不带 openid 的纯 OAuth2 请求会被拒绝"，而不是静默地不发 id_token。
    """
    client_id = make_public_client(client, scopes=["pdf:read"])
    _username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": "pdf:read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "error=invalid_scope" in response.headers["location"]


@pytest.mark.parametrize("ttl", [120, 600])
def test_id_token_ttl_follows_config(client, ttl):
    settings = client.app.state.settings
    original = settings.id_token_ttl
    settings.id_token_ttl = ttl
    try:
        tokens, _, _ = get_tokens(client, scopes=["openid"], scope="openid")
        claims = pyjwt.decode(tokens["id_token"], options={"verify_signature": False})
        assert claims["exp"] - claims["iat"] == ttl
    finally:
        settings.id_token_ttl = original

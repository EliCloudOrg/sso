"""SSO 全链路与契约测试。

覆盖验收标准（docs/architecture.md §0.7）：
注册 → 登录 → userinfo → refresh 轮换 → 重放整链撤销 → logout → JWKS/OIDC 契约 →
RS256 白名单（拒绝 HS256 与 alg:none）→ 限流 → 密钥持久化。

conftest.py 在导入期就写好了环境变量，因此这里可以安全地在模块顶层 import app。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select

from app.config import get_settings
from app.db import session_scope
from app.keys import KeyStore, reset_keystore_cache, save_public_key
from app.models import User
from app.security import decode_access_token

PASSWORD = "S3cret!pass1"


def unique_username(prefix: str = "user") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def register(client, username: str | None = None, password: str = PASSWORD, email: str | None = None):
    username = username or unique_username()
    body: dict[str, str] = {"username": username, "password": password}
    if email:
        body["email"] = email
    response = client.post("/v1/register", json=body)
    return response, username


def login(client, username: str, password: str = PASSWORD):
    return client.post("/v1/login", json={"username": username, "password": password})


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def public_pem_from_jwks(client) -> bytes:
    jwks = client.get("/.well-known/jwks.json").json()
    key = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --------------------------------------------------------------- 契约 / 发现


def test_jwks_is_anonymous_and_publishes_rs256_key(client, settings):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"

    payload = response.json()
    assert payload["keys"], "JWKS 不能为空"
    key = payload["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"] == settings.jwt_kid
    assert key["n"] and key["e"] == "AQAB"


def test_openid_configuration_derives_from_public_base_url(client, settings):
    response = client.get("/.well-known/openid-configuration")
    assert response.status_code == 200

    payload = response.json()
    assert payload["issuer"] == settings.public_base_url == "http://127.0.0.1:8000/auth"
    assert payload["jwks_uri"] == f"{settings.public_base_url}/.well-known/jwks.json"
    assert payload["userinfo_endpoint"] == f"{settings.public_base_url}/userinfo"
    assert payload["id_token_signing_alg_values_supported"] == ["RS256"]


def test_service_routes_have_no_auth_prefix(client):
    """服务内只有 /v1/* 与 /.well-known/*；/auth/* 属于网关。"""
    for path in ("/auth/v1/login", "/auth/login", "/v1/auth/login"):
        assert client.post(path, json={}).status_code == 404


# ------------------------------------------------------------------- 全链路


def test_full_flow_register_login_userinfo_refresh_logout(client, settings):
    response, username = register(client, email=f"{unique_username('mail')}@example.com")
    assert response.status_code == 201, response.text
    created = response.json()["user"]
    assert created["id"].startswith("user_")
    assert created["username"] == username
    assert "password" not in created and "password_hash" not in created

    # 登录
    response = login(client, username)
    assert response.status_code == 200, response.text
    tokens = response.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] == settings.access_token_ttl
    assert tokens["scope"] == settings.default_scope
    assert tokens["refresh_token"].startswith("rt_")
    assert tokens["user"]["id"] == created["id"]
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Access Token 的 claim 契约：iss / aud / sub / username / scope / iat / exp
    claims = pyjwt.decode(access_token, options={"verify_signature": False})
    assert claims["iss"] == settings.issuer
    assert claims["aud"] == settings.audience
    assert claims["sub"] == created["id"]
    assert claims["username"] == username
    assert claims["scope"] == settings.default_scope
    assert claims["exp"] > claims["iat"]

    # 业务服务视角：用 JWKS 里的公钥独立验签（含 kid 匹配）
    header = pyjwt.get_unverified_header(access_token)
    jwks = client.get("/.well-known/jwks.json").json()
    jwk = next(key for key in jwks["keys"] if key["kid"] == header["kid"])
    verified = pyjwt.decode(
        access_token,
        pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk)),
        algorithms=["RS256"],
        audience=settings.audience,
        issuer=settings.issuer,
    )
    assert verified["sub"] == created["id"]

    # userinfo
    response = client.get("/v1/userinfo", headers=auth_header(access_token))
    assert response.status_code == 200
    info = response.json()
    assert info["sub"] == created["id"]
    # B2 决策：只返回标准 preferred_username（不再返回非标准的 username）
    assert info["preferred_username"] == username
    assert "username" not in info
    assert info["scope"] == settings.default_scope

    # refresh：轮换出新的 refresh_token
    response = client.post("/v1/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200, response.text
    rotated = response.json()
    assert rotated["refresh_token"] != refresh_token
    new_refresh_token = rotated["refresh_token"]

    # 旧 refresh_token 已被使用 → 重放判定 → 整链撤销
    replay = client.post("/v1/refresh", json={"refresh_token": refresh_token})
    assert replay.status_code == 401
    assert replay.json()["error"] == "invalid_grant"

    # 链上更新的那个也必须失效
    assert client.post("/v1/refresh", json={"refresh_token": new_refresh_token}).status_code == 401

    # 重新登录仍然正常。
    # 注意：私有 POST /v1/logout 已按 docs/sso-oidc.md §1.3 的 A3 决策下线，
    # 注销统一走标准 RP-Initiated Logout —— 见 tests/test_logout.py。
    fresh = login(client, username).json()
    assert fresh["access_token"] and fresh["refresh_token"].startswith("rt_")


# ------------------------------------------------------------------- 注册


def test_register_duplicate_username_returns_409(client):
    response, username = register(client)
    assert response.status_code == 201

    duplicate = client.post("/v1/register", json={"username": username, "password": PASSWORD})
    assert duplicate.status_code == 409
    assert duplicate.json()["error"] == "user_exists"

    # 仅大小写不同也算冲突
    duplicate = client.post("/v1/register", json={"username": username.upper(), "password": PASSWORD})
    assert duplicate.status_code == 409


@pytest.mark.parametrize(
    "password",
    [
        "short1",  # 太短
        "alllettersonly",  # 缺数字
        "12345678",  # 缺字母且是常见口令
        "ab",  # 太短
    ],
)
def test_register_rejects_weak_password(client, password):
    response, _ = register(client, password=password)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_register_rejects_bad_username_and_email(client):
    assert client.post("/v1/register", json={"username": "a b", "password": PASSWORD}).status_code == 400

    response = client.post(
        "/v1/register",
        json={"username": unique_username(), "password": PASSWORD, "email": "nope"},
    )
    assert response.status_code == 400


def test_register_duplicate_email_returns_409(client):
    email = f"{unique_username('dup')}@example.com"
    assert register(client, email=email)[0].status_code == 201

    response = client.post(
        "/v1/register",
        json={"username": unique_username(), "password": PASSWORD, "email": email},
    )
    assert response.status_code == 409


def test_registration_can_be_disabled_by_config(client):
    settings = get_settings()
    original = settings.allow_registration
    settings.allow_registration = False
    try:
        response, _ = register(client)
        assert response.status_code == 403
        assert response.json()["error"] == "registration_disabled"
    finally:
        settings.allow_registration = original


# ------------------------------------------------------------------- 登录


def test_login_failure_does_not_leak_user_existence(client):
    _, username = register(client)

    wrong_password = login(client, username, "WrongPass123")
    unknown_user = login(client, unique_username("ghost"), PASSWORD)

    assert wrong_password.status_code == unknown_user.status_code == 401
    # 「用户不存在」与「密码错误」必须给出完全相同的响应
    assert wrong_password.json() == unknown_user.json() == {
        "error": "invalid_grant",
        "error_description": "用户名或密码错误",
    }


def test_disabled_user_cannot_login(client):
    _, username = register(client)

    with session_scope() as session:
        user = session.scalar(select(User).where(User.username == username))
        user.status = "disabled"
        session.commit()

    assert login(client, username).status_code == 401


def test_login_is_rate_limited_per_ip_and_username(client, settings):
    _, username = register(client)
    limit = settings.login_attempts_per_window

    for _ in range(limit):
        assert login(client, username, "WrongPass123").status_code == 401

    blocked = login(client, username, "WrongPass123")
    assert blocked.status_code == 429
    assert blocked.json()["error"] == "too_many_requests"
    assert "retry-after" in {key.lower() for key in blocked.headers}


def test_successful_login_resets_failure_counter(client, settings):
    _, username = register(client)

    for _ in range(settings.login_attempts_per_window - 1):
        assert login(client, username, "WrongPass123").status_code == 401
    assert login(client, username).status_code == 200
    # 成功后计数清零，还能继续失败而不是马上 429
    assert login(client, username, "WrongPass123").status_code == 401


# --------------------------------------------------------------- 令牌安全


def test_userinfo_requires_valid_bearer(client):
    assert client.get("/v1/userinfo").status_code == 401
    assert client.get("/v1/userinfo", headers=auth_header("not-a-jwt")).status_code == 401
    assert client.get("/v1/userinfo", headers={"Authorization": "Basic YWJjOmRlZg=="}).status_code == 401


def _raw_token(header: dict, claims: dict, signature: bytes) -> str:
    def segment(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signing_input = f"{segment(header)}.{segment(claims)}"
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def _forged_none_token(settings) -> str:
    return _raw_token(
        {"alg": "none", "typ": "JWT"},
        {
            "iss": settings.issuer,
            "sub": "user_0001",
            "username": "attacker",
            "aud": settings.audience,
        },
        b"",
    )


def _forged_hs256_token(settings, claims: dict, secret: bytes, kid: str) -> str:
    """手工构造 HS256 令牌。

    新版 PyJWT 会拒绝把非对称 PEM 当 HMAC 密钥（`InvalidKeyError`），
    但真实攻击者不受这个保护约束，所以这里自己按 JWS 规则算签名。
    """
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}

    def segment(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signing_input = f"{segment(header)}.{segment(claims)}"
    signature = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return _raw_token(header, claims, signature)


def test_alg_none_and_hs256_are_rejected(client, settings):
    _, username = register(client)
    access_token = login(client, username).json()["access_token"]
    claims = pyjwt.decode(access_token, options={"verify_signature": False})

    # 1) alg: none
    assert client.get("/v1/userinfo", headers=auth_header(_forged_none_token(settings))).status_code == 401

    # 2) HS256 —— 拿公开的公钥 PEM 当 HMAC 密钥（经典算法混淆攻击）
    public_pem = public_pem_from_jwks(client)
    forged = _forged_hs256_token(settings, claims, public_pem, settings.jwt_kid)
    response = client.get("/v1/userinfo", headers=auth_header(forged))
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"

    # 3) 未知 kid（即使算法正确也拒绝）
    unknown_kid = _forged_hs256_token(settings, claims, public_pem, "nope")
    assert client.get("/v1/userinfo", headers=auth_header(unknown_kid)).status_code == 401

    # 4) 合法令牌本身必须能通过，确保上面拒绝的是算法/密钥而不是别的原因
    assert client.get("/v1/userinfo", headers=auth_header(access_token)).status_code == 200


def test_expired_token_is_rejected(client):
    settings = get_settings()
    _, username = register(client)
    original_ttl = settings.access_token_ttl
    settings.access_token_ttl = -5  # 立刻过期
    try:
        expired = login(client, username).json()["access_token"]
    finally:
        settings.access_token_ttl = original_ttl

    assert client.get("/v1/userinfo", headers=auth_header(expired)).status_code == 401


def test_tokens_survive_key_reload(client, settings):
    """私钥持久化：重新从磁盘加载密钥后，此前签发的令牌依然有效。"""
    _, username = register(client)
    token = login(client, username).json()["access_token"]
    assert client.get("/v1/userinfo", headers=auth_header(token)).status_code == 200

    reloaded = KeyStore.load(settings)
    assert reloaded.signing_kid == settings.jwt_kid
    assert decode_access_token(settings, reloaded, token)["username"] == username


def test_jwks_publishes_retired_keys_after_rotation(client, settings):
    """密钥轮换后新旧公钥必须并存，否则轮换瞬间所有业务服务验签失败。"""
    retired_path = Path(settings.jwt_keys_dir) / "2025-01.public.pem"
    save_public_key(retired_path, KeyStore.load(settings).signing_public_key)
    reset_keystore_cache()  # 让 JWKS 端点重新从磁盘读密钥目录
    try:
        kids = {key["kid"] for key in client.get("/.well-known/jwks.json").json()["keys"]}
        assert {settings.jwt_kid, "2025-01"} <= kids
    finally:
        retired_path.unlink(missing_ok=True)
        reset_keystore_cache()

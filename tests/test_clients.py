"""客户端静态注册与管理接口测试（docs/sso-oidc.md §5、§7.1、§7.8）。"""

from __future__ import annotations

import secrets

from app.config import get_settings
from app.constants import (
    AUTH_METHOD_BASIC,
    AUTH_METHOD_NONE,
    CLIENT_TYPE_CONFIDENTIAL,
    CLIENT_TYPE_PUBLIC,
    GRANT_AUTHORIZATION_CODE,
    GRANT_DEVICE_CODE,
    GRANT_REFRESH_TOKEN,
)

ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token-not-a-real-secret"}


def unique_client_id(prefix: str = "client") -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def make_client(
    client,
    *,
    client_id: str | None = None,
    name: str = "Test Client",
    client_type: str = CLIENT_TYPE_PUBLIC,
    redirect_uris: list[str] | None = None,
    allowed_scopes: list[str] | None = None,
    **extra,
):
    body = {
        "client_id": client_id or unique_client_id(),
        "name": name,
        "client_type": client_type,
        "redirect_uris": ["https://example.com/callback"] if redirect_uris is None else redirect_uris,
        "allowed_scopes": ["openid", "profile", "email"] if allowed_scopes is None else allowed_scopes,
    }
    body.update(extra)
    return client.post("/v1/clients", json=body, headers=ADMIN_HEADERS)


# ------------------------------------------------------------ 管理接口鉴权


def test_admin_endpoints_require_token(client):
    assert client.get("/v1/clients").status_code == 401
    assert client.get("/v1/clients", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/v1/clients", json={}).status_code == 401


def test_admin_endpoints_disabled_when_token_unset(client):
    """未配置 ADMIN_TOKEN 时必须整体关闭（fail closed），而不是放行。"""
    settings = get_settings()
    original = settings.admin_token
    settings.admin_token = None
    try:
        response = client.get("/v1/clients", headers=ADMIN_HEADERS)
        assert response.status_code == 403
        assert response.json()["error"] == "admin_disabled"
    finally:
        settings.admin_token = original


# ------------------------------------------------------------------ 创建


def test_create_public_client_has_no_secret(client):
    client_id = unique_client_id("web")
    response = make_client(client, client_id=client_id)
    assert response.status_code == 201, response.text

    body = response.json()
    assert body["client_id"] == client_id
    assert body["client_type"] == CLIENT_TYPE_PUBLIC
    assert body["client_secret"] is None
    assert body["token_endpoint_auth_method"] == AUTH_METHOD_NONE
    assert body["redirect_uris"] == ["https://example.com/callback"]
    # scope 保序（openid 打头），不做字典序排序
    assert body["allowed_scopes"] == ["openid", "profile", "email"]
    assert body["allowed_grant_types"] == [GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN]
    assert "client_secret_hash" not in body


def test_create_confidential_client_returns_secret_once(client):
    response = make_client(client, client_type=CLIENT_TYPE_CONFIDENTIAL)
    assert response.status_code == 201, response.text

    body = response.json()
    assert body["token_endpoint_auth_method"] == AUTH_METHOD_BASIC
    secret = body["client_secret"]
    assert secret and secret.startswith("cs_")

    # 之后任何入口都不再回显 secret / 其哈希
    listed = client.get("/v1/clients", headers=ADMIN_HEADERS).json()["clients"]
    entry = next(item for item in listed if item["client_id"] == body["client_id"])
    assert "client_secret" not in entry
    assert "client_secret_hash" not in entry

    detail = client.get(f"/v1/clients/{body['client_id']}", headers=ADMIN_HEADERS).json()
    assert "client_secret" not in detail
    assert "client_secret_hash" not in detail


def test_create_device_only_client_needs_no_redirect_uri(client):
    """§5.4 的 elicloud-cli：走设备码，没有 redirect_uri。"""
    response = make_client(
        client,
        client_id=unique_client_id("cli"),
        redirect_uris=[],
        allowed_scopes=["openid", "profile", "offline_access"],
        allowed_grant_types=[GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN],
    )
    assert response.status_code == 201, response.text
    assert response.json()["redirect_uris"] == []


def test_authorization_code_client_requires_redirect_uri(client):
    response = make_client(client, redirect_uris=[], allowed_grant_types=[GRANT_AUTHORIZATION_CODE])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_duplicate_client_id_returns_409(client):
    client_id = unique_client_id("dup")
    assert make_client(client, client_id=client_id).status_code == 201

    response = make_client(client, client_id=client_id)
    assert response.status_code == 409
    assert response.json()["error"] == "client_exists"


# ------------------------------------------------------------------ 校验


def test_redirect_uri_validation(client):
    cases = [
        "/relative/callback",  # 相对路径
        "https://example.com/cb#fragment",  # 带 fragment
        "javascript:alert(1)",  # 危险 scheme
        "https://",  # http(s) 缺主机
        "",  # 空
    ]
    for bad in cases:
        response = make_client(client, redirect_uris=[bad])
        assert response.status_code == 400, f"应当拒绝 {bad!r}"
        assert response.json()["error"] == "invalid_request"


def test_custom_scheme_redirect_uri_is_allowed(client):
    """手机 App 的自定义 scheme 回跳（§3.1）。"""
    response = make_client(client, redirect_uris=["elipese://callback"])
    assert response.status_code == 201, response.text


def test_unknown_scope_and_grant_type_are_rejected(client):
    response = make_client(client, allowed_scopes=["openid", "not:a:scope"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"

    response = make_client(client, allowed_grant_types=["password"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_auth_method_must_match_client_type(client):
    # public 客户端不能使用 secret 认证
    response = make_client(client, client_type=CLIENT_TYPE_PUBLIC, token_endpoint_auth_method=AUTH_METHOD_BASIC)
    assert response.status_code == 400

    # confidential 客户端必须使用 secret 认证
    response = make_client(client, client_type=CLIENT_TYPE_CONFIDENTIAL, token_endpoint_auth_method=AUTH_METHOD_NONE)
    assert response.status_code == 400


def test_unknown_field_is_rejected_not_ignored(client):
    """拼错字段名要 400，不能被静默忽略。"""
    response = make_client(client, client_secret="attacker-supplied")
    assert response.status_code == 400


# ------------------------------------------------------------ 更新与删除


def test_patch_updates_allowlisted_fields(client):
    client_id = make_client(client).json()["client_id"]

    response = client.patch(
        f"/v1/clients/{client_id}",
        json={"name": "Renamed", "redirect_uris": ["https://new.example.com/cb"], "allowed_scopes": ["openid"]},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "Renamed"
    assert body["redirect_uris"] == ["https://new.example.com/cb"]
    assert body["allowed_scopes"] == ["openid"]
    # 未提供的字段保持不变
    assert body["client_type"] == CLIENT_TYPE_PUBLIC
    assert body["allowed_grant_types"] == [GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN]


def test_patch_cannot_change_client_type_or_auth_method(client):
    client_id = make_client(client).json()["client_id"]

    for field in ("client_type", "token_endpoint_auth_method", "client_secret_hash"):
        response = client.patch(
            f"/v1/clients/{client_id}",
            json={field: "anything"},
            headers=ADMIN_HEADERS,
        )
        assert response.status_code == 400, f"{field} 不该可改"

    detail = client.get(f"/v1/clients/{client_id}", headers=ADMIN_HEADERS).json()
    assert detail["client_type"] == CLIENT_TYPE_PUBLIC
    assert detail["token_endpoint_auth_method"] == AUTH_METHOD_NONE


def test_patch_redirect_uris_keeps_exact_match_semantics(client):
    client_id = make_client(client).json()["client_id"]
    response = client.patch(
        f"/v1/clients/{client_id}",
        json={"redirect_uris": ["https://a.example.com/cb", "https://b.example.com/cb"]},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 200
    assert response.json()["redirect_uris"] == ["https://a.example.com/cb", "https://b.example.com/cb"]


def test_delete_client(client):
    client_id = make_client(client).json()["client_id"]

    response = client.delete(f"/v1/clients/{client_id}", headers=ADMIN_HEADERS)
    assert response.status_code == 204
    assert response.content == b""
    assert client.get(f"/v1/clients/{client_id}", headers=ADMIN_HEADERS).status_code == 404


def test_missing_client_returns_404(client):
    assert client.get("/v1/clients/nope", headers=ADMIN_HEADERS).status_code == 404
    assert client.patch("/v1/clients/nope", json={"name": "x"}, headers=ADMIN_HEADERS).status_code == 404
    assert client.delete("/v1/clients/nope", headers=ADMIN_HEADERS).status_code == 404
    assert client.post("/v1/clients/nope/rotate-secret", headers=ADMIN_HEADERS).status_code == 404


# --------------------------------------------------------------- 轮换 secret


def test_rotate_secret_replaces_hash(client):
    created = make_client(client, client_type=CLIENT_TYPE_CONFIDENTIAL).json()
    client_id = created["client_id"]
    first_secret = created["client_secret"]

    response = client.post(f"/v1/clients/{client_id}/rotate-secret", headers=ADMIN_HEADERS)
    assert response.status_code == 200, response.text
    second_secret = response.json()["client_secret"]

    assert second_secret.startswith("cs_")
    assert second_secret != first_secret

    # 库里只有新 secret 的哈希
    from app.clients import hash_client_secret
    from app.db import session_scope
    from app.models import OAuthClient

    with session_scope() as session:
        stored = session.get(OAuthClient, client_id)
        assert stored is not None
        assert stored.client_secret_hash == hash_client_secret(second_secret)
        assert stored.client_secret_hash != hash_client_secret(first_secret)


def test_rotate_secret_rejected_for_public_client(client):
    client_id = make_client(client).json()["client_id"]
    response = client.post(f"/v1/clients/{client_id}/rotate-secret", headers=ADMIN_HEADERS)
    assert response.status_code == 400

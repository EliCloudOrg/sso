"""发现文档的**自我一致性**（docs/sso-oidc.md §2.2 硬规则 1、§11）。

核心那条：遍历发现文档里声明的**每一个端点**，断言它不是 404。
这条测试能防止再次出现「声明了却没实现」——本次扩展的起因之一。
"""

from __future__ import annotations

import pytest

from tests.helpers import (
    get_authorize,
    gateway_internal_path,
    make_public_client,
    make_user,
    obtain_code,
    pkce_pair,
)

ENDPOINT_KEYS = (
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "end_session_endpoint",
    "device_authorization_endpoint",
)


def discovery(client) -> dict:
    response = client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    return response.json()


def test_issuer_equals_public_base_url(client, settings):
    payload = discovery(client)
    assert payload["issuer"] == settings.public_base_url


def test_token_endpoint_points_at_token_not_refresh(client, settings):
    """历史上这里错误地指向 /refresh（那是私有 JSON 端点），标准客户端会打不通。"""
    payload = discovery(client)
    assert payload["token_endpoint"] == f"{settings.public_base_url}/token"
    assert not payload["token_endpoint"].endswith("/refresh")


@pytest.mark.parametrize("key", ENDPOINT_KEYS)
def test_every_declared_endpoint_exists(client, settings, key):
    """发现文档里声明的端点必须真的存在（不是 404）。

    路径按网关规则还原（``/auth/userinfo`` → 服务内 ``/v1/userinfo`` 等），
    否则会误判成"声明了却没实现"。
    """
    payload = discovery(client)
    if key not in payload:
        pytest.skip(f"{key} 尚未实现，按 §2.2 也不应声明")
    path = gateway_internal_path(settings, payload[key])
    response = client.get(path, follow_redirects=False)
    assert response.status_code != 404, f"{key} 声明为 {payload[key]}，但服务内 {path} 返回 404"


def test_declared_grant_types_are_implemented(client):
    """声明的 grant_type 必须真的能用，否则标准客户端会踩空。"""
    from app.routers.wellknown import IMPLEMENTED_GRANT_TYPES

    declared = discovery(client)["grant_types_supported"]
    assert set(declared) == set(IMPLEMENTED_GRANT_TYPES)
    assert "password" not in declared  # OAuth 2.1 已移除 ROPC


def test_pkce_and_auth_methods_declared(client):
    payload = discovery(client)
    assert payload["code_challenge_methods_supported"] == ["S256"]  # plain 明确不支持
    assert set(payload["token_endpoint_auth_methods_supported"]) == {
        "client_secret_basic",
        "client_secret_post",
        "none",
    }
    assert payload["response_types_supported"] == ["code"]
    assert payload["response_modes_supported"] == ["query"]
    assert payload["subject_types_supported"] == ["public"]
    assert payload["id_token_signing_alg_values_supported"] == ["RS256"]


def test_scopes_and_claims_declared(client):
    payload = discovery(client)
    assert {"openid", "profile", "email", "offline_access"} <= set(payload["scopes_supported"])
    assert {"sub", "preferred_username", "email"} <= set(payload["claims_supported"])
    # 不再声明非标准的 username（B2）
    assert "username" not in payload["claims_supported"]


def test_mc_whitelist_scope_is_declared_and_accepted(client):
    """业务 scope `mc:whitelist`（MC 白名单服务用，docs/mc-whitelist.md §12.4）。

    声明的 scope 与真正接受的 scope 必须一致 —— 这两处历史上最容易漂移：
    发现文档里声明了、但 SUPPORTED_SCOPES 里没有（客户端一请求就 invalid_scope）。
    """
    from app.constants import SCOPE_MC_WHITELIST, SUPPORTED_SCOPES
    from app.clients import validate_scopes

    payload = discovery(client)
    assert SCOPE_MC_WHITELIST == "mc:whitelist"
    assert SCOPE_MC_WHITELIST in SUPPORTED_SCOPES
    assert SCOPE_MC_WHITELIST in payload["scopes_supported"]
    # 客户端注册时声明它必须被接受
    assert validate_scopes(["openid", SCOPE_MC_WHITELIST]) == ["openid", SCOPE_MC_WHITELIST]


def test_default_scope_covers_mc_whitelist(settings):
    """默认签发的令牌必须带上它，否则 mc-whitelist 服务会对所有令牌回 403。"""
    from app.constants import SCOPE_MC_WHITELIST

    assert SCOPE_MC_WHITELIST in settings.default_scope.split()


def test_authorization_endpoint_actually_serves_the_flow(client):
    """声明的 authorization_endpoint 不只是"非 404"，而是真的能跑通授权。"""
    payload = discovery(client)
    assert payload["authorization_endpoint"].endswith("/authorize")

    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(client, client_id=client_id, username=username, verifier=verifier, challenge=challenge)
    assert code

""".well-known 发现端点：JWKS 与 OIDC 配置。

两个硬规则（docs/sso-oidc.md §2.2）：

1. **声明的每个端点都必须真的存在** —— 这里只 advertise 已实现的能力，
   每落地一个端点/能力就往这里加一项。``tests/test_discovery.py`` 会遍历所有 endpoint
   断言"不是 404"，防止再出现"声明了却没实现"。
2. 所有 URI 都由 ``settings`` 从 ``PUBLIC_BASE_URL`` 派生，零硬编码。
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response

from ..constants import (
    GRANT_AUTHORIZATION_CODE,
    GRANT_DEVICE_CODE,
    GRANT_REFRESH_TOKEN,
    SUPPORTED_AUTH_METHODS,
    SUPPORTED_CLAIMS,
    SUPPORTED_CODE_CHALLENGE_METHODS,
    SUPPORTED_RESPONSE_MODES,
    SUPPORTED_RESPONSE_TYPES,
    SUPPORTED_SCOPES,
)
from ..deps import KeyStoreDep, SettingsDep

router = APIRouter(tags=["well-known"])

JWKS_CACHE_CONTROL = "public, max-age=300"

# 已经落地、可以对外声明的 grant_type。
IMPLEMENTED_GRANT_TYPES: tuple[str, ...] = (
    GRANT_AUTHORIZATION_CODE,
    GRANT_REFRESH_TOKEN,
    GRANT_DEVICE_CODE,
)


@router.get("/.well-known/jwks.json")
def jwks(response: Response, keystore: KeyStoreDep) -> dict[str, list[dict[str, str]]]:
    """匿名可访问的公钥集（业务服务验签 access token / id_token 用）。"""
    response.headers["Cache-Control"] = JWKS_CACHE_CONTROL
    return keystore.jwks()


@router.get("/.well-known/openid-configuration")
def openid_configuration(response: Response, settings: SettingsDep) -> dict[str, Any]:
    response.headers["Cache-Control"] = JWKS_CACHE_CONTROL

    # 所有已声明的端点都真的存在（§2.2 硬规则 1）
    return {
        "issuer": settings.issuer,
        "authorization_endpoint": settings.authorization_endpoint,
        "token_endpoint": settings.token_endpoint,
        "userinfo_endpoint": settings.userinfo_endpoint,
        "jwks_uri": settings.jwks_uri,
        "device_authorization_endpoint": settings.device_authorization_endpoint,
        "end_session_endpoint": settings.end_session_endpoint,
        "response_types_supported": list(SUPPORTED_RESPONSE_TYPES),
        "response_modes_supported": list(SUPPORTED_RESPONSE_MODES),
        "grant_types_supported": list(IMPLEMENTED_GRANT_TYPES),
        "code_challenge_methods_supported": list(SUPPORTED_CODE_CHALLENGE_METHODS),
        "token_endpoint_auth_methods_supported": list(SUPPORTED_AUTH_METHODS),
        "id_token_signing_alg_values_supported": [settings.jwt_alg],
        "subject_types_supported": ["public"],
        "scopes_supported": list(SUPPORTED_SCOPES),
        "claims_supported": list(SUPPORTED_CLAIMS),
    }

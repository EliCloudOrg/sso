"""FastAPI 依赖：配置、密钥、当前用户身份、管理员鉴权、客户端 IP。"""

from __future__ import annotations

import logging
import secrets
from typing import Annotated, Any

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session as DbSession

from .config import Settings, get_settings
from .db import get_db
from .errors import api_error, limiter
from .keys import KeyStore, get_keystore
from .models import UserSession
from .security import decode_access_token
from .sessions import get_session_from_request

logger = logging.getLogger(__name__)

# 管理员令牌认证的失败限流（防暴力猜 ADMIN_TOKEN）
ADMIN_AUTH_ATTEMPTS = 20
ADMIN_AUTH_WINDOW_SECONDS = 300

bearer_scheme = HTTPBearer(auto_error=False, description="SSO 签发的 RS256 Access Token")

SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_keystore_dep(settings: SettingsDep) -> KeyStore:
    return get_keystore(settings)


KeyStoreDep = Annotated[KeyStore, Depends(get_keystore_dep)]


def client_ip(request: Request) -> str:
    """取真实客户端 IP。

    网关（Caddy）会把客户端 IP **追加**到 X-Forwarded-For 末尾，因此取最后一段；
    取第一段会被调用方自带的值污染。服务不直接对公网暴露端口，这是可接受的前提。
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if parts:
            return parts[-1]
    if request.headers.get("x-real-ip"):
        return str(request.headers["x-real-ip"]).strip()
    return request.client.host if request.client else "unknown"


def current_claims(
    request: Request,
    settings: SettingsDep,
    keystore: KeyStoreDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> dict[str, Any]:
    if credentials is None or not credentials.credentials:
        raise api_error(
            401,
            "invalid_token",
            "缺少 Bearer 令牌",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if credentials.scheme.lower() != "bearer":
        raise api_error(401, "invalid_token", "认证方案必须是 Bearer", headers={"WWW-Authenticate": "Bearer"})

    claims = decode_access_token(settings, keystore, credentials.credentials)
    request.state.user_id = claims.get("sub")
    return claims


CurrentClaims = Annotated[dict[str, Any], Depends(current_claims)]


def require_admin(
    request: Request,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> None:
    """客户端管理接口的鉴权（sso-oidc.md §5.2）。

    ``ADMIN_TOKEN`` 未配置时**整体关闭**（fail closed），而不是"无鉴权放行"。
    令牌比较用 ``secrets.compare_digest``（常量时间），失败尝试按 IP 限流。
    """
    if not settings.admin_token:
        raise api_error(403, "admin_disabled", "客户端管理接口未启用：请先配置 ADMIN_TOKEN")

    ip = client_ip(request)
    if not limiter.allow(f"admin-auth:{ip}", ADMIN_AUTH_ATTEMPTS, ADMIN_AUTH_WINDOW_SECONDS):
        raise api_error(
            429,
            "too_many_requests",
            "管理员认证尝试过于频繁，请稍后再试",
            headers={"Retry-After": str(ADMIN_AUTH_WINDOW_SECONDS)},
        )

    provided = credentials.credentials if credentials is not None else None
    # 两侧都转 bytes：compare_digest 不支持非 ASCII 的 str
    authorized = bool(provided) and secrets.compare_digest(
        str(provided).encode("utf-8"),
        settings.admin_token.encode("utf-8"),
    )
    if not authorized:
        logger.warning("admin auth failed ip=%s", ip)
        # 绝不记录令牌原文
        raise api_error(401, "invalid_token", "管理员令牌无效", headers={"WWW-Authenticate": "Bearer"})

    limiter.reset(f"admin-auth:{ip}")


AdminAuth = Annotated[None, Depends(require_admin)]


def optional_session(
    request: Request,
    settings: SettingsDep,
    db: DbSession = Depends(get_db),
) -> UserSession | None:
    """浏览器会话（可选）：没有 cookie / 已撤销 / 已过期都返回 None，不报错。"""
    return get_session_from_request(db, request, settings)


OptionalSession = Annotated[UserSession | None, Depends(optional_session)]


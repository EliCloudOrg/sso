"""OAuth2 / OIDC 客户端的静态注册（docs/sso-oidc.md §5）。

* 一期**不做** RFC 7591 动态注册，客户端只由管理接口 / CLI 创建。
* ``client_secret`` 明文**只在创建（或轮换）那一次返回**，库里只存哈希。
* 哈希用 SHA-256 + 常量时间比较：client_secret 是 256 位机器随机串（不可爆破），
  与 refresh token 同等对待；换成 bcrypt 会让每一次 token 请求多付 ~300ms 而没有实际安全收益。
* ``redirect_uri`` 的防线是**精确字符串匹配**注册值（§7.1），不做前缀/通配。
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .constants import (
    AUTH_METHOD_NONE,
    CLIENT_TYPE_CONFIDENTIAL,
    CLIENT_TYPE_PUBLIC,
    GRANT_AUTHORIZATION_CODE,
    GRANT_REFRESH_TOKEN,
    SUPPORTED_AUTH_METHODS,
    SUPPORTED_CLIENT_TYPES,
    SUPPORTED_GRANT_TYPES,
    SUPPORTED_SCOPES,
)
from .errors import api_error
from .models import (
    AuthorizationCode,
    Consent,
    DeviceCode,
    OAuthClient,
    RefreshToken,
    dumps_list,
    to_iso,
    utcnow,
)

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
CLIENT_SECRET_PREFIX = "cs_"
# 未显式指定时给客户端的默认授权类型
DEFAULT_GRANT_TYPES: tuple[str, ...] = (GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN)
# 只用于 302 Location，出现这些 scheme 有被当成脚本/本地文件执行的风险
FORBIDDEN_REDIRECT_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})


# ------------------------------------------------------------------ 校验


def validate_client_id(client_id: str) -> str:
    value = (client_id or "").strip()
    if not CLIENT_ID_RE.match(value):
        raise api_error(
            400,
            "invalid_request",
            "client_id 需为 2~64 位，以字母或数字开头，仅含字母、数字、_ . : -",
        )
    return value


def validate_client_type(client_type: str) -> str:
    value = (client_type or "").strip().lower()
    if value not in SUPPORTED_CLIENT_TYPES:
        raise api_error(400, "invalid_request", f"client_type 只能是 {' / '.join(SUPPORTED_CLIENT_TYPES)}")
    return value


def validate_redirect_uri(uri: str) -> str:
    value = (uri or "").strip()
    if not value:
        raise api_error(400, "invalid_request", "redirect_uri 不能为空")
    if any(ch.isspace() for ch in value):
        raise api_error(400, "invalid_request", f"redirect_uri 不能包含空白字符：{value}")

    parts = urlsplit(value)
    if not parts.scheme:
        raise api_error(400, "invalid_request", f"redirect_uri 必须是绝对 URI：{value}")
    if parts.fragment:
        # RFC 6749 §3.1.2：redirect_uri 不得带 fragment
        raise api_error(400, "invalid_request", f"redirect_uri 不得包含片段（#）：{value}")
    if parts.scheme.lower() in FORBIDDEN_REDIRECT_SCHEMES:
        raise api_error(400, "invalid_request", f"不允许的 redirect_uri scheme：{parts.scheme}")
    if parts.scheme.lower() in {"http", "https"} and not parts.netloc:
        raise api_error(400, "invalid_request", f"http(s) 的 redirect_uri 必须带主机：{value}")
    if parts.scheme.lower() not in {"http", "https"} and not (parts.netloc or parts.path):
        raise api_error(400, "invalid_request", f"自定义 scheme 的 redirect_uri 必须带目标：{value}")
    return value


def validate_redirect_uris(uris: list[str] | None, *, field: str = "redirect_uris", required: bool = True) -> list[str]:
    values = [validate_redirect_uri(uri) for uri in (uris or [])]
    # 去重保序
    deduped: list[str] = []
    for uri in values:
        if uri not in deduped:
            deduped.append(uri)
    if required and not deduped:
        raise api_error(400, "invalid_request", f"{field} 至少需要一个值")
    return deduped


def validate_scopes(scopes: list[str] | None, *, required: bool = True) -> list[str]:
    values: list[str] = []
    for item in scopes or []:
        for token in str(item).split():
            if token and token not in values:
                values.append(token)
    unknown = [item for item in values if item not in SUPPORTED_SCOPES]
    if unknown:
        raise api_error(400, "invalid_scope", f"平台不支持的 scope：{' '.join(unknown)}")
    if required and not values:
        raise api_error(400, "invalid_request", "allowed_scopes 至少需要一个值")
    return values


def validate_grant_types(grant_types: list[str] | None) -> list[str]:
    values: list[str] = []
    for item in grant_types or []:
        text = str(item).strip()
        if text and text not in values:
            values.append(text)
    unknown = [item for item in values if item not in SUPPORTED_GRANT_TYPES]
    if unknown:
        raise api_error(400, "invalid_request", f"不支持的 grant_type：{' '.join(unknown)}")
    if not values:
        values = list(DEFAULT_GRANT_TYPES)
    return values


def default_grant_types() -> list[str]:
    return list(DEFAULT_GRANT_TYPES)


def needs_redirect_uri(grant_types: list[str]) -> bool:
    """只有授权码流程才需要 redirect_uri；纯设备码客户端可以没有（§5.4 的 elicloud-cli）。"""
    return GRANT_AUTHORIZATION_CODE in grant_types


def default_auth_method(client_type: str) -> str:
    return AUTH_METHOD_NONE if client_type == CLIENT_TYPE_PUBLIC else "client_secret_basic"


def validate_auth_method(client_type: str, method: str | None) -> str:
    value = (method or default_auth_method(client_type)).strip()
    if value not in SUPPORTED_AUTH_METHODS:
        raise api_error(400, "invalid_request", f"token_endpoint_auth_method 只能是 {' / '.join(SUPPORTED_AUTH_METHODS)}")
    if client_type == CLIENT_TYPE_PUBLIC and value != AUTH_METHOD_NONE:
        raise api_error(400, "invalid_request", "public 客户端只能用 token_endpoint_auth_method=none")
    if client_type == CLIENT_TYPE_CONFIDENTIAL and value == AUTH_METHOD_NONE:
        raise api_error(400, "invalid_request", "confidential 客户端必须使用 client_secret_basic 或 client_secret_post")
    return value


# ------------------------------------------------------------- secret


def generate_client_secret() -> str:
    return f"{CLIENT_SECRET_PREFIX}{secrets.token_urlsafe(32)}"


def hash_client_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_client_secret(secret: str | None, stored_hash: str | None) -> bool:
    """常量时间比较；缺任一参数都判失败。"""
    if not secret or not stored_hash:
        return False
    return hmac.compare_digest(hash_client_secret(secret), stored_hash)


# ------------------------------------------------------------------ 查询


def get_client_or_404(db: Session, client_id: str) -> OAuthClient:
    client = db.get(OAuthClient, client_id)
    if client is None:
        raise api_error(404, "not_found", f"客户端不存在：{client_id}")
    return client


def list_clients(db: Session) -> list[OAuthClient]:
    return list(db.scalars(select(OAuthClient).order_by(OAuthClient.client_id)))


# ------------------------------------------------------------------ 写入


def create_client(
    db: Session,
    *,
    client_id: str,
    name: str,
    client_type: str,
    redirect_uris: list[str] | None,
    allowed_scopes: list[str] | None,
    post_logout_redirect_uris: list[str] | None = None,
    allowed_grant_types: list[str] | None = None,
    token_endpoint_auth_method: str | None = None,
) -> tuple[OAuthClient, str | None]:
    """创建客户端；返回 (客户端, 明文 secret 或 None)。"""
    cid = validate_client_id(client_id)
    ctype = validate_client_type(client_type)
    method = validate_auth_method(ctype, token_endpoint_auth_method)

    display_name = (name or "").strip()
    if not display_name:
        raise api_error(400, "invalid_request", "name 不能为空")

    if db.get(OAuthClient, cid) is not None:
        raise api_error(409, "client_exists", f"client_id 已存在：{cid}")

    grants = validate_grant_types(allowed_grant_types)
    # 只有授权码流程才要求 redirect_uri（纯设备码客户端可以为空）
    uris = validate_redirect_uris(redirect_uris, required=needs_redirect_uri(grants))
    logout_uris = validate_redirect_uris(
        post_logout_redirect_uris,
        field="post_logout_redirect_uris",
        required=False,
    )
    scopes = validate_scopes(allowed_scopes)

    plaintext_secret: str | None = None
    secret_hash: str | None = None
    if method != AUTH_METHOD_NONE:
        plaintext_secret = generate_client_secret()
        secret_hash = hash_client_secret(plaintext_secret)

    now_iso = to_iso(utcnow())
    client = OAuthClient(
        client_id=cid,
        client_secret_hash=secret_hash,
        client_type=ctype,
        name=display_name,
        redirect_uris=dumps_list(uris),
        post_logout_redirect_uris=dumps_list(logout_uris),
        allowed_scopes=dumps_list(scopes),
        allowed_grant_types=dumps_list(grants),
        token_endpoint_auth_method=method,
        created_at=now_iso,
        updated_at=now_iso,
    )
    db.add(client)
    db.commit()
    return client, plaintext_secret


def update_client(
    db: Session,
    client_id: str,
    *,
    name: str | None = None,
    redirect_uris: list[str] | None = None,
    post_logout_redirect_uris: list[str] | None = None,
    allowed_scopes: list[str] | None = None,
    allowed_grant_types: list[str] | None = None,
) -> OAuthClient:
    """只允许改这几项。

    ``client_type`` 与 ``token_endpoint_auth_method`` **不在可改范围内**：它们决定
    认证强度，属于安全相关变更，应当删除后重建（避免悄悄把 public 客户端升级成 confidential
    或反过来）。
    """
    client = get_client_or_404(db, client_id)

    if name is not None:
        display_name = name.strip()
        if not display_name:
            raise api_error(400, "invalid_request", "name 不能为空")
        client.name = display_name
    # 先落 grant_types，再校验 redirect_uris —— 否则同一次 PATCH 里改两者时判定会用到旧值
    if allowed_grant_types is not None:
        client.allowed_grant_types = dumps_list(validate_grant_types(allowed_grant_types))
    if redirect_uris is not None:
        client.redirect_uris = dumps_list(
            validate_redirect_uris(redirect_uris, required=needs_redirect_uri(client.grant_type_list))
        )
    if post_logout_redirect_uris is not None:
        client.post_logout_redirect_uris = dumps_list(
            validate_redirect_uris(post_logout_redirect_uris, field="post_logout_redirect_uris", required=False)
        )
    if allowed_scopes is not None:
        client.allowed_scopes = dumps_list(validate_scopes(allowed_scopes))

    client.updated_at = to_iso(utcnow())
    db.commit()
    return client


def delete_client(db: Session, client_id: str) -> None:
    """删除客户端，并连带清理它的授权码 / 设备码 / 同意记录，同时撤销其 refresh 链。"""
    client = get_client_or_404(db, client_id)
    now_iso = to_iso(utcnow())

    for row in db.scalars(
        select(RefreshToken).where(RefreshToken.client_id == client_id, RefreshToken.revoked_at.is_(None))
    ).all():
        row.revoked_at = now_iso

    db.execute(delete(AuthorizationCode).where(AuthorizationCode.client_id == client_id))
    db.execute(delete(DeviceCode).where(DeviceCode.client_id == client_id))
    db.execute(delete(Consent).where(Consent.client_id == client_id))
    db.delete(client)
    db.commit()


def rotate_client_secret(db: Session, client_id: str) -> tuple[OAuthClient, str]:
    """轮换 secret；旧 secret 立刻失效（哈希被替换）。"""
    client = get_client_or_404(db, client_id)
    if client.token_endpoint_auth_method == AUTH_METHOD_NONE:
        raise api_error(400, "invalid_request", f"public 客户端没有 client_secret：{client.client_id}")

    plaintext = generate_client_secret()
    client.client_secret_hash = hash_client_secret(plaintext)
    client.updated_at = to_iso(utcnow())
    db.commit()
    return client, plaintext

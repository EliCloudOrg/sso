"""token 端点的客户端认证（docs/sso-oidc.md §2.4、§5.1）。

支持三种方式，且**必须与客户端注册值一致**：

* ``client_secret_basic`` —— HTTP Basic（凭据按 RFC 6749 附录 B 做 form-urlencoded 后 base64）
* ``client_secret_post``  —— 表单字段 ``client_id`` + ``client_secret``
* ``none``                —— 公开客户端，只给 ``client_id``，安全性由 PKCE 保证

RFC 6749 §2.3.1 要求一个请求里**不得混用多种认证方式**；混用直接 ``invalid_request``。
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from urllib.parse import unquote

from fastapi import Request
from sqlalchemy.orm import Session as DbSession

from .clients import verify_client_secret
from .constants import AUTH_METHOD_BASIC, AUTH_METHOD_NONE, AUTH_METHOD_POST, CLIENT_TYPE_PUBLIC
from .errors import api_error
from .models import OAuthClient

METHOD_BASIC = AUTH_METHOD_BASIC
METHOD_POST = AUTH_METHOD_POST
METHOD_NONE = AUTH_METHOD_NONE


@dataclass
class ClientCredentials:
    client_id: str | None = None
    client_secret: str | None = None
    method: str = METHOD_NONE
    used_authorization_header: bool = False


def _invalid_client(used_authorization_header: bool, description: str = "客户端认证失败"):
    """RFC 6749 §5.2：用 Authorization 头认证失败时必须返回 401，否则 400。"""
    return api_error(
        401 if used_authorization_header else 400,
        "invalid_client",
        description,
        headers={"WWW-Authenticate": 'Basic realm="sso"'} if used_authorization_header else None,
    )


def _parse_basic(header: str) -> tuple[str, str] | None:
    try:
        raw = base64.b64decode(header.encode("ascii"), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if ":" not in raw:
        return None
    client_id, _, client_secret = raw.partition(":")
    # RFC 6749 附录 B：凭据在 base64 之前经过 form-urlencoded
    return unquote(client_id), unquote(client_secret)


def extract_credentials(
    request: Request,
    *,
    form_client_id: str | None,
    form_client_secret: str | None,
) -> ClientCredentials:
    header = request.headers.get("authorization") or ""
    scheme, _, payload = header.partition(" ")
    basic_parts = _parse_basic(payload) if scheme.lower() == "basic" and payload else None

    if scheme.lower() == "basic" and basic_parts is None:
        raise api_error(401, "invalid_client", "Authorization 头格式不合法", headers={"WWW-Authenticate": 'Basic realm="sso"'})

    if basic_parts is not None and form_client_id:
        # 同一请求里混用两种方式
        raise api_error(400, "invalid_request", "不得同时使用 Authorization 头与表单提交客户端凭据")

    if basic_parts is not None:
        return ClientCredentials(
            client_id=basic_parts[0],
            client_secret=basic_parts[1],
            method=METHOD_BASIC,
            used_authorization_header=True,
        )

    if form_client_id:
        return ClientCredentials(
            client_id=form_client_id,
            client_secret=form_client_secret,
            method=METHOD_POST if form_client_secret else METHOD_NONE,
        )

    raise _invalid_client(False, "缺少 client_id")


def authenticate_client(db: DbSession, credentials: ClientCredentials) -> OAuthClient:
    """校验客户端身份，并确认它用的认证方式与注册值一致。"""
    client = db.get(OAuthClient, credentials.client_id) if credentials.client_id else None
    if client is None:
        raise _invalid_client(credentials.used_authorization_header, "client_id 未注册")

    registered = client.token_endpoint_auth_method
    if registered == METHOD_NONE:
        if client.client_type != CLIENT_TYPE_PUBLIC:
            raise _invalid_client(credentials.used_authorization_header, "客户端注册信息异常")
        if credentials.method != METHOD_NONE:
            # 公开客户端不该带 secret（也说明对方把 secret 配错了）
            raise _invalid_client(credentials.used_authorization_header, "该客户端为公开客户端，不接受 client_secret")
        return client

    if credentials.method != registered:
        raise _invalid_client(
            credentials.used_authorization_header,
            f"该客户端必须使用 {registered} 认证",
        )
    if not verify_client_secret(credentials.client_secret, client.client_secret_hash):
        raise _invalid_client(credentials.used_authorization_header, "client_secret 不正确")
    return client


def ensure_grant_allowed(client: OAuthClient, grant_type: str) -> None:
    """客户端未注册该 grant_type → unauthorized_client（§2.4 错误码表）。"""
    if grant_type not in client.grant_type_list:
        raise api_error(400, "unauthorized_client", f"该客户端未注册 grant_type={grant_type}")

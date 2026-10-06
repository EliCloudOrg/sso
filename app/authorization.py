"""授权端点的参数校验与授权码签发（docs/sso-oidc.md §2.3、§6.1）。

错误处理刻意分成两类，这是防开放重定向的关键：

* :class:`AuthorizeFatalError` —— ``client_id`` / ``redirect_uri`` **不可信**。
  此时**绝不能重定向**（否则就是开放重定向），调用方必须渲染错误页。
* :class:`AuthorizeRedirectError` —— 其余参数问题（``response_type`` / ``scope`` /
  PKCE / ``prompt``）。此时 ``redirect_uri`` 已确认属于该客户端，可以安全地
  302 回 ``redirect_uri?error=...&state=...``。
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .config import Settings
from .constants import (
    CLIENT_TYPE_PUBLIC,
    GRANT_AUTHORIZATION_CODE,
    RESPONSE_TYPE_CODE,
    SCOPE_OPENID,
)
from .errors import api_error
from .models import AuthorizationCode, OAuthClient, parse_iso, to_iso, utcnow
from .oidc import ensure_pkce_s256, join_scope, pkce_matches, split_scope, validate_scope_subset
from .tokens import revoke_family

MAX_STATE_LENGTH = 512
MAX_NONCE_LENGTH = 512
MAX_SCOPE_ITEMS = 20
CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43,128}$")
SUPPORTED_PROMPTS = ("login", "none")


class AuthorizeFatalError(Exception):
    """client_id / redirect_uri 不可信 —— 只渲染错误页，绝不重定向。"""

    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


class AuthorizeRedirectError(Exception):
    """可安全 302 回 redirect_uri 的参数错误。"""

    def __init__(self, error: str, description: str, state: str | None = None) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.state = state


@dataclass
class AuthorizeParams:
    """校验通过后的授权请求。"""

    client_id: str
    redirect_uri: str
    scope: list[str]
    state: str | None = None
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    prompt: str | None = None
    extra_hidden: dict[str, str] = field(default_factory=dict)

    @property
    def scope_text(self) -> str:
        return join_scope(self.scope)


# --------------------------------------------------------------- 校验


def resolve_client(db: DbSession, client_id: str | None, redirect_uri: str | None) -> OAuthClient:
    """先验客户端与回跳地址；这两项不合法就**不能重定向**（§7.1）。"""
    client = db.get(OAuthClient, client_id) if client_id else None
    if client is None:
        raise AuthorizeFatalError("invalid_request", "client_id 缺失或未注册")
    if not redirect_uri:
        raise AuthorizeFatalError("invalid_request", "缺少 redirect_uri")
    if not client.allows_redirect_uri(redirect_uri):
        # 精确匹配：不做前缀/通配（§7.1）
        raise AuthorizeFatalError("invalid_request", "redirect_uri 与该客户端注册值不匹配")
    return client


def _bounded(value: str | None, name: str, limit: int) -> str | None:
    if value is None or value == "":
        return None
    if len(value) > limit:
        raise AuthorizeRedirectError("invalid_request", f"{name} 过长")
    return value


def build_params(
    client: OAuthClient,
    *,
    redirect_uri: str,
    response_type: str | None,
    scope: str | None,
    state: str | None,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
    prompt: str | None,
) -> AuthorizeParams:
    """校验除 client_id / redirect_uri 之外的参数（可以重定向报错）。"""
    bounded_state = _bounded(state, "state", MAX_STATE_LENGTH)

    if (response_type or "") != RESPONSE_TYPE_CODE:
        raise AuthorizeRedirectError("unsupported_response_type", "只支持 response_type=code", bounded_state)

    if GRANT_AUTHORIZATION_CODE not in client.grant_type_list:
        raise AuthorizeRedirectError("unauthorized_client", "该客户端未注册 authorization_code", bounded_state)

    requested_scope = split_scope(scope)
    if len(requested_scope) > MAX_SCOPE_ITEMS:
        raise AuthorizeRedirectError("invalid_scope", "scope 项数过多", bounded_state)
    if SCOPE_OPENID not in requested_scope:
        # OIDC 请求必须带 openid（§2.3）
        raise AuthorizeRedirectError("invalid_scope", "scope 必须包含 openid", bounded_state)
    try:
        validated_scope = validate_scope_subset(requested_scope, client.scope_list)
    except HTTPException as exc:
        # 把 400 转成可重定向的 OAuth 错误（此时 redirect_uri 已确认可信）
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        description = str(detail.get("error_description") or "scope 不被允许")
        raise AuthorizeRedirectError("invalid_scope", description, bounded_state) from exc

    method: str | None = None
    challenge: str | None = None
    if code_challenge:
        if not CHALLENGE_RE.match(code_challenge):
            raise AuthorizeRedirectError("invalid_request", "code_challenge 格式不合法", bounded_state)
        try:
            method = ensure_pkce_s256(code_challenge_method)  # plain/缺失都拒绝（§7.2）
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            description = str(detail.get("error_description") or "code_challenge_method 只支持 S256")
            raise AuthorizeRedirectError("invalid_request", description, bounded_state) from exc
        challenge = code_challenge
    elif client.client_type == CLIENT_TYPE_PUBLIC:
        # 公开客户端强制 PKCE（§5.1、§7.2）
        raise AuthorizeRedirectError("invalid_request", "公开客户端必须提供 code_challenge（S256）", bounded_state)

    normalized_prompt = (prompt or "").strip() or None
    if normalized_prompt is not None and normalized_prompt not in SUPPORTED_PROMPTS:
        raise AuthorizeRedirectError("invalid_request", "prompt 只支持 login 或 none", bounded_state)

    return AuthorizeParams(
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scope=list(validated_scope),
        state=bounded_state,
        nonce=_bounded(nonce, "nonce", MAX_NONCE_LENGTH),
        code_challenge=challenge,
        code_challenge_method=method,
        prompt=normalized_prompt,
    )


# ------------------------------------------------------------- 重定向 URL


def _append_query(uri: str, params: dict[str, str]) -> str:
    """把参数并入 redirect_uri 的查询串（保留原有 query，如自定义 scheme 也适用）。"""
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.extend((key, value) for key, value in params.items() if value is not None)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def success_redirect_url(redirect_uri: str, code: str, state: str | None) -> str:
    return _append_query(redirect_uri, {"code": code, "state": state})


def error_redirect_url(redirect_uri: str, error: str, description: str, state: str | None) -> str:
    return _append_query(
        redirect_uri,
        {"error": error, "error_description": description, "state": state},
    )


# --------------------------------------------------------------- 授权码


def hash_authorization_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def issue_authorization_code(
    db: DbSession,
    *,
    client: OAuthClient,
    user_id: str,
    params: AuthorizeParams,
    settings: Settings,
    session_id: str | None,
    auth_time_iso: str,
    ip: str | None,
    user_agent: str | None,
) -> str:
    """生成一次性授权码：明文只回给客户端，库里只存 SHA-256，TTL 默认 60 秒。"""
    code = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(
        AuthorizationCode(
            code_hash=hash_authorization_code(code),
            client_id=client.client_id,
            user_id=user_id,
            redirect_uri=params.redirect_uri,
            scope=params.scope_text,
            nonce=params.nonce,
            code_challenge=params.code_challenge,
            code_challenge_method=params.code_challenge_method,
            auth_time=auth_time_iso,
            session_id=session_id,
            expires_at=to_iso(now + timedelta(seconds=settings.authorization_code_ttl)),
            created_at=to_iso(now),
            ip=ip,
            user_agent=(user_agent or "")[:256] or None,
        )
    )
    return code


@dataclass
class CodeExchange:
    """授权码兑换出的上下文（token 端点据此签发令牌）。"""

    user_id: str
    scope: list[str]
    nonce: str | None
    session_id: str | None
    auth_time: str
    row: AuthorizationCode


def consume_authorization_code(
    db: DbSession,
    *,
    code: str | None,
    client: OAuthClient,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> CodeExchange:
    """兑换授权码：一次性 + 绑定校验 + PKCE（docs/sso-oidc.md §2.4a、§7.3、§7.4）。

    顺序刻意如此：

    1. **先查重放**：码已被用过 → 撤销它派生的整条 refresh 链，再报 ``invalid_grant``；
    2. **立刻把码标记为已用并 commit**（即使后面校验失败也不回滚）—— 这样 PKCE 的
       ``code_verifier`` 无法被在线暴力试错（否则等于给了攻击者无限次猜测机会）；
    3. 再逐项校验过期 / 归属 / redirect_uri / PKCE，任一失败都返回 ``invalid_grant``。
    """
    if not code:
        raise api_error(400, "invalid_request", "缺少 code")

    row = db.scalar(select(AuthorizationCode).where(AuthorizationCode.code_hash == hash_authorization_code(code)))
    if row is None:
        raise api_error(400, "invalid_grant", "授权码无效或已过期")

    if row.used_at is not None:
        # 重放：该码派生出的整条 refresh 链立即撤销（§7.4）
        revoked = revoke_family(db, row.family_id, reason="authorization_code_replay")
        db.commit()
        raise api_error(
            400,
            "invalid_grant",
            f"授权码已被使用，已撤销其派生的令牌（{revoked} 条）",
        )

    # 一次性：立即标记并落库，之后的任何失败都不允许再次兑换
    row.used_at = to_iso(utcnow())
    db.commit()

    if parse_iso(row.expires_at) <= utcnow():
        raise api_error(400, "invalid_grant", "授权码已过期")

    if row.client_id != client.client_id:
        # 码不属于这个客户端：按泄露处理，不再细分原因
        raise api_error(400, "invalid_grant", "授权码与客户端不匹配")

    if not redirect_uri or row.redirect_uri != redirect_uri:
        raise api_error(400, "invalid_grant", "redirect_uri 与授权请求不一致")

    if row.code_challenge:
        if not pkce_matches(code_verifier, row.code_challenge):
            raise api_error(400, "invalid_grant", "code_verifier 校验失败")
    elif client.client_type == CLIENT_TYPE_PUBLIC:
        # 公开客户端在 /authorize 阶段已被强制要求 PKCE，这里兜一层
        raise api_error(400, "invalid_grant", "公开客户端必须使用 PKCE")

    return CodeExchange(
        user_id=row.user_id,
        scope=split_scope(row.scope),
        nonce=row.nonce,
        session_id=row.session_id,
        auth_time=row.auth_time,
        row=row,
    )

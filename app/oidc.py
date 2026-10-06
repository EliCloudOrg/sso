"""OIDC / OAuth 2.0 协议层的共用校验与工具（docs/sso-oidc.md §2、§7）。

纯函数 + ``api_error``，不碰数据库、不碰表结构。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Iterable

from .constants import (
    CODE_CHALLENGE_S256,
    PKCE_VERIFIER_MAX,
    PKCE_VERIFIER_MIN,
    SUPPORTED_SCOPES,
)
from .errors import api_error

# PKCE code_verifier 只允许 unreserved 字符集（RFC 7636 §4.1）
_UNRESERVED_RE = re.compile(r"^[A-Za-z0-9\-._~]+$")


# ------------------------------------------------------------------ scope


def split_scope(value: str | None) -> list[str]:
    """把 ``"openid profile email"`` 拆成去重且保序的列表。"""
    if not value:
        return []
    result: list[str] = []
    for item in value.split():
        item = item.strip()
        if item and item not in result:
            result.append(item)
    return result


def join_scope(values: Iterable[str]) -> str:
    return " ".join(values)


def scope_has(scope: str | None, name: str) -> bool:
    return name in split_scope(scope)


def validate_scope_subset(requested: list[str], allowed: list[str]) -> list[str]:
    """请求的 scope 必须是**平台支持**且**该客户端已注册**的子集（§7.5 防提权）。"""
    unsupported = [item for item in requested if item not in SUPPORTED_SCOPES]
    if unsupported:
        raise api_error(400, "invalid_scope", f"平台不支持的 scope：{' '.join(unsupported)}")

    forbidden = [item for item in requested if item not in allowed]
    if forbidden:
        raise api_error(400, "invalid_scope", f"该客户端未被授权使用 scope：{' '.join(forbidden)}")

    return list(requested)


# ------------------------------------------------------------------- PKCE


def pkce_challenge_s256(verifier: str) -> str:
    """BASE64URL(SHA256(ASCII(code_verifier)))，无 padding（RFC 7636 §4.2）。"""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pkce_verifier_looks_valid(verifier: str | None) -> bool:
    if not verifier:
        return False
    if not (PKCE_VERIFIER_MIN <= len(verifier) <= PKCE_VERIFIER_MAX):
        return False
    return bool(_UNRESERVED_RE.match(verifier))


def pkce_matches(verifier: str | None, challenge: str | None) -> bool:
    """校验 code_verifier 是否匹配 S256 challenge；任何异常输入都返回 False。

    只有 S256 —— ``plain`` 一律拒绝（§2.3、§7.2）。
    """
    if not challenge or not pkce_verifier_looks_valid(verifier):
        return False
    try:
        expected = pkce_challenge_s256(verifier or "")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(expected, challenge)


def ensure_pkce_s256(method: str | None) -> str:
    """只接受 S256；缺失或 plain 都拒绝。"""
    normalized = (method or "").strip()
    if normalized != CODE_CHALLENGE_S256:
        raise api_error(400, "invalid_request", "code_challenge_method 只支持 S256")
    return normalized


# --------------------------------------------------------------- 客户端断言


def ensure_public_client_requires_pkce(client_type: str, code_challenge: str | None) -> None:
    """公开客户端必须带 PKCE（§5.1、§7.2）。"""
    from .constants import CLIENT_TYPE_PUBLIC

    if client_type == CLIENT_TYPE_PUBLIC and not code_challenge:
        raise api_error(400, "invalid_request", "公开客户端必须提供 code_challenge")

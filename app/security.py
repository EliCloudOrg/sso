"""密码哈希、口令强度校验、JWT 签发与验签。"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import timedelta
from typing import Any

import bcrypt
import jwt

from .claims import user_claims
from .config import Settings
from .errors import api_error
from .keys import KeyStore
from .models import User, parse_iso, to_iso, utcnow

logger = logging.getLogger(__name__)

BCRYPT_ROUNDS = 12
# bcrypt 只处理前 72 字节，超长口令会被静默截断——直接拒绝，行为可预期。
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64
MAX_USERNAME_LENGTH = 32
MIN_USERNAME_LENGTH = 3

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# 常见弱口令（只做最小拦截，避免引入额外数据依赖）
COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "passw0rd",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "iloveyou",
        "admin123",
        "abc12345",
        "elicloud",
        "elipese",
    }
)

_ALG_HEADER_NAME = "alg"


# ----------------------------------------------------------------- 口令哈希


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


_dummy_hash: str | None = None


def _dummy_password_hash() -> str:
    """用户不存在时也走一次 bcrypt 校验，避免用响应时间枚举用户。"""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(16))
    return _dummy_hash


def verify_password(password: str, password_hash: str | None) -> bool:
    candidate = password.encode("utf-8")
    target = password_hash if password_hash else _dummy_password_hash()
    try:
        matched = bcrypt.checkpw(candidate, target.encode("ascii"))
    except ValueError:
        return False
    return bool(matched) and password_hash is not None


# --------------------------------------------------------------- 输入校验


def validate_username(username: str) -> str:
    value = (username or "").strip()
    if not (MIN_USERNAME_LENGTH <= len(value) <= MAX_USERNAME_LENGTH):
        raise api_error(
            400,
            "invalid_request",
            f"用户名长度必须在 {MIN_USERNAME_LENGTH}~{MAX_USERNAME_LENGTH} 个字符之间",
        )
    if not USERNAME_RE.match(value):
        raise api_error(400, "invalid_request", "用户名只能包含字母、数字、下划线、点与连字符，且需以字母或数字开头")
    return value


def validate_password(password: str) -> str:
    value = password or ""
    if len(value) < MIN_PASSWORD_LENGTH:
        raise api_error(400, "invalid_request", f"密码至少 {MIN_PASSWORD_LENGTH} 位")
    if len(value) > MAX_PASSWORD_LENGTH:
        raise api_error(400, "invalid_request", f"密码最多 {MAX_PASSWORD_LENGTH} 位")
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise api_error(400, "invalid_request", f"密码的 UTF-8 编码不得超过 {MAX_PASSWORD_BYTES} 字节")
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise api_error(400, "invalid_request", "密码必须同时包含字母和数字")
    if value.lower() in COMMON_PASSWORDS:
        raise api_error(400, "invalid_request", "该密码过于常见，请更换")
    return value


def validate_email(email: str | None) -> str | None:
    if email is None:
        return None
    value = email.strip()
    if not value:
        return None
    if len(value) > 254 or not EMAIL_RE.match(value):
        raise api_error(400, "invalid_request", "邮箱格式不正确")
    return value.lower()


# ------------------------------------------------------------------ JWT


def create_access_token(
    settings: Settings,
    keystore: KeyStore,
    user: User,
    *,
    scope: str | None = None,
    client_id: str | None = None,
) -> tuple[str, int]:
    """签发 RS256 Access Token，返回 (token, expires_in 秒)。

    ``aud`` **保持** ``settings.audience``（业务服务按它校验），
    OIDC 客户端只额外写进 ``client_id`` claim 用于审计（docs/sso-oidc.md §4.1）。
    """
    issued_at = utcnow()
    expires_in = int(settings.access_token_ttl)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": user.id,
        "username": user.username,
        "scope": scope or settings.default_scope,
        "aud": settings.audience,
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(seconds=expires_in)).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    if client_id:
        payload["client_id"] = client_id
    token = jwt.encode(
        payload,
        keystore.signing_key,
        algorithm=settings.jwt_alg,
        headers={"kid": keystore.signing_kid, "typ": "JWT"},
    )
    # 只记 user_id / kid / 过期时间，绝不记令牌原文
    logger.info(
        "access token issued user=%s kid=%s expires_in=%s client=%s",
        user.id,
        keystore.signing_kid,
        expires_in,
        client_id or "-",
    )
    return token, expires_in


def create_id_token(
    settings: Settings,
    keystore: KeyStore,
    *,
    user: User,
    client_id: str,
    scopes: list[str],
    auth_time_iso: str | None,
    nonce: str | None = None,
) -> tuple[str, int]:
    """签发 id_token（docs/sso-oidc.md §4.2），返回 (token, expires_in 秒)。

    与 access token 的**关键区别**：

    * ``aud`` 是 **client_id**（不是业务服务用的 ``elicloud-services``）—— 两者最容易搞混；
    * ``auth_time`` 是用户**实际认证时间**，不是签发时间；
    * ``nonce`` 仅在授权请求带了 nonce 时原样回传；
    * 它**只用来证明身份，绝不能拿去访问业务 API**（业务服务按 aud 就会拒绝）。
    ``at_hash`` / ``c_hash`` 按 §13 一期不实现。
    """
    issued_at = utcnow()
    expires_in = int(settings.id_token_ttl)

    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": user.id,
        "aud": client_id,
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(seconds=expires_in)).timestamp()),
    }
    # auth_time 只在**真的知道**用户何时认证时出现：
    # 宁可省略，也不要用签发时间冒充认证时间（刷新流程里两者可能差很久）。
    if auth_time_iso:
        payload["auth_time"] = int(parse_iso(auth_time_iso).timestamp())
    if nonce:
        payload["nonce"] = nonce
    # 按 scope 附加身份 claim —— 与 /userinfo 共用同一份映射（app/claims.py）
    payload.update(user_claims(user, scopes))

    token = jwt.encode(
        payload,
        keystore.signing_key,
        algorithm=settings.jwt_alg,
        headers={"kid": keystore.signing_kid, "typ": "JWT"},
    )
    logger.info(
        "id_token issued user=%s aud=%s kid=%s expires_in=%s",
        user.id,
        client_id,
        keystore.signing_kid,
        expires_in,
    )
    return token, expires_in


def decode_id_token_hint(settings: Settings, keystore: KeyStore, token: str) -> dict[str, Any] | None:
    """校验 ``id_token_hint``（RP-Initiated Logout 用），失败返回 None。

    ``id_token_hint`` 通常**已经过期**，所以这里只校验**签名**与 ``iss``、不校验 ``exp``。
    但**绝不能跳过签名校验** —— 否则任何人都能伪造 ``aud`` 来操纵登出的回跳地址。
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return None

    if str(header.get(_ALG_HEADER_NAME, "")).upper() != settings.jwt_alg:
        return None

    kid = header.get("kid")
    public_key = keystore.public_key_for(str(kid) if kid is not None else None)
    if public_key is None:
        return None

    try:
        return jwt.decode(
            token,
            key=public_key,
            algorithms=[settings.jwt_alg],
            issuer=settings.issuer,
            options={"verify_aud": False, "verify_exp": False, "require": ["iss", "sub"]},
        )
    except jwt.PyJWTError:
        return None


def decode_access_token(settings: Settings, keystore: KeyStore, token: str) -> dict[str, Any]:
    """验签并校验 iss/aud/exp；任何失败都抛 401。

    显式白名单：只接受 RS256。HS256 与 alg:none 都会被拒（alg:none 在取 header 时即被拦下）。
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise api_error(401, "invalid_token", "令牌格式不合法") from exc

    alg = str(header.get(_ALG_HEADER_NAME, "")).upper()
    if alg != settings.jwt_alg:
        raise api_error(401, "invalid_token", "令牌签名算法不被接受")

    kid = header.get("kid")
    public_key = keystore.public_key_for(str(kid) if kid is not None else None)
    if public_key is None:
        raise api_error(401, "invalid_token", "令牌引用了未知的 kid")

    try:
        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=[settings.jwt_alg],
            audience=settings.audience,
            issuer=settings.issuer,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise api_error(401, "invalid_token", "令牌已过期") from exc
    except jwt.PyJWTError as exc:
        raise api_error(401, "invalid_token", "令牌校验失败") from exc

    return claims


# --------------------------------------------------------- Refresh Token


def new_refresh_token() -> str:
    return f"rt_{secrets.token_urlsafe(32)}"


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_token_expiry_iso(settings: Settings) -> str:
    return to_iso(utcnow() + timedelta(seconds=int(settings.refresh_token_ttl)))

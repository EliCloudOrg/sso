"""浏览器登录会话与 CSRF（docs/sso-oidc.md §6.2、§7.11、§7.15、§7.16）。

安全要点：

* cookie 值 ``secrets.token_urlsafe(32)``，库里**只存 SHA-256**（与 refresh token 同等对待）；
* 属性固定为 ``HttpOnly`` + ``SameSite=Lax`` + ``Path=<对外前缀>`` + ``Secure``（https 阶段）；
* **防会话固定**：登录成功一律**新建**会话，并撤销请求里带的旧会话，绝不复用；
* CSRF 用「双重提交 cookie」：cookie 与表单里各放一份随机值，服务端常量时间比对。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from fastapi import Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .config import Settings
from .models import RefreshToken, UserSession, parse_iso, to_iso, utcnow

CSRF_COOKIE_SUFFIX = "_csrf"
SESSION_SAMESITE = "lax"


def hash_session_value(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ CSRF


def csrf_cookie_name(settings: Settings) -> str:
    return f"{settings.session_cookie_name}{CSRF_COOKIE_SUFFIX}"


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf(request: Request, settings: Settings, submitted: str | None) -> bool:
    """双重提交：表单里的值必须与 cookie 里的值相同（常量时间比较）。"""
    cookie_value = request.cookies.get(csrf_cookie_name(settings))
    if not cookie_value or not submitted:
        return False
    return hmac.compare_digest(str(submitted), str(cookie_value))


def set_csrf_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        csrf_cookie_name(settings),
        token,
        max_age=settings.session_ttl,
        path=settings.cookie_path,
        httponly=True,
        samesite=SESSION_SAMESITE,
        secure=settings.cookie_secure,
    )


# ----------------------------------------------------------------- 会话


def get_session_from_request(db: DbSession, request: Request, settings: Settings) -> UserSession | None:
    """从 cookie 解析出有效会话；不存在/已撤销/已过期都返回 None。"""
    raw = request.cookies.get(settings.session_cookie_name)
    if not raw:
        return None

    row = db.scalar(select(UserSession).where(UserSession.session_hash == hash_session_value(raw)))
    if row is None or row.revoked_at is not None:
        return None
    if parse_iso(row.expires_at) <= utcnow():
        return None
    return row


def create_session(
    db: DbSession,
    *,
    user_id: str,
    settings: Settings,
    ip: str | None,
    user_agent: str | None,
) -> tuple[UserSession, str]:
    """新建会话，返回 (记录, cookie 明文)。调用方负责 commit。"""
    raw = secrets.token_urlsafe(32)
    now = utcnow()
    row = UserSession(
        id=f"sess_{secrets.token_hex(12)}",
        user_id=user_id,
        session_hash=hash_session_value(raw),
        auth_time=to_iso(now),
        expires_at=to_iso(now + timedelta(seconds=settings.session_ttl)),
        created_at=to_iso(now),
        ip=ip,
        user_agent=(user_agent or "")[:256] or None,
    )
    db.add(row)
    return row, raw


def revoke_session(db: DbSession, row: UserSession | None, *, reason: str) -> None:
    if row is None or row.revoked_at is not None:
        return
    row.revoked_at = to_iso(utcnow())


def revoke_session_chains(db: DbSession, session_id: str | None, *, reason: str) -> int:
    """撤销"某个登录会话派生出来的"全部 refresh 链。

    标准 logout 用它：只杀掉这个浏览器会话产生的链，**不误伤同一账号在其它设备上的登录**
    （这正是当初给 refresh_tokens 加 session_id 的原因）。
    """
    if not session_id:
        return 0

    from .tokens import revoke_family  # 局部导入：tokens 也依赖 models，避免顶层循环

    family_ids = db.scalars(
        select(RefreshToken.family_id)
        .where(RefreshToken.session_id == session_id)
        .distinct()
    ).all()

    revoked = 0
    for family_id in family_ids:
        revoked += revoke_family(db, family_id, reason=reason)
    return revoked


def set_session_cookie(response: Response, settings: Settings, raw: str) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        raw,
        max_age=settings.session_ttl,
        path=settings.cookie_path,
        httponly=True,
        samesite=SESSION_SAMESITE,
        secure=settings.cookie_secure,
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        settings.session_cookie_name,
        path=settings.cookie_path,
        httponly=True,
        samesite=SESSION_SAMESITE,
        secure=settings.cookie_secure,
    )
    response.delete_cookie(
        csrf_cookie_name(settings),
        path=settings.cookie_path,
        httponly=True,
        samesite=SESSION_SAMESITE,
        secure=settings.cookie_secure,
    )

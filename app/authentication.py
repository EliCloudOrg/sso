"""密码认证与登录限流：私有密码直连（`/v1/login`）与 OIDC 登录页（`/authorize`）共用。

抽出来的原因是安全语义必须只有一份，否则两条入口迟早会漂移
（docs/architecture.md §6.4、docs/sso-oidc.md §7.14）：

* 失败响应**逐字相同**，不区分「用户不存在 / 密码错误 / 账号被禁用」；
* 用户不存在时也执行一次 bcrypt 校验，避免用响应时间枚举账号；
* 密码正确但账号还在 pending 邮箱验证时，返回 403 email_not_verified（唯一例外）；
* 按 **IP + 登录标识** 双维度限流，成功后清零。

**登录标识可以是用户名或邮箱**（`find_user_by_identifier`）。注册时的用户名仍然只能是用户名
（`validate_username`），所以「用邮箱当用户名」这件事不存在，两种标识也不会互相冒充。
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session as DbSession

from .config import Settings
from .errors import api_error, limiter
from .models import User
from .registration import find_pending_by_identifier
from .security import verify_password
from .users import find_user_by_email, find_user_by_identifier, find_user_by_username

logger = logging.getLogger(__name__)

# 登录失败的统一响应（防枚举：三种失败原因共用）
LOGIN_FAILED_ERROR = "invalid_grant"
LOGIN_FAILED_DESCRIPTION = "账号或密码错误"
EMAIL_NOT_VERIFIED_ERROR = "email_not_verified"
EMAIL_NOT_VERIFIED_DESCRIPTION = "邮箱还没有验证，请先完成邮箱验证"


def login_rate_keys(ip: str, identifier: str | None) -> tuple[str, str]:
    return f"login:{ip}|{(identifier or '').strip().lower()}", f"login-ip:{ip}"


def enforce_login_rate_limit(settings: Settings, ip: str, identifier: str | None) -> None:
    per_user_key, per_ip_key = login_rate_keys(ip, identifier)
    allowed = limiter.allow(per_user_key, settings.login_attempts_per_window, settings.login_window_seconds)
    # 同一 IP 跨标识的总尝试放宽 5 倍，避免误伤共享出口
    allowed = allowed and limiter.allow(
        per_ip_key, settings.login_attempts_per_window * 5, settings.login_window_seconds
    )
    if not allowed:
        logger.warning("login rate limited ip=%s identifier=%s", ip, identifier)
        raise api_error(
            429,
            "too_many_requests",
            "登录尝试过于频繁，请稍后再试",
            headers={"Retry-After": str(int(settings.login_window_seconds))},
        )


def reset_login_rate_limit(ip: str, identifier: str | None) -> None:
    per_user_key, _ = login_rate_keys(ip, identifier)
    limiter.reset(per_user_key)


def authenticate(
    db: DbSession,
    *,
    identifier: str | None,
    password: str | None,
    ip: str,
    settings: Settings,
) -> User:
    """校验口令，成功返回 User；失败一律 401 且响应相同（pending 未验证除外）。

    ``identifier`` 是用户在登录页那一格里填的东西：用户名或邮箱都行。
    """
    enforce_login_rate_limit(settings, ip, identifier)

    user = find_user_by_identifier(db, identifier)
    if user is None:
        # 密码正确但账号还在 pending：明确告诉用户去完成邮箱验证；密码错误时
        # 仍然落到下面的统一 401，不泄露「这个标识正在注册」。
        pending = find_pending_by_identifier(db, identifier)
        if pending is not None and verify_password(password or "", pending.password_hash):
            logger.info("login pending email verification ip=%s", ip)
            raise api_error(403, EMAIL_NOT_VERIFIED_ERROR, EMAIL_NOT_VERIFIED_DESCRIPTION)

    password_ok = verify_password(password or "", user.password_hash if user else None)

    if user is None or not password_ok or user.status != "active":
        logger.info("login failed ip=%s identifier=%s", ip, identifier)
        raise api_error(401, LOGIN_FAILED_ERROR, LOGIN_FAILED_DESCRIPTION)

    reset_login_rate_limit(ip, identifier)
    return user

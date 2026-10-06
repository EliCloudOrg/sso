"""密码认证与登录限流：私有密码直连（`/v1/login`）与 OIDC 登录页（`/authorize`）共用。

抽出来的原因是安全语义必须只有一份，否则两条入口迟早会漂移
（docs/architecture.md §6.4、docs/sso-oidc.md §7.14）：

* 失败响应**逐字相同**，不区分「用户不存在 / 密码错误 / 账号被禁用」；
* 用户不存在时也执行一次 bcrypt 校验，避免用响应时间枚举账号；
* 按 **IP + 用户名** 双维度限流，成功后清零。
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from .config import Settings
from .errors import api_error, limiter
from .models import User
from .security import verify_password

logger = logging.getLogger(__name__)

# 登录失败的统一响应（防枚举：三种失败原因共用）
LOGIN_FAILED_ERROR = "invalid_grant"
LOGIN_FAILED_DESCRIPTION = "用户名或密码错误"


def find_user_by_username(db: DbSession, username: str | None) -> User | None:
    """大小写不敏感查找（注册时也用它做重名判断）。"""
    return db.scalar(select(User).where(func.lower(User.username) == (username or "").strip().lower()))


def login_rate_keys(ip: str, username: str | None) -> tuple[str, str]:
    return f"login:{ip}|{(username or '').strip().lower()}", f"login-ip:{ip}"


def enforce_login_rate_limit(settings: Settings, ip: str, username: str | None) -> None:
    per_user_key, per_ip_key = login_rate_keys(ip, username)
    allowed = limiter.allow(per_user_key, settings.login_attempts_per_window, settings.login_window_seconds)
    # 同一 IP 跨用户名的总尝试放宽 5 倍，避免误伤共享出口
    allowed = allowed and limiter.allow(
        per_ip_key, settings.login_attempts_per_window * 5, settings.login_window_seconds
    )
    if not allowed:
        logger.warning("login rate limited ip=%s username=%s", ip, username)
        raise api_error(
            429,
            "too_many_requests",
            "登录尝试过于频繁，请稍后再试",
            headers={"Retry-After": str(int(settings.login_window_seconds))},
        )


def reset_login_rate_limit(ip: str, username: str | None) -> None:
    per_user_key, _ = login_rate_keys(ip, username)
    limiter.reset(per_user_key)


def authenticate(
    db: DbSession,
    *,
    username: str | None,
    password: str | None,
    ip: str,
    settings: Settings,
) -> User:
    """校验用户名口令，成功返回 User；失败一律 401 且响应相同。"""
    enforce_login_rate_limit(settings, ip, username)

    user = find_user_by_username(db, username)
    password_ok = verify_password(password or "", user.password_hash if user else None)

    if user is None or not password_ok or user.status != "active":
        logger.info("login failed ip=%s username=%s", ip, username)
        raise api_error(401, LOGIN_FAILED_ERROR, LOGIN_FAILED_DESCRIPTION)

    reset_login_rate_limit(ip, username)
    return user

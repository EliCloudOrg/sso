"""私有认证路由：注册 / 登录 / 刷新（服务内路径为 /v1/*，/auth 前缀由网关处理）。

⚠️ 注销不在这里 —— 已按 docs/sso-oidc.md §1.3 的 A3 决策下线，统一走标准
RP-Initiated Logout（`GET|POST /logout`，见 app/routers/oidc.py）。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..authentication import authenticate, find_user_by_username
from ..config import Settings
from ..db import get_db
from ..deps import KeyStoreDep, SettingsDep, client_ip
from ..errors import api_error, limiter
from ..models import User, to_iso, utcnow
from ..security import (
    create_access_token,
    hash_password,
    validate_email,
    validate_password,
    validate_username,
)
from ..tokens import consume_refresh_token, issue_refresh_token, new_family_id, revoke_family

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["auth"])

MAX_USER_ID_ATTEMPTS = 5


# ------------------------------------------------------------------ 模型


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class PublicUser(BaseModel):
    id: str
    username: str
    email: str | None = None
    created_at: str | None = None


class RegisterResponse(BaseModel):
    user: PublicUser


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str
    scope: str
    user: PublicUser


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str


# ------------------------------------------------------------------ 工具


def _next_user_id(db: Session) -> str:
    """生成 user_0001 形式的递增 ID；并发下靠重试 + 主键冲突兜底。"""
    existing = db.scalars(select(User.id)).all()
    max_index = 0
    for value in existing:
        if value.startswith("user_"):
            suffix = value[5:]
            if suffix.isdigit():
                max_index = max(max_index, int(suffix))
    return f"user_{max_index + 1:04d}"


def _login_rate_keys_placeholder() -> None:  # pragma: no cover - 占位，见下
    """（已迁移到 app/authentication.py，此处仅保留文档说明位置。）"""


# ------------------------------------------------------------------ 接口


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(
    payload: RegisterRequest,
    request: Request,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> RegisterResponse:
    if not settings.allow_registration:
        raise api_error(403, "registration_disabled", "本平台未开放自助注册，请联系管理员建号")

    ip = client_ip(request)
    if not limiter.allow(f"register-ip:{ip}", 20, 3600):
        raise api_error(429, "too_many_requests", "注册请求过于频繁，请稍后再试", headers={"Retry-After": "3600"})

    username = validate_username(payload.username)
    password = validate_password(payload.password)
    email = validate_email(payload.email)

    if find_user_by_username(db, username) is not None:
        raise api_error(409, "user_exists", "该用户名已被占用")
    if email and db.scalar(select(User).where(func.lower(User.email) == email)) is not None:
        raise api_error(409, "email_exists", "该邮箱已被占用")

    now_iso = to_iso(utcnow())
    last_error: IntegrityError | None = None
    for _ in range(MAX_USER_ID_ATTEMPTS):
        user = User(
            id=_next_user_id(db),
            username=username,
            email=email,
            password_hash=hash_password(password),
            status="active",
            created_at=now_iso,
            updated_at=now_iso,
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            last_error = exc
            if find_user_by_username(db, username) is not None:
                raise api_error(409, "user_exists", "该用户名已被占用") from exc
            continue
        logger.info("user registered id=%s ip=%s", user.id, ip)
        return RegisterResponse(user=PublicUser(**user.to_public_dict()))

    raise api_error(409, "conflict", "注册冲突，请重试") from last_error


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    settings: SettingsDep,
    keystore: KeyStoreDep,
    db: Session = Depends(get_db),
) -> LoginResponse:
    ip = client_ip(request)
    # 反枚举 + 限流的语义统一在 app/authentication.py，OIDC 登录页共用同一份实现
    user = authenticate(db, username=payload.username, password=payload.password, ip=ip, settings=settings)

    access_token, expires_in = create_access_token(settings, keystore, user)
    refresh_token = issue_refresh_token(
        db,
        user_id=user.id,
        settings=settings,
        family_id=new_family_id(),
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    logger.info("login ok user=%s ip=%s", user.id, ip)

    return LoginResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=refresh_token,
        scope=settings.default_scope,
        user=PublicUser(**user.to_public_dict()),
    )


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    payload: RefreshRequest,
    request: Request,
    settings: SettingsDep,
    keystore: KeyStoreDep,
    db: Session = Depends(get_db),
) -> RefreshResponse:
    # 校验/重放检测/过期/一次性标记统一走 app/tokens.py（与 OIDC /token 共用一份实现）。
    # 这里用 401（JSON 私有端点语义），并禁止绑定了客户端的令牌在此兑换。
    row = consume_refresh_token(
        db,
        token=payload.refresh_token,
        error_status=401,
        forbid_client_id=True,
    )

    user = db.get(User, row.user_id)
    if user is None or user.status != "active":
        revoke_family(db, row.family_id, reason="user_unavailable")
        db.commit()
        raise api_error(401, "invalid_grant", "账号不可用")

    new_token = issue_refresh_token(
        db,
        user_id=user.id,
        settings=settings,
        family_id=row.family_id,  # 同一条链
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()

    access_token, expires_in = create_access_token(settings, keystore, user)
    logger.info("token refreshed user=%s family=%s", user.id, row.family_id)

    return RefreshResponse(access_token=access_token, expires_in=expires_in, refresh_token=new_token)


# 注意：私有 POST /v1/logout 已按 docs/sso-oidc.md §1.3 的决策（A3）**下线**。
# 登出统一走标准 RP-Initiated Logout：GET|POST /logout（见 app/routers/oidc.py）。
# 标准 logout 撤销的是"该浏览器会话派生的 refresh 链"；密码直连签发的令牌没有会话绑定，
# 因此这类客户端需要改用授权码 + PKCE 流程（见 README §18.4）。

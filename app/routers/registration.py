"""注册与邮箱验证路由（服务内路径，/auth 前缀由网关处理）。

公开：``POST /v1/register``、``/v1/register/status``、``/v1/register/resend``、
``/v1/register/cancel``。
内部：``POST /internal/email/verification`` —— 只给 email 容器调用，不在 /auth 路由下。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import get_db
from ..deps import SettingsDep, client_ip
from ..email_client import EmailServiceClient, EmailServiceError
from ..errors import api_error, limiter
from ..registration import (
    RegistrationAlreadyVerified,
    RegistrationCooldown,
    RegistrationConflict,
    RegistrationError,
    RegistrationExpired,
    RegistrationNotFound,
    cancel_registration,
    get_pending,
    get_status,
    handle_callback,
    mask_email,
    resend_after,
    resend_registration,
    start_registration,
)
from ..schemas import PublicUser
from ..security import validate_email, validate_password, validate_username, verify_callback_signature

logger = logging.getLogger(__name__)

router = APIRouter(tags=["registration"])


# ------------------------------------------------------------------ 模型


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str


class RegistrationRef(BaseModel):
    registration_id: str = Field(min_length=1, max_length=128)


class RegisterPendingResponse(BaseModel):
    registration_id: str
    status: str
    email_masked: str
    expires_at: str
    resend_after: int


class RegistrationStatusResponse(BaseModel):
    registration_id: str
    status: str
    email_masked: str
    expires_at: str
    resend_after: int
    user: PublicUser | None = None
    reason: str | None = None


# ------------------------------------------------------------------ 工具


def _email_client(request: Request, settings: Settings) -> EmailServiceClient:
    client = getattr(request.app.state, "email_client", None)
    if client is None or not settings.email_verification_enabled:
        raise api_error(503, "email_service_unavailable", "邮箱验证服务还没有配置，请稍后再试")
    return client


def _raise_registration_error(exc: RegistrationError) -> None:
    if isinstance(exc, RegistrationCooldown):
        retry = max(1, int(exc.retry_after or 60))
        raise api_error(429, exc.error, exc.description, headers={"Retry-After": str(retry)}) from exc
    if isinstance(exc, RegistrationConflict):
        status = 409
    elif isinstance(exc, RegistrationNotFound):
        status = 404
    elif isinstance(exc, RegistrationExpired):
        status = 410
    elif isinstance(exc, RegistrationAlreadyVerified):
        status = 409
    else:
        status = 400
    raise api_error(status, exc.error, exc.description) from exc


def _raise_email_error(exc: EmailServiceError) -> None:
    if exc.kind == "rate_limited":
        retry = max(1, int(exc.retry_after or 60))
        raise api_error(
            429,
            "too_many_requests",
            "验证邮件请求过于频繁，请稍后再试",
            headers={"Retry-After": str(retry)},
        ) from exc
    if exc.kind == "delivery_failed":
        raise api_error(502, "email_delivery_failed", "验证邮件发送失败，请稍后重试") from exc
    if exc.kind == "rejected":
        raise api_error(400, "invalid_request", exc.description) from exc
    raise api_error(503, "email_service_unavailable", "邮箱验证服务暂时不可用，请稍后重试") from exc


def _pending_response(row, settings: Settings) -> RegisterPendingResponse:
    return RegisterPendingResponse(
        registration_id=row.id,
        status=row.status,
        email_masked=mask_email(row.email),
        expires_at=row.expires_at,
        resend_after=resend_after(row, settings),
    )


def _status_response(view) -> RegistrationStatusResponse:
    user = PublicUser(**view.user) if view.user is not None else None
    return RegistrationStatusResponse(
        registration_id=view.registration_id,
        status=view.status,
        email_masked=view.email_masked,
        expires_at=view.expires_at,
        resend_after=view.resend_after,
        user=user,
        reason=view.reason,
    )


# ------------------------------------------------------------------ 公开接口


@router.post("/v1/register", response_model=RegisterPendingResponse, status_code=202)
def register(
    payload: RegisterRequest,
    request: Request,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> RegisterPendingResponse:
    if not settings.allow_registration:
        raise api_error(403, "registration_disabled", "本平台未开放自助注册，请联系管理员建号")

    ip = client_ip(request)
    if not limiter.allow(f"register-ip:{ip}", 20, 3600):
        raise api_error(
            429,
            "too_many_requests",
            "注册请求过于频繁，请稍后再试",
            headers={"Retry-After": "3600"},
        )

    username = validate_username(payload.username)
    password = validate_password(payload.password)
    email = validate_email(payload.email)
    if not email:
        raise api_error(400, "invalid_request", "注册必须填写邮箱")

    email_client = _email_client(request, settings)
    try:
        row = start_registration(
            db,
            settings,
            email_client,
            username=username,
            password=password,
            email=email,
            ip=ip,
        )
    except RegistrationError as exc:
        _raise_registration_error(exc)
    except EmailServiceError as exc:
        _raise_email_error(exc)

    logger.info("register pending id=%s ip=%s", row.id[:12], ip)
    return _pending_response(row, settings)


@router.post("/v1/register/status", response_model=RegistrationStatusResponse)
def register_status(
    payload: RegistrationRef,
    request: Request,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> RegistrationStatusResponse:
    ip = client_ip(request)
    if not limiter.allow(f"registration-status-ip:{ip}", 120, 60) or not limiter.allow(
        f"registration-status:{payload.registration_id}", 120, 60
    ):
        raise api_error(429, "too_many_requests", "查询太频繁，请稍后再试", headers={"Retry-After": "60"})

    email_client = _email_client(request, settings)
    view = get_status(db, settings, email_client, payload.registration_id)
    if view is None:
        raise api_error(404, "registration_not_found", "注册请求不存在或已取消")
    return _status_response(view)


@router.post("/v1/register/resend", response_model=RegisterPendingResponse, status_code=202)
def register_resend(
    payload: RegistrationRef,
    request: Request,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> RegisterPendingResponse:
    ip = client_ip(request)
    if not limiter.allow(f"registration-resend-ip:{ip}", 20, 3600) or not limiter.allow(
        f"registration-resend:{payload.registration_id}", 5, 3600
    ):
        raise api_error(
            429,
            "too_many_requests",
            "重发太频繁，请稍后再试",
            headers={"Retry-After": "3600"},
        )

    email_client = _email_client(request, settings)
    try:
        view = resend_registration(db, settings, email_client, payload.registration_id)
    except RegistrationError as exc:
        _raise_registration_error(exc)
    except EmailServiceError as exc:
        _raise_email_error(exc)

    return RegisterPendingResponse(
        registration_id=view.registration_id,
        status=view.status,
        email_masked=view.email_masked,
        expires_at=view.expires_at,
        resend_after=view.resend_after,
    )


@router.post("/v1/register/cancel", status_code=204)
def register_cancel(
    payload: RegistrationRef,
    request: Request,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> None:
    ip = client_ip(request)
    if not limiter.allow(f"registration-cancel-ip:{ip}", 20, 3600):
        raise api_error(429, "too_many_requests", "操作太频繁，请稍后再试", headers={"Retry-After": "3600"})
    try:
        cancel_registration(db, payload.registration_id)
    except RegistrationError as exc:
        _raise_registration_error(exc)
    return None


# ------------------------------------------------------------------ 内部回调


@router.post("/internal/email/verification", include_in_schema=False)
async def email_verification_callback(
    request: Request,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> JSONResponse:
    if not settings.email_callback_secret:
        return JSONResponse(
            status_code=503,
            content={"error": "email_callback_disabled", "error_description": "EMAIL_CALLBACK_SECRET 未配置"},
        )

    raw_body = await request.body()
    event = request.headers.get("x-elicloud-event")
    timestamp = request.headers.get("x-elicloud-timestamp")
    signature = request.headers.get("x-elicloud-signature")

    if event != "email.verification":
        return JSONResponse(status_code=400, content={"error": "invalid_event"})
    if not verify_callback_signature(settings.email_callback_secret, timestamp, raw_body, signature):
        logger.warning("email callback signature rejected")
        return JSONResponse(status_code=401, content={"error": "invalid_signature"})

    try:
        import json

        body = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "invalid_json"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "invalid_body"})
    if body.get("purpose") != "register" or body.get("source") != "sso":
        return JSONResponse(status_code=400, content={"error": "invalid_purpose"})

    metadata = body.get("metadata")
    if not isinstance(metadata, dict):
        return JSONResponse(status_code=400, content={"error": "invalid_metadata"})
    registration_id = str(metadata.get("registration_id") or "")
    status = str(body.get("status") or "")
    email = str(body.get("email") or "")
    if not registration_id or status not in {"approved", "denied"}:
        return JSONResponse(status_code=400, content={"error": "invalid_body"})

    row = get_pending(db, registration_id)
    if row is None:
        logger.warning("email callback unknown registration=%s", registration_id[:12])
        return JSONResponse(status_code=404, content={"error": "registration_not_found"})
    if (row.email or "").lower() != email.strip().lower():
        logger.warning("email callback email mismatch registration=%s", registration_id[:12])
        return JSONResponse(status_code=200, content={"status": "ignored"})

    verified = handle_callback(db, registration_id=registration_id, status=status, email=email)
    logger.info(
        "email callback registration=%s status=%s verified=%s",
        registration_id[:12],
        status,
        verified,
    )
    return JSONResponse(status_code=200, content={"status": "ok"})

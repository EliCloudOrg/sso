"""注册邮箱验证的领域逻辑。

状态机（``pending_registrations.status``）::

    pending --callback approved--> verified
    pending --callback denied / 超时 / 对账 denied--> expired
    pending --最终建号冲突 / 邮件发送失败--> failed
    pending --用户取消--> cancelled

账号只在 ``verified`` 时创建；email 服务只负责发信、确认与回调，不保存账号，
也不提供 ``trusted?email=`` 这类全局可信邮箱判断。
"""

from __future__ import annotations

import logging
import math
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session as DbSession

from .config import Settings
from .email_client import EmailServiceClient, EmailServiceError
from .models import PendingRegistration, User, parse_iso, to_iso, utcnow
from .security import hash_password, verify_password
from .users import UserConflict, create_user, find_user_by_email, find_user_by_username

logger = logging.getLogger(__name__)

PENDING = "pending"
VERIFIED = "verified"
EXPIRED = "expired"
FAILED = "failed"
CANCELLED = "cancelled"

ACTIVE_STATUSES = frozenset({PENDING, FAILED, EXPIRED})
TERMINAL_STATUSES = frozenset({VERIFIED, EXPIRED, FAILED, CANCELLED})


# ------------------------------------------------------------------ 异常


class RegistrationError(RuntimeError):
    """注册领域错误的基类；路由层把它映射成稳定的 API 错误码。"""

    def __init__(self, error: str, description: str, *, retry_after: int | None = None) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.retry_after = retry_after


class RegistrationConflict(RegistrationError):
    def __init__(self, field: str, description: str) -> None:
        super().__init__(field, description)
        self.field = field


class RegistrationNotFound(RegistrationError):
    def __init__(self) -> None:
        super().__init__("registration_not_found", "注册请求不存在或已取消")


class RegistrationAlreadyVerified(RegistrationError):
    def __init__(self) -> None:
        super().__init__("already_verified", "邮箱已经验证过了，直接登录即可")


class RegistrationExpired(RegistrationError):
    def __init__(self) -> None:
        super().__init__("registration_expired", "这次注册已经过期，请重新创建账号")


class RegistrationCooldown(RegistrationError):
    def __init__(self, retry_after: int) -> None:
        super().__init__(
            "too_many_requests",
            "验证邮件刚刚发过，请稍后再试",
            retry_after=retry_after,
        )


# ------------------------------------------------------------------ 视图


@dataclass(frozen=True)
class RegistrationView:
    registration_id: str
    status: str
    email_masked: str
    expires_at: str
    resend_after: int
    user: dict[str, object] | None = None
    reason: str | None = None


# ------------------------------------------------------------------ 工具


def new_registration_id() -> str:
    return f"reg_{secrets.token_urlsafe(24)}"


def mask_email(email: str) -> str:
    value = (email or "").strip()
    if "@" not in value:
        return "***"
    local, domain = value.split("@", 1)
    if len(local) <= 1:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def _moment(now: datetime | None) -> datetime:
    return now or utcnow()


def _elapsed_seconds(start_iso: str | None, now: datetime) -> float | None:
    if not start_iso:
        return None
    try:
        return (now - parse_iso(start_iso)).total_seconds()
    except (TypeError, ValueError):
        return None


def resend_after(row: PendingRegistration, settings: Settings, now: datetime | None = None) -> int:
    """剩余重发冷却秒数（0 = 可以立即重发）。"""
    return _resend_after(row, settings, _moment(now))


def _resend_after(row: PendingRegistration, settings: Settings, now: datetime) -> int:
    if row.status != PENDING or not row.email_sent_at:
        return 0
    elapsed = _elapsed_seconds(row.email_sent_at, now)
    if elapsed is None:
        return 0
    # +1 秒安全边界：避免 SSO 与 email 服务的 60 秒冷却在边界上互相打脸。
    return max(0, int(math.ceil(settings.email_resend_cooldown_seconds - elapsed)) + 1)


def _is_expired(row: PendingRegistration, now: datetime) -> bool:
    try:
        return parse_iso(row.expires_at) <= now
    except (TypeError, ValueError):
        return True


def _mark_expired(db: DbSession, row: PendingRegistration, now: datetime) -> None:
    if row.status in (PENDING, FAILED):
        row.status = EXPIRED
        row.updated_at = to_iso(now)
        row.failure_reason = row.failure_reason or "timeout"
        db.commit()


def _mark_failed(db: DbSession, row: PendingRegistration, reason: str, now: datetime) -> None:
    row.status = FAILED
    row.failure_reason = reason[:200]
    row.updated_at = to_iso(now)
    db.commit()


# ------------------------------------------------------------------ 查询


def get_pending(db: DbSession, registration_id: str) -> PendingRegistration | None:
    value = (registration_id or "").strip()
    if not value:
        return None
    return db.get(PendingRegistration, value)


def _find_by_username(db: DbSession, username: str) -> PendingRegistration | None:
    return db.scalar(
        select(PendingRegistration).where(
            PendingRegistration.username_lower == (username or "").strip().lower()
        )
    )


def _find_by_email(db: DbSession, email: str) -> PendingRegistration | None:
    return db.scalar(
        select(PendingRegistration).where(
            PendingRegistration.email_lower == (email or "").strip().lower()
        )
    )


def find_pending_by_identifier(db: DbSession, identifier: str | None) -> PendingRegistration | None:
    """登录时判断「账号还没验证」用；只返回仍可恢复的 pending 行。"""
    value = (identifier or "").strip()
    if not value:
        return None
    row = _find_by_username(db, value) or _find_by_email(db, value)
    if row is None or row.status in (VERIFIED, CANCELLED):
        return None
    return row


# ------------------------------------------------------------------ 清理


def cleanup(db: DbSession, settings: Settings, *, now: datetime | None = None) -> None:
    """惰性清理：过期 pending 置 expired；终态超过保留期删除。"""
    moment = _moment(now)
    now_iso = to_iso(moment)

    expired_rows = list(
        db.scalars(
            select(PendingRegistration).where(
                PendingRegistration.status == PENDING,
                PendingRegistration.expires_at <= now_iso,
            )
        )
    )
    for row in expired_rows:
        _mark_expired(db, row, moment)
    if expired_rows:
        db.commit()
        logger.info("registration cleanup expired=%s", len(expired_rows))

    if settings.registration_retention_days <= 0:
        return
    cutoff = to_iso(moment - timedelta(days=settings.registration_retention_days))
    db.execute(
        delete(PendingRegistration).where(
            PendingRegistration.status.in_(tuple(TERMINAL_STATUSES)),
            PendingRegistration.updated_at < cutoff,
        )
    )
    db.commit()


# ------------------------------------------------------------------ 发信


def _send_verification(
    db: DbSession,
    settings: Settings,
    email_client: EmailServiceClient,
    row: PendingRegistration,
    *,
    now: datetime | None = None,
) -> None:
    moment = _moment(now)
    if not settings.email_verification_enabled:
        _mark_failed(db, row, "email_service_unavailable", moment)
        raise EmailServiceError("unavailable", "注册邮箱验证未配置")

    try:
        created = email_client.create_verification(
            email=row.email,
            purpose="register",
            callback_url=settings.email_callback_url,
            metadata={"registration_id": row.id},
            expires_in=int(settings.email_verification_ttl_seconds),
        )
    except EmailServiceError as exc:
        _mark_failed(db, row, exc.kind, moment)
        raise

    row.email_request_id = created.id
    row.email_sent_at = to_iso(moment)
    row.expires_at = created.expires_at
    row.status = PENDING
    row.failure_reason = None
    row.updated_at = to_iso(moment)
    db.commit()
    logger.info("registration verification sent registration=%s", row.id[:12])


# ------------------------------------------------------------------ 开始注册


def start_registration(
    db: DbSession,
    settings: Settings,
    email_client: EmailServiceClient,
    *,
    username: str,
    password: str,
    email: str,
    ip: str | None = None,
    now: datetime | None = None,
) -> PendingRegistration:
    """创建或恢复一条待验证注册；成功返回 pending 行。

    同名/同邮箱且密码匹配 = 恢复（用户关闭应用后重新提交同一表单）。
    """
    moment = _moment(now)
    cleanup(db, settings, now=moment)

    if find_user_by_username(db, username) is not None:
        raise RegistrationConflict("user_exists", "该用户名已被占用")
    if find_user_by_email(db, email) is not None:
        raise RegistrationConflict("email_exists", "该邮箱已被占用")

    matches = list(
        db.scalars(
            select(PendingRegistration).where(
                or_(
                    PendingRegistration.username_lower == username.strip().lower(),
                    PendingRegistration.email_lower == email.strip().lower(),
                )
            )
        )
    )
    if len(matches) > 1:
        raise RegistrationConflict("registration_pending", "该用户名或邮箱正在注册中，请稍后再试")

    if matches:
        row = matches[0]
        email_changed = row.email_lower != email.strip().lower()
        if not verify_password(password, row.password_hash):
            raise RegistrationConflict("registration_pending", "该用户名或邮箱正在注册中，请使用原来的密码继续")
        if row.status == VERIFIED:
            raise RegistrationConflict("user_exists", "该账号已经注册完成，请直接登录")
        if row.status == CANCELLED:
            db.delete(row)
            db.commit()
        else:
            # failed / expired 可以恢复；pending 保持原 id。
            row.username = username
            row.username_lower = username.strip().lower()
            row.email = email
            row.email_lower = email.strip().lower()
            row.updated_at = to_iso(moment)
            if row.status != PENDING:
                row.status = PENDING
                row.failure_reason = None
                row.email_sent_at = None
                row.email_request_id = None
                row.expires_at = to_iso(moment + timedelta(seconds=settings.email_verification_ttl_seconds))
            db.commit()

            resend_after = _resend_after(row, settings, moment)
            if resend_after > 0 and row.email_request_id and not email_changed:
                return row
            _send_verification(db, settings, email_client, row, now=moment)
            return row

    row = PendingRegistration(
        id=new_registration_id(),
        username=username,
        username_lower=username.strip().lower(),
        email=email,
        email_lower=email.strip().lower(),
        password_hash=hash_password(password),
        status=PENDING,
        email_request_id=None,
        email_sent_at=None,
        last_reconciled_at=None,
        expires_at=to_iso(moment + timedelta(seconds=settings.email_verification_ttl_seconds)),
        verified_at=None,
        user_id=None,
        failure_reason=None,
        created_at=to_iso(moment),
        updated_at=to_iso(moment),
        ip=ip,
    )
    db.add(row)
    db.commit()
    _send_verification(db, settings, email_client, row, now=moment)
    return row


# ------------------------------------------------------------------ 状态 / 重发 / 取消


def _reconcile(
    db: DbSession,
    settings: Settings,
    email_client: EmailServiceClient,
    row: PendingRegistration,
    *,
    now: datetime,
) -> None:
    if row.status != PENDING or not row.email_request_id:
        return
    elapsed = _elapsed_seconds(row.last_reconciled_at, now)
    if elapsed is not None and elapsed < settings.email_reconcile_seconds:
        return

    row.last_reconciled_at = to_iso(now)
    db.commit()
    try:
        status = email_client.get_verification(row.email_request_id)
    except EmailServiceError as exc:
        logger.info("registration reconcile skipped registration=%s kind=%s", row.id[:12], exc.kind)
        return

    if status.status == "approved":
        finalize_verified(db, row, now=now)
    elif status.status in ("denied", "failed"):
        _mark_expired(db, row, now)


def get_status(
    db: DbSession,
    settings: Settings,
    email_client: EmailServiceClient,
    registration_id: str,
    *,
    now: datetime | None = None,
) -> RegistrationView | None:
    moment = _moment(now)
    row = get_pending(db, registration_id)
    if row is None or row.status == CANCELLED:
        return None

    if row.status == PENDING and _is_expired(row, moment):
        _mark_expired(db, row, moment)
    elif row.status == PENDING:
        _reconcile(db, settings, email_client, row, now=moment)

    user = None
    if row.status == VERIFIED:
        if row.user_id:
            user_row = db.get(User, row.user_id)
        else:
            user_row = find_user_by_email(db, row.email) or find_user_by_username(db, row.username)
        if user_row is not None:
            user = user_row.to_public_dict()

    return RegistrationView(
        registration_id=row.id,
        status=row.status,
        email_masked=mask_email(row.email),
        expires_at=row.expires_at,
        resend_after=_resend_after(row, settings, moment),
        user=user,
        reason=row.failure_reason,
    )


def resend_registration(
    db: DbSession,
    settings: Settings,
    email_client: EmailServiceClient,
    registration_id: str,
    *,
    now: datetime | None = None,
) -> RegistrationView:
    moment = _moment(now)
    row = get_pending(db, registration_id)
    if row is None or row.status == CANCELLED:
        raise RegistrationNotFound()
    if row.status == VERIFIED:
        raise RegistrationAlreadyVerified()
    if settings.registration_retention_days > 0:
        age = _elapsed_seconds(row.updated_at, moment)
        if age is not None and age > settings.registration_retention_days * 86400:
            raise RegistrationExpired()

    resend_after = _resend_after(row, settings, moment)
    if resend_after > 0:
        raise RegistrationCooldown(resend_after)

    row.status = PENDING
    row.failure_reason = None
    row.expires_at = to_iso(moment + timedelta(seconds=settings.email_verification_ttl_seconds))
    row.last_reconciled_at = None
    row.updated_at = to_iso(moment)
    db.commit()
    _send_verification(db, settings, email_client, row, now=moment)

    return RegistrationView(
        registration_id=row.id,
        status=row.status,
        email_masked=mask_email(row.email),
        expires_at=row.expires_at,
        resend_after=_resend_after(row, settings, moment),
    )


def cancel_registration(
    db: DbSession,
    registration_id: str,
    *,
    now: datetime | None = None,
) -> None:
    row = get_pending(db, registration_id)
    if row is None or row.status == CANCELLED:
        return
    if row.status == VERIFIED:
        raise RegistrationAlreadyVerified()
    row.status = CANCELLED
    row.updated_at = to_iso(_moment(now))
    db.commit()
    logger.info("registration cancelled registration=%s", row.id[:12])


# ------------------------------------------------------------------ 回调 finalize


def finalize_verified(
    db: DbSession,
    row: PendingRegistration,
    *,
    now: datetime | None = None,
) -> bool:
    """把已确认的 pending 注册变成 users 行；返回是否处于 verified。"""
    moment = _moment(now)
    if row.status == VERIFIED:
        return True
    if row.status == CANCELLED:
        return False
    if _is_expired(row, moment):
        _mark_expired(db, row, moment)
        return False

    # 幂等恢复：如果上一轮已经建了用户但没来得及回填 pending，就认领它。
    existing_by_email = find_user_by_email(db, row.email)
    if existing_by_email is not None:
        if existing_by_email.username.lower() == row.username_lower:
            row.status = VERIFIED
            row.user_id = existing_by_email.id
            row.verified_at = row.verified_at or to_iso(moment)
            row.updated_at = to_iso(moment)
            db.commit()
            return True
        _mark_failed(db, row, "email_taken", moment)
        return False

    existing_by_username = find_user_by_username(db, row.username)
    if existing_by_username is not None:
        _mark_failed(db, row, "username_taken", moment)
        return False

    try:
        user = create_user(
            db,
            username=row.username,
            email=row.email,
            password_hash=row.password_hash,
            email_verified_at=to_iso(moment),
            status="active",
        )
    except UserConflict as exc:
        _mark_failed(db, row, f"{exc.field}_taken", moment)
        return False

    row.status = VERIFIED
    row.user_id = user.id
    row.verified_at = to_iso(moment)
    row.updated_at = to_iso(moment)
    db.commit()
    logger.info("registration verified registration=%s user=%s", row.id[:12], user.id)
    return True


def handle_callback(
    db: DbSession,
    *,
    registration_id: str,
    status: str,
    email: str,
    now: datetime | None = None,
) -> bool:
    """处理 email 服务回调；返回是否已 verified（用于 2xx 语义）。"""
    moment = _moment(now)
    row = get_pending(db, registration_id)
    if row is None:
        return False
    if (row.email or "").lower() != (email or "").strip().lower():
        logger.warning("registration callback email mismatch registration=%s", row.id[:12])
        return False
    if status == "approved":
        return finalize_verified(db, row, now=moment)
    if status == "denied":
        _mark_expired(db, row, moment)
        return False
    return False

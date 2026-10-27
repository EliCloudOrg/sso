"""用户查询与创建：注册回调、登录、CLI 共用同一份实现。

把「用户 ID 生成 + 唯一冲突判定 + 创建 users 行」集中在这里，避免
``/v1/register`` 与邮箱验证回调各写一份、慢慢漂移。
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from .models import User, to_iso, utcnow

MAX_USER_ID_ATTEMPTS = 5


class UserConflict(Exception):
    """用户名或邮箱已被占用。"""

    def __init__(self, field: str, description: str) -> None:
        super().__init__(description)
        self.field = field
        self.description = description


def find_user_by_username(db: DbSession, username: str | None) -> User | None:
    """按用户名大小写不敏感查找。"""
    return db.scalar(select(User).where(func.lower(User.username) == (username or "").strip().lower()))


def find_user_by_email(db: DbSession, email: str | None) -> User | None:
    """按邮箱大小写不敏感查找（邮箱在注册时已统一小写）。"""
    return db.scalar(select(User).where(func.lower(User.email) == (email or "").strip().lower()))


def find_user_by_identifier(db: DbSession, identifier: str | None) -> User | None:
    """登录标识：先当用户名找，找不到再当邮箱找（两种标识不会互相冒充）。"""
    return find_user_by_username(db, identifier) or find_user_by_email(db, identifier)


def next_user_id(db: DbSession) -> str:
    """生成 user_0001 形式的递增 ID；并发下靠重试 + 主键冲突兜底。"""
    existing = db.scalars(select(User.id)).all()
    max_index = 0
    for value in existing:
        if value.startswith("user_"):
            suffix = value[5:]
            if suffix.isdigit():
                max_index = max(max_index, int(suffix))
    return f"user_{max_index + 1:04d}"


def create_user(
    db: DbSession,
    *,
    username: str,
    email: str | None,
    password_hash: str,
    email_verified_at: str | None = None,
    status: str = "active",
) -> User:
    """创建并提交一个 users 行；唯一冲突抛 :class:`UserConflict`。

    ID 冲突会重试；用户名/邮箱冲突直接抛异常，由调用方转成 409 或把
    pending 注册标记为 failed。
    """
    last_error: IntegrityError | None = None
    for _ in range(MAX_USER_ID_ATTEMPTS):
        now_iso = to_iso(utcnow())
        user = User(
            id=next_user_id(db),
            username=username,
            email=email,
            password_hash=password_hash,
            email_verified_at=email_verified_at,
            status=status,
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
                raise UserConflict("username", "该用户名已被占用") from exc
            if email and find_user_by_email(db, email) is not None:
                raise UserConflict("email", "该邮箱已被占用") from exc
            continue
        db.refresh(user)
        return user

    raise UserConflict("conflict", "注册冲突，请重试") from last_error

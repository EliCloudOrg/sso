"""RFC 8628 设备授权流程（docs/sso-oidc.md §2.5、§3.2、§7.9、§7.14）。

适用于**没有浏览器**的客户端（CLI、桌面工具）：客户端拿 ``device_code`` 轮询，
人在浏览器里输入人读短码 ``user_code`` 完成授权。

安全要点：

* 短码用**无歧义字符集**（去掉 ``0/O/1/I/L``），TTL 短（默认 600 秒）；
* 「短码不存在」与「短码已过期」对用户给出**完全相同**的提示（防枚举，§7.14）；
* ``device_code`` 绑定到发起它的 ``client_id``，别的客户端不能代领；
* **一次性**：兑换成功后置为 ``used``，同一次批准不会被反复换成令牌。
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from .constants import (
    DEVICE_MAX_POLL_INTERVAL,
    DEVICE_SLOW_DOWN_STEP,
    DEVICE_STATUS_APPROVED,
    DEVICE_STATUS_DENIED,
    DEVICE_STATUS_EXPIRED,
    DEVICE_STATUS_PENDING,
    DEVICE_STATUS_USED,
    USER_CODE_ALPHABET,
    USER_CODE_LENGTH,
)
from .errors import api_error
from .models import DeviceCode, OAuthClient, parse_iso, to_iso, utcnow

# scope 的中文说明，用于确认页（一期不做精细品牌化）
SCOPE_LABELS: dict[str, str] = {
    "openid": "确认你的身份",
    "profile": "读取你的用户名",
    "email": "读取你的邮箱",
    "offline_access": "在你离线时保持登录（长期访问）",
    "pdf:read": "PDF 解密：查看任务",
    "pdf:write": "PDF 解密：提交任务",
    "mc:whitelist": "MC 白名单：提交游戏名",
}

USER_CODE_RE = re.compile(rf"^[A-Z0-9]{{{USER_CODE_LENGTH}}}$")


def hash_device_code(device_code: str) -> str:
    return hashlib.sha256(device_code.encode("utf-8")).hexdigest()


def generate_user_code() -> str:
    raw = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))
    return f"{raw[:4]}-{raw[4:]}"


def normalize_user_code(value: str | None) -> str:
    """规范化用户输入（大小写、有无连字符、多余空格都容忍）；格式不对返回空串。"""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", value or "").upper()
    if not USER_CODE_RE.match(cleaned):
        return ""
    return f"{cleaned[:4]}-{cleaned[4:]}"


def describe_scopes(scopes: list[str]) -> list[dict[str, str]]:
    return [{"name": scope, "label": SCOPE_LABELS.get(scope, scope)} for scope in scopes]


# ------------------------------------------------------------------ 创建


def create_device_code(
    db: DbSession,
    *,
    client: OAuthClient,
    scope: str,
    settings_ttl: int,
    interval_seconds: int,
    ip: str | None,
) -> tuple[str, DeviceCode]:
    """生成设备码与人读短码；返回 (device_code 明文, 记录)。"""
    for _ in range(5):
        user_code = generate_user_code()
        if db.scalar(select(DeviceCode.user_code).where(DeviceCode.user_code == user_code)) is not None:
            continue  # 极低概率撞码 → 换一个

        device_code = f"dc_{secrets.token_urlsafe(32)}"
        now = utcnow()
        row = DeviceCode(
            device_code_hash=hash_device_code(device_code),
            user_code=user_code,
            client_id=client.client_id,
            scope=scope,
            status=DEVICE_STATUS_PENDING,
            interval_seconds=interval_seconds,
            expires_at=to_iso(now + timedelta(seconds=settings_ttl)),
            created_at=to_iso(now),
            ip=ip,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            continue
        return device_code, row

    raise api_error(500, "server_error", "无法生成唯一设备码，请稍后重试")


# ------------------------------------------------------------------ 查询


def find_pending_by_user_code(db: DbSession, user_code: str | None) -> DeviceCode | None:
    """按短码找**仍可用**的设备码；找不到/已过期/格式不合法都返回 None。

    过期时顺带把它标记成 expired（只影响状态，不改变对用户的提示）。
    """
    normalized = normalize_user_code(user_code)
    if not normalized:
        return None

    row = db.scalar(select(DeviceCode).where(DeviceCode.user_code == normalized))
    if row is None:
        return None

    if parse_iso(row.expires_at) <= utcnow():
        if row.status != DEVICE_STATUS_EXPIRED:
            row.status = DEVICE_STATUS_EXPIRED
            db.commit()
        return None

    if row.status not in (DEVICE_STATUS_PENDING, DEVICE_STATUS_APPROVED):
        return None
    return row


# --------------------------------------------------------------- 用户决定


def approve_device_code(
    db: DbSession,
    row: DeviceCode,
    *,
    user_id: str,
    session_id: str | None,
    auth_time_iso: str | None,
) -> None:
    row.status = DEVICE_STATUS_APPROVED
    row.user_id = user_id
    row.session_id = session_id
    row.auth_time = auth_time_iso
    db.commit()


def deny_device_code(db: DbSession, row: DeviceCode) -> None:
    row.status = DEVICE_STATUS_DENIED
    db.commit()


# --------------------------------------------------------------- 客户端轮询


def consume_device_code(db: DbSession, *, device_code: str | None, client: OAuthClient) -> DeviceCode:
    """客户端轮询时校验 device_code；按 RFC 8628 §3.5 返回对应错误码。

    成功时**立即标记 used** 并返回该行（调用方据此签发令牌）。
    """
    if not device_code:
        raise api_error(400, "invalid_request", "缺少 device_code")

    row = db.scalar(select(DeviceCode).where(DeviceCode.device_code_hash == hash_device_code(device_code)))
    if row is None:
        raise api_error(400, "invalid_grant", "device_code 无效")

    if row.client_id != client.client_id:
        raise api_error(400, "invalid_grant", "device_code 与客户端不匹配")

    now = utcnow()

    # ① 终态先判：已过期 / 已拒绝 / 已兑换都要**立刻**给出确定答复，
    #    不能被"轮询过快"掩盖成 slow_down（否则客户端会一直重试一个已经结束的流程）。
    if parse_iso(row.expires_at) <= now:
        if row.status != DEVICE_STATUS_EXPIRED:
            row.status = DEVICE_STATUS_EXPIRED
            db.commit()
        raise api_error(400, "expired_token", "设备码已过期，请重新发起")

    if row.status == DEVICE_STATUS_DENIED:
        raise api_error(400, "access_denied", "用户拒绝了本次授权")

    if row.status == DEVICE_STATUS_USED:
        raise api_error(400, "invalid_grant", "device_code 已被使用")

    # ② 仍在等待用户时，才用 slow_down 约束轮询频率（RFC 8628 §3.5）
    if row.last_polled_at is not None:
        elapsed = (now - parse_iso(row.last_polled_at)).total_seconds()
        if elapsed < row.interval_seconds:
            # 递增步长有**上限**：否则过快轮询会把 interval 越顶越高，客户端永远追不上
            row.interval_seconds = min(row.interval_seconds + DEVICE_SLOW_DOWN_STEP, DEVICE_MAX_POLL_INTERVAL)
            row.last_polled_at = to_iso(now)
            db.commit()
            raise api_error(400, "slow_down", f"轮询过快，请每 {row.interval_seconds} 秒轮询一次")

    row.last_polled_at = to_iso(now)

    if row.status != DEVICE_STATUS_APPROVED:
        db.commit()
        raise api_error(400, "authorization_pending", "等待用户在浏览器中确认")

    # ③ 一次性：兑换成功即置 used，同一次批准不会被反复换成令牌
    row.status = DEVICE_STATUS_USED
    db.commit()
    return row

"""refresh token 的签发与撤销：私有密码直连（``/v1/refresh``）与 OIDC ``/token`` 共用。

抽出来的原因：**重放检测 / family 整链撤销**是安全核心，两条入口必须完全一致
（docs/sso-oidc.md §3.3、§7.4）。
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .config import Settings
from .errors import api_error
from .models import RefreshToken, UserSession, parse_iso, to_iso, utcnow
from .oidc import split_scope
from .security import hash_refresh_token, new_refresh_token, refresh_token_expiry_iso

logger = logging.getLogger(__name__)


def new_family_id() -> str:
    """一次登录 / 一次授权码兑换 = 一条链。"""
    return new_refresh_token()


def issue_refresh_token(
    db: DbSession,
    *,
    user_id: str,
    settings: Settings,
    family_id: str,
    client_id: str | None = None,
    scope: str | None = None,
    session_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> str:
    """签发不透明 refresh token；库里只存 SHA-256。返回明文（只此一次）。"""
    token = new_refresh_token()
    db.add(
        RefreshToken(
            id=f"rt_{hash_refresh_token(token)[:24]}",
            user_id=user_id,
            family_id=family_id,
            token_hash=hash_refresh_token(token),
            expires_at=refresh_token_expiry_iso(settings),
            created_at=to_iso(utcnow()),
            user_agent=(user_agent or "")[:256] or None,
            ip=ip,
            client_id=client_id,
            scope=scope,
            session_id=session_id,
        )
    )
    return token


def revoke_family(db: DbSession, family_id: str | None, *, reason: str) -> int:
    """撤销整条链（重放检测、登出、删除客户端时都用它）。"""
    if not family_id:
        return 0
    rows = db.scalars(
        select(RefreshToken).where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
    ).all()
    if rows:
        now_iso = to_iso(utcnow())
        for row in rows:
            row.revoked_at = now_iso
        logger.warning("refresh token family revoked family=%s reason=%s count=%s", family_id, reason, len(rows))
    return len(rows)


def resolve_auth_time(db: DbSession, *, session_id: str | None, family_id: str | None) -> str | None:
    """推断"用户最初认证的时间"，用于刷新时重新签发的 id_token。

    优先取登录会话的 ``auth_time``（最准确）；会话已过期时退化为**该令牌链最早一条**
    的创建时间（授权码兑换就紧跟在认证之后，误差只有秒级）。
    都取不到就返回 None —— 此时 ``id_token`` 会**省略** ``auth_time``，而不是拿签发时间冒充。
    """
    if session_id:
        session_row = db.get(UserSession, session_id)
        if session_row is not None:
            return session_row.auth_time

    if family_id:
        root = db.scalar(
            select(RefreshToken)
            .where(RefreshToken.family_id == family_id)
            .order_by(RefreshToken.created_at)
            .limit(1)
        )
        if root is not None:
            return root.created_at
    return None


def consume_refresh_token(
    db: DbSession,
    *,
    token: str | None,
    error_status: int = 400,
    require_client_id: str | None = None,
    forbid_client_id: bool = False,
    requested_scope: str | None = None,
) -> RefreshToken:
    """校验 refresh token 并**立即标记为已用**（一次性）；返回令牌行。

    调用方负责签发新令牌并 ``commit()``。

    两个端点共用这一份实现，因为**重放 → 整链撤销**、**过期 → 撤销**是安全核心，
    两份实现迟早会漂移；差异用显式参数表达：

    * ``error_status``：OIDC ``/token`` 用 400，私有 ``/v1/refresh`` 用 401；
    * ``require_client_id``：OIDC 端点要求令牌**绑定到发起它的客户端**
      （防止 A 客户端签发的 refresh token 被 B 客户端拿去换令牌）；
    * ``forbid_client_id``：私有端点只服务密码直连流程，因此**拒绝**绑定了客户端的令牌
      —— 否则 OIDC 令牌可以绕过客户端认证在私有端点兑换。
    * ``requested_scope``：刷新时可以**收窄**但不能**扩大**（RFC 6749 §6，防提权）。
    """
    if not token:
        raise api_error(error_status, "invalid_grant", "缺少 refresh_token")

    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(token)))
    if row is None:
        raise api_error(error_status, "invalid_grant", "refresh_token 无效")

    if row.revoked_at is not None:
        raise api_error(error_status, "invalid_grant", "refresh_token 已失效")

    if row.used_at is not None:
        # 重放：整链撤销，强制重新登录
        revoked = revoke_family(db, row.family_id, reason="replay_detected")
        db.commit()
        logger.warning(
            "refresh token replay detected family=%s user=%s revoked=%s",
            row.family_id,
            row.user_id,
            revoked,
        )
        raise api_error(error_status, "invalid_grant", "refresh_token 已被使用，该令牌链已全部撤销")

    if parse_iso(row.expires_at) <= utcnow():
        row.revoked_at = to_iso(utcnow())
        db.commit()
        raise api_error(error_status, "invalid_grant", "refresh_token 已过期")

    if forbid_client_id and row.client_id is not None:
        # 该令牌是 OIDC 流程签发的：必须在 /token 兑换并做客户端认证
        raise api_error(error_status, "invalid_grant", "该 refresh_token 不是本端点签发的，请改用 /token")

    if require_client_id is not None:
        if row.client_id is None:
            # 密码直连签发的令牌没有客户端绑定，不允许在标准端点使用
            raise api_error(error_status, "invalid_grant", "该 refresh_token 不是本端点签发的")
        if row.client_id != require_client_id:
            logger.warning(
                "refresh token client mismatch token_client=%s presented_by=%s",
                row.client_id,
                require_client_id,
            )
            raise api_error(error_status, "invalid_grant", "refresh_token 与客户端不匹配")

    if requested_scope:
        requested = split_scope(requested_scope)
        current = split_scope(row.scope)
        escalated = [item for item in requested if item not in current]
        if escalated:
            raise api_error(400, "invalid_scope", f"刷新时不能申请原 scope 之外的权限：{' '.join(escalated)}")

    row.used_at = to_iso(utcnow())
    return row

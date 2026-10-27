"""数据表定义（architecture.md §6.5 + sso-oidc.md §6.1）。

刻意只使用可迁移的通用类型（TEXT / 时间戳统一存 ISO8601 UTC 字符串），
JSON 数组以 TEXT 存 JSON 文本，SQLite 换 PostgreSQL 不改表结构。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import ForeignKey, Index, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .constants import (
    AUTH_METHOD_BASIC,
    AUTH_METHOD_NONE,
    AUTH_METHOD_POST,
    CLIENT_TYPE_CONFIDENTIAL,
    CLIENT_TYPE_PUBLIC,
    DEVICE_STATUS_APPROVED,
    DEVICE_STATUS_DENIED,
    DEVICE_STATUS_PENDING,
)

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(ISO_FORMAT)


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, ISO_FORMAT).replace(tzinfo=timezone.utc)


def dumps_list(values: list[str] | None) -> str:
    """去重且**保序**：scope 的惯例是 ``openid`` 打头，排序会把它挪到中间。"""
    ordered: list[str] = []
    for item in values or []:
        text = str(item)
        if text not in ordered:
            ordered.append(text)
    return json.dumps(ordered, ensure_ascii=False)


def loads_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # 如 user_0001，对外即 sub
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(Text, unique=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    # 邮箱被证明属于该账号的时间；NULL 表示未验证（历史账号/管理员建号默认如此）。
    email_verified_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False)

    @property
    def email_verified(self) -> bool:
        return bool(self.email and self.email_verified_at)

    def to_public_dict(self) -> dict[str, str | bool | None]:
        """对外表示：绝不包含 password_hash 等内部字段。"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "email_verified": self.email_verified,
            "created_at": self.created_at,
        }


class PendingRegistration(Base):
    """待验证的自助注册：账号只在邮箱确认成功后才落到 ``users``。

    刻意不提前创建 users 行：未验证的账号不应被刷新令牌、OIDC 或业务服务看到。
    ``id`` 是状态查询/重发/取消的 capability（高熵随机串），不是用户 ID。
    """

    __tablename__ = "pending_registrations"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # reg_...
    username: Mapped[str] = mapped_column(Text, nullable=False)
    username_lower: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    email_lower: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)  # bcrypt，验证后复制
    status: Mapped[str] = mapped_column(Text, nullable=False)
    email_request_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_sent_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_reconciled_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[str] = mapped_column(Text, nullable=False)
    verified_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_id: Mapped[str | None] = mapped_column(Text, ForeignKey("users.id"), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_pending_status_expires", "status", "expires_at"),
        Index("ix_pending_email_created", "email_lower", "created_at"),
    )


class OAuthClient(Base):
    """OIDC 客户端（静态注册，sso-oidc.md §5、§6.1）。

    一期不实现 RFC 7591 动态注册，客户端由管理接口 / CLI 创建。
    """

    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(Text, primary_key=True)
    client_secret_hash: Mapped[str | None] = mapped_column(Text, nullable=True)  # public 客户端为 NULL
    client_type: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False)  # JSON 数组，精确匹配
    post_logout_redirect_uris: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON 数组
    allowed_scopes: Mapped[str] = mapped_column(Text, nullable=False)  # JSON 数组
    allowed_grant_types: Mapped[str] = mapped_column(Text, nullable=False)  # JSON 数组
    token_endpoint_auth_method: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[str] = mapped_column(Text, nullable=False)

    # -------- 便捷访问器（存的是 JSON 文本，读写都走这两个方向）--------
    @property
    def redirect_uri_list(self) -> list[str]:
        return loads_list(self.redirect_uris)

    @property
    def post_logout_redirect_uri_list(self) -> list[str]:
        return loads_list(self.post_logout_redirect_uris)

    @property
    def scope_list(self) -> list[str]:
        return loads_list(self.allowed_scopes)

    @property
    def grant_type_list(self) -> list[str]:
        return loads_list(self.allowed_grant_types)

    @property
    def is_public(self) -> bool:
        return self.client_type == CLIENT_TYPE_PUBLIC

    def allows_redirect_uri(self, uri: str) -> bool:
        """开放重定向防线：**精确字符串匹配**，不做前缀/通配（sso-oidc.md §7.1）。"""
        return uri in self.redirect_uri_list

    def allows_post_logout_redirect_uri(self, uri: str) -> bool:
        return uri in self.post_logout_redirect_uri_list

    def to_public_dict(self) -> dict[str, object]:
        """对外表示：绝不回显 client_secret_hash。"""
        return {
            "client_id": self.client_id,
            "client_type": self.client_type,
            "name": self.name,
            "redirect_uris": self.redirect_uri_list,
            "post_logout_redirect_uris": self.post_logout_redirect_uri_list,
            "allowed_scopes": self.scope_list,
            "allowed_grant_types": self.grant_type_list,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id"), nullable=False)
    family_id: Mapped[str] = mapped_column(Text, nullable=False)  # 一次登录 = 一条链
    token_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    expires_at: Mapped[str] = mapped_column(Text, nullable=False)
    used_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    # OIDC 扩展（sso-oidc.md §4.3 / §6.1）
    client_id: Mapped[str | None] = mapped_column(Text, nullable=True)  # 绑定客户端，防跨客户端使用
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)  # 绑定 scope，防刷新时提权
    # 超出文档的一列：把令牌链挂到登录会话上，标准 /logout 才能精确撤销"该会话的链"（§2.7）。
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuthorizationCode(Base):
    """授权码：只存哈希、一次性、60 秒（sso-oidc.md §6.1）。"""

    __tablename__ = "authorization_codes"

    code_hash: Mapped[str] = mapped_column(Text, primary_key=True)  # sha256(code)
    client_id: Mapped[str] = mapped_column(Text, ForeignKey("oauth_clients.client_id"), nullable=False)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id"), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str | None] = mapped_column(Text, nullable=True)
    code_challenge: Mapped[str | None] = mapped_column(Text, nullable=True)
    code_challenge_method: Mapped[str | None] = mapped_column(Text, nullable=True)  # 只存 S256
    auth_time: Mapped[str] = mapped_column(Text, nullable=False)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[str] = mapped_column(Text, nullable=False)
    used_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 兑换成功后派生出的 refresh 链，用于"授权码重放 → 撤销整链"（§2.4a / §7.4）
    family_id: Mapped[str | None] = mapped_column(Text, nullable=True)


class DeviceCode(Base):
    """设备码（RFC 8628，sso-oidc.md §2.5 / §6.1）。"""

    __tablename__ = "device_codes"

    device_code_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    user_code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(Text, ForeignKey("oauth_clients.client_id"), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default=DEVICE_STATUS_PENDING)
    user_id: Mapped[str | None] = mapped_column(Text, ForeignKey("users.id"), nullable=True)
    interval_seconds: Mapped[int] = mapped_column(nullable=False, default=5)
    last_polled_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 确认时所在会话，用于把后续 refresh 链挂到会话上
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_time: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserSession(Base):
    """浏览器登录会话：让 /authorize 不必每次重登（sso-oidc.md §6.1 / §6.2）。"""

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id"), nullable=False)
    session_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)  # sha256(cookie 值)
    auth_time: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)


class Consent(Base):
    """同意记录：一期自动写入，二期做交互式同意页（sso-oidc.md §6.1）。"""

    __tablename__ = "consents"

    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.id"), primary_key=True)
    client_id: Mapped[str] = mapped_column(Text, ForeignKey("oauth_clients.client_id"), primary_key=True)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)

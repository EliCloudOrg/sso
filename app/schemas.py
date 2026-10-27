"""跨路由复用的响应模型。"""

from __future__ import annotations

from pydantic import BaseModel


class PublicUser(BaseModel):
    """对外用户表示：绝不包含 password_hash 等内部字段。"""

    id: str
    username: str
    email: str | None = None
    email_verified: bool = False
    created_at: str | None = None

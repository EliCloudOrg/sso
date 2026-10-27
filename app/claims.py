"""用户 claim 的**唯一来源**：``id_token`` 与 ``/userinfo`` 必须给出完全一致的 scope→claim 映射。

单独抽出来的理由：两份实现一旦漂移，就会出现「id_token 里有 email、userinfo 里没有」
这类很难查的不一致（docs/sso-oidc.md §2.6、§4.2）。
"""

from __future__ import annotations

from typing import Any
from collections.abc import Iterable

from .constants import SCOPE_EMAIL, SCOPE_PROFILE
from .models import User


def user_claims(user: User, scopes: Iterable[str]) -> dict[str, Any]:
    """按 scope 返回该用户的 claim。

    * ``sub`` —— 永远返回（业务数据隔离的唯一依据）；
    * ``profile`` → ``preferred_username``。**B2 决策：不再返回非标准的 ``username``**；
    * ``email``   → ``email`` + ``email_verified``。

    ``email_verified`` 由 ``users.email_verified_at`` 决定：新注册必须完成邮箱
    验证才会建号；历史账号有邮箱但没有验证时间，仍如实返回 ``false``。
    """
    scope_list = list(scopes)
    claims: dict[str, Any] = {"sub": user.id}

    if SCOPE_PROFILE in scope_list:
        claims["preferred_username"] = user.username

    if SCOPE_EMAIL in scope_list and user.email:
        claims["email"] = user.email
        claims["email_verified"] = user.email_verified

    return claims

"""UserInfo 端点（docs/sso-oidc.md §2.6）。

* 接受 **GET 与 POST**（OIDC 要求两者都支持）；
* 按 access token 的 ``scope`` 过滤 claim —— ``scope`` 里没有的一律不返回；
* claim 的构造与 ``id_token`` 共用 ``app/claims.py``，两边不会漂移。
* **B2 决策**：只返回标准 ``preferred_username``，不再返回非标准的 ``username``。
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..claims import user_claims
from ..config import Settings
from ..db import get_db
from ..deps import CurrentClaims, SettingsDep
from ..errors import api_error
from ..models import User
from ..oidc import split_scope

router = APIRouter(prefix="/v1", tags=["userinfo"])


def _userinfo_payload(claims: dict[str, Any], settings: Settings, db: Session) -> dict[str, Any]:
    sub = str(claims.get("sub", ""))
    user = db.get(User, sub)
    if user is None or user.status != "active":
        # 令牌本身有效但用户已不可用 → 401（与 invalid_token 一致）
        raise api_error(401, "invalid_token", "用户不存在或已被禁用")

    body: dict[str, Any] = user_claims(user, split_scope(claims.get("scope")))
    # scope 本身不是"用户 claim"，不在 §2.6 的过滤范围内；保留它便于调用方自检
    body["scope"] = str(claims.get("scope") or settings.default_scope)
    return body


@router.get("/userinfo")
def userinfo_get(
    claims: CurrentClaims,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _userinfo_payload(claims, settings, db)


@router.post("/userinfo")
def userinfo_post(
    claims: CurrentClaims,
    settings: SettingsDep,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _userinfo_payload(claims, settings, db)

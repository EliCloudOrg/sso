"""客户端静态注册的管理接口（docs/sso-oidc.md §5.2）。

整组路由都由 ``require_admin`` 保护（``ADMIN_TOKEN`` 未配置时整体返回 403）。
``client_secret`` 明文只在 POST 创建与 rotate-secret 两处返回，之后任何入口都不回显。
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ..clients import (
    create_client,
    delete_client,
    get_client_or_404,
    list_clients,
    rotate_client_secret,
    update_client,
)
from ..constants import CLIENT_TYPE_PUBLIC
from ..db import get_db
from ..deps import require_admin

router = APIRouter(prefix="/v1/clients", tags=["clients"], dependencies=[Depends(require_admin)])


# --------------------------------------------------------------- 请求模型


class CreateClientRequest(BaseModel):
    # extra=forbid：拼错字段名时直接 400，而不是被静默忽略
    model_config = ConfigDict(extra="forbid")

    client_id: str
    name: str
    client_type: str = CLIENT_TYPE_PUBLIC
    redirect_uris: list[str] = Field(default_factory=list)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=list)
    # 不传时按 DEFAULT_GRANT_TYPES（authorization_code + refresh_token）
    allowed_grant_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None


class UpdateClientRequest(BaseModel):
    """可改字段白名单；client_type 与认证方式刻意不可改（安全相关，需重建）。

    ``extra="forbid"`` 让"试图 PATCH client_type"这类请求直接 400，
    而不是静默忽略后让人以为改成功了。
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    redirect_uris: list[str] | None = None
    post_logout_redirect_uris: list[str] | None = None
    allowed_scopes: list[str] | None = None
    allowed_grant_types: list[str] | None = None


class ClientResponse(BaseModel):
    client_id: str
    client_type: str
    name: str
    redirect_uris: list[str]
    post_logout_redirect_uris: list[str]
    allowed_scopes: list[str]
    allowed_grant_types: list[str]
    token_endpoint_auth_method: str
    created_at: str
    updated_at: str


class CreatedClientResponse(ClientResponse):
    # 仅创建时出现；public 客户端为 null
    client_secret: str | None = None


class ClientListResponse(BaseModel):
    clients: list[ClientResponse]


class RotatedSecretResponse(BaseModel):
    client_id: str
    client_secret: str


# ----------------------------------------------------------------- 端点


@router.post("", response_model=CreatedClientResponse, status_code=201)
def create(
    payload: CreateClientRequest,
    db: Session = Depends(get_db),
) -> CreatedClientResponse:
    client, plaintext_secret = create_client(
        db,
        client_id=payload.client_id,
        name=payload.name,
        client_type=payload.client_type,
        redirect_uris=payload.redirect_uris,
        post_logout_redirect_uris=payload.post_logout_redirect_uris,
        allowed_scopes=payload.allowed_scopes,
        allowed_grant_types=payload.allowed_grant_types,
        token_endpoint_auth_method=payload.token_endpoint_auth_method,
    )
    body: dict[str, Any] = client.to_public_dict()
    body["client_secret"] = plaintext_secret
    return CreatedClientResponse(**body)


@router.get("", response_model=ClientListResponse)
def list_all(db: Session = Depends(get_db)) -> ClientListResponse:
    return ClientListResponse(clients=[ClientResponse(**client.to_public_dict()) for client in list_clients(db)])


@router.get("/{client_id}", response_model=ClientResponse)
def get_one(client_id: str, db: Session = Depends(get_db)) -> ClientResponse:
    return ClientResponse(**get_client_or_404(db, client_id).to_public_dict())


@router.patch("/{client_id}", response_model=ClientResponse)
def patch(client_id: str, payload: UpdateClientRequest, db: Session = Depends(get_db)) -> ClientResponse:
    # exclude_unset：区分"没传这个字段"与"显式传了 null"
    fields = payload.model_dump(exclude_unset=True)
    client = update_client(db, client_id, **fields)
    return ClientResponse(**client.to_public_dict())


@router.delete("/{client_id}", status_code=204)
def remove(client_id: str, db: Session = Depends(get_db)) -> Response:
    delete_client(db, client_id)
    return Response(status_code=204)


@router.post("/{client_id}/rotate-secret", response_model=RotatedSecretResponse)
def rotate_secret(client_id: str, db: Session = Depends(get_db)) -> RotatedSecretResponse:
    client, plaintext = rotate_client_secret(db, client_id)
    return RotatedSecretResponse(client_id=client.client_id, client_secret=plaintext)

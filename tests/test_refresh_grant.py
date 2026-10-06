"""``grant_type=refresh_token`` 测试（docs/sso-oidc.md §2.4b、§4.3、§7.5、§11）。

重点两条：
* **跨客户端**：A 客户端签发的 refresh token 不能被 B 客户端兑换；
* **提权**：刷新时只能收窄 scope，不能扩大。
"""

from __future__ import annotations

import jwt as pyjwt
import pytest

from app.db import session_scope
from app.models import RefreshToken, User
from app.security import hash_refresh_token
from tests.helpers import (
    REDIRECT_URI,
    make_confidential_client,
    make_public_client,
    make_user,
    obtain_code,
    pkce_pair,
)
from tests.test_token import token_request

OFFLINE_SCOPES = ["openid", "profile", "offline_access"]
OFFLINE_SCOPE = "openid profile offline_access"


def obtain_tokens(client, *, scopes=None, scope=OFFLINE_SCOPE, client_id=None, auth=None) -> dict:
    """走授权码流程拿到初始令牌组。"""
    if client_id is None:
        client_id = make_public_client(client, scopes=scopes or OFFLINE_SCOPES)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, _ = obtain_code(
        client, client_id=client_id, username=username, verifier=verifier, challenge=challenge, scope=scope
    )
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }
    # 用 Authorization 头认证时**不能**再在表单里带 client_id（RFC 6749 §2.3.1，服务端会拒绝混用）
    if auth is None:
        data["client_id"] = client_id
    response = token_request(client, data, basic=auth)
    assert response.status_code == 200, response.text
    tokens = response.json()
    tokens["_client_id"] = client_id
    return tokens


def do_refresh(client, *, client_id: str, refresh_token: str, scope: str | None = None, basic=None, secret=None):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if basic is None:
        data["client_id"] = client_id
    if scope is not None:
        data["scope"] = scope
    if secret is not None:
        data["client_secret"] = secret
    return token_request(client, data, basic=basic)


# ------------------------------------------------------------- 正常轮换


def test_refresh_rotates_tokens_and_reissues_id_token(client, settings):
    tokens = obtain_tokens(client)
    client_id = tokens["_client_id"]

    response = do_refresh(client, client_id=client_id, refresh_token=tokens["refresh_token"])
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"

    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["refresh_token"] != tokens["refresh_token"]  # 已轮换
    assert body["refresh_token"].startswith("rt_")
    assert body["scope"] == OFFLINE_SCOPE

    # 新的 id_token：aud 仍是 client_id，但**不该带 nonce**（刷新与原始 nonce 无关）
    assert "id_token" in body
    claims = pyjwt.decode(body["id_token"], options={"verify_signature": False})
    assert claims["aud"] == client_id
    assert "nonce" not in claims
    assert claims["auth_time"] > 0  # 从会话/链起点推断出来，不是签发时间

    access = pyjwt.decode(body["access_token"], options={"verify_signature": False})
    assert access["aud"] == settings.audience  # access token 的 aud 不变
    assert access["client_id"] == client_id


def test_old_refresh_token_invalid_after_rotation(client):
    tokens = obtain_tokens(client)
    client_id = tokens["_client_id"]

    rotated = do_refresh(client, client_id=client_id, refresh_token=tokens["refresh_token"]).json()

    # 用刚轮换出来的那个：可用
    second = do_refresh(client, client_id=client_id, refresh_token=rotated["refresh_token"])
    assert second.status_code == 200

    # 用更早那个：它是"已用过"的 → 触发重放判定
    replay = do_refresh(client, client_id=client_id, refresh_token=tokens["refresh_token"])
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    # 整链撤销：最新那个也失效了
    after = do_refresh(client, client_id=client_id, refresh_token=rotated["refresh_token"])
    assert after.status_code == 400


def test_refresh_replay_revokes_whole_chain(client):
    tokens = obtain_tokens(client)
    client_id = tokens["_client_id"]
    first = tokens["refresh_token"]

    rotated = do_refresh(client, client_id=client_id, refresh_token=first).json()["refresh_token"]
    assert do_refresh(client, client_id=client_id, refresh_token=first).status_code == 400  # 重放

    with session_scope() as session:
        rows = session.query(RefreshToken).filter(RefreshToken.family_id.isnot(None)).all()
        by_hash = {row.token_hash: row for row in rows}
        assert by_hash[hash_refresh_token(first)].revoked_at is not None
        assert by_hash[hash_refresh_token(rotated)].revoked_at is not None


# ------------------------------------------------------- 跨客户端绑定


def test_refresh_token_cannot_be_used_by_another_client(client):
    """§7.5：A 客户端签发的 refresh token 不能被 B 客户端兑换。"""
    tokens = obtain_tokens(client)
    other_client = make_public_client(client, scopes=OFFLINE_SCOPES)

    response = do_refresh(client, client_id=other_client, refresh_token=tokens["refresh_token"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert "不匹配" in response.json()["error_description"]


def test_private_flow_refresh_token_rejected_at_token_endpoint(client):
    """密码直连签发的令牌没有 client_id 绑定，不允许在标准端点使用。"""
    public_client = make_public_client(client, scopes=OFFLINE_SCOPES)
    username, _ = make_user(client)

    private = client.post("/v1/login", json={"username": username, "password": "S3cret!pass1"})
    assert private.status_code == 200
    private_refresh = private.json()["refresh_token"]

    response = do_refresh(client, client_id=public_client, refresh_token=private_refresh)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert "不是本端点签发" in response.json()["error_description"]


def test_oidc_refresh_token_rejected_at_private_refresh_endpoint(client):
    """反向：绑定了客户端的令牌不能绕过客户端认证在 /v1/refresh 兑换。"""
    tokens = obtain_tokens(client)
    response = client.post("/v1/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_grant"


# ------------------------------------------------------------ 提权防护


def test_scope_cannot_be_escalated_on_refresh(client):
    """原 scope 没有 email，刷新时申请 email → invalid_scope。"""
    tokens = obtain_tokens(client, scopes=["openid", "offline_access"], scope="openid offline_access")
    client_id = tokens["_client_id"]

    response = do_refresh(
        client,
        client_id=client_id,
        refresh_token=tokens["refresh_token"],
        scope="openid offline_access email",
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def test_scope_can_be_narrowed_on_refresh(client):
    tokens = obtain_tokens(client)  # openid profile offline_access
    client_id = tokens["_client_id"]

    response = do_refresh(
        client,
        client_id=client_id,
        refresh_token=tokens["refresh_token"],
        scope="openid offline_access",
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scope"] == "openid offline_access"
    assert "profile" not in body["scope"]

    # 收窄后的新令牌继续只用收窄后的 scope
    again = do_refresh(client, client_id=client_id, refresh_token=body["refresh_token"], scope="openid")
    assert again.status_code == 200
    assert again.json()["scope"] == "openid"


# -------------------------------------------------------- 客户端认证与授权


def test_confidential_client_must_authenticate_to_refresh(client):
    client_id, secret = make_confidential_client(client, scopes=OFFLINE_SCOPES)
    tokens = obtain_tokens(client, client_id=client_id, auth=(client_id, secret))
    refresh = tokens["refresh_token"]

    # 不带凭据 → 400 invalid_client
    assert do_refresh(client, client_id=client_id, refresh_token=refresh).status_code == 400
    # 错凭据 → 401
    wrong = do_refresh(client, client_id=client_id, refresh_token=refresh, basic=(client_id, "nope"))
    assert wrong.status_code == 401
    assert wrong.json()["error"] == "invalid_client"
    # 正确凭据 → 成功
    ok = do_refresh(client, client_id=client_id, refresh_token=refresh, basic=(client_id, secret))
    assert ok.status_code == 200


def test_client_without_refresh_grant_gets_unauthorized_client(client):
    client_id = make_public_client(client, scopes=OFFLINE_SCOPES, grant_types=["authorization_code"])
    response = do_refresh(client, client_id=client_id, refresh_token="rt_whatever")
    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"


def test_offline_access_without_refresh_grant_issues_no_refresh_token(client):
    """客户端没注册 refresh_token 授权类型时，即使请求 offline_access 也不发 refresh token。"""
    tokens = obtain_tokens(client, client_id=make_public_client(client, scopes=OFFLINE_SCOPES, grant_types=["authorization_code"]))
    assert "refresh_token" not in tokens


# ------------------------------------------------------------ 失效与错误


def test_expired_and_revoked_refresh_tokens(client):
    tokens = obtain_tokens(client)
    client_id = tokens["_client_id"]

    with session_scope() as session:
        row = session.query(RefreshToken).filter(RefreshToken.token_hash == hash_refresh_token(tokens["refresh_token"])).one()
        row.expires_at = "2020-01-01T00:00:00Z"
        session.commit()

    expired = do_refresh(client, client_id=client_id, refresh_token=tokens["refresh_token"])
    assert expired.status_code == 400
    assert expired.json()["error"] == "invalid_grant"

    # 过期已把该令牌标记撤销
    with session_scope() as session:
        row = session.query(RefreshToken).filter(RefreshToken.token_hash == hash_refresh_token(tokens["refresh_token"])).one()
        assert row.revoked_at is not None


def test_missing_and_unknown_refresh_token(client):
    client_id = make_public_client(client, scopes=OFFLINE_SCOPES)

    missing = client.post(
        "/token",
        data={"grant_type": "refresh_token", "client_id": client_id},
    )
    assert missing.status_code == 400
    assert missing.json()["error"] == "invalid_grant"

    unknown = do_refresh(client, client_id=client_id, refresh_token="rt_not-a-real-token")
    assert unknown.status_code == 400
    assert unknown.json()["error"] == "invalid_grant"


def test_disabled_user_cannot_refresh(client):
    tokens = obtain_tokens(client)
    client_id = tokens["_client_id"]

    with session_scope() as session:
        row = (
            session.query(RefreshToken)
            .filter(RefreshToken.token_hash == hash_refresh_token(tokens["refresh_token"]))
            .one()
        )
        user = session.get(User, row.user_id)
        user.status = "disabled"
        session.commit()

    response = do_refresh(client, client_id=client_id, refresh_token=tokens["refresh_token"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.parametrize("client_type", ["public", "confidential"])
def test_refresh_works_for_both_client_types(client, client_type):
    if client_type == "public":
        client_id = make_public_client(client, scopes=OFFLINE_SCOPES)
        auth = None
    else:
        client_id, secret = make_confidential_client(client, scopes=OFFLINE_SCOPES)
        auth = (client_id, secret)

    tokens = obtain_tokens(client, client_id=client_id, auth=auth)
    response = do_refresh(client, client_id=client_id, refresh_token=tokens["refresh_token"], basic=auth)
    assert response.status_code == 200, response.text

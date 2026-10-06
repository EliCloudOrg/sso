"""标准 RP-Initiated Logout 测试（docs/sso-oidc.md §2.7、§1.3 的 A3 决策）。

重点两条：
* **开放重定向**：`post_logout_redirect_uri` 必须精确匹配注册值，否则不跳转；
* **撤销范围**：只撤销"该浏览器会话派生的 refresh 链"，不误伤同账号的其它设备。
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt

from app.db import session_scope
from app.models import RefreshToken, UserSession
from app.oidc import pkce_challenge_s256
from app.security import hash_refresh_token
from tests.helpers import (
    LOGOUT_REDIRECT_URI,
    REDIRECT_URI,
    make_public_client,
    make_user,
    obtain_code,
    pkce_pair,
)
from tests.helpers import adopt_cookies, get_authorize, post_login
from tests.test_token import token_request

OFFLINE_SCOPES = ["openid", "profile", "offline_access"]
OFFLINE_SCOPE = "openid profile offline_access"


def sign_in_with_tokens(
    client,
    *,
    scopes: list[str] | None = None,
    scope: str = OFFLINE_SCOPE,
    post_logout_redirect_uris: list[str] | None = None,
) -> dict:
    """走完整授权码流程：拿到令牌，并在浏览器侧留下会话 cookie。"""
    client_id = make_public_client(
        client,
        scopes=scopes or OFFLINE_SCOPES,
        post_logout_redirect_uris=post_logout_redirect_uris,
    )
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    code, params = obtain_code(
        client, client_id=client_id, username=username, verifier=verifier, challenge=challenge, scope=scope
    )
    tokens = token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    ).json()
    tokens["_client_id"] = client_id
    tokens["_username"] = username
    return tokens


def do_logout(client, *, params: dict | None = None, method: str = "GET", data: dict | None = None):
    if method == "GET":
        return adopt_cookies(client, client.get("/logout", params=params or {}, follow_redirects=False))
    return adopt_cookies(client, client.post("/logout", data=data or {}, follow_redirects=False))


# ------------------------------------------------------------- 基本行为


def test_logout_without_session_renders_page(client):
    response = do_logout(client)
    assert response.status_code == 200
    assert "已登出" in response.text
    assert response.headers.get("cache-control") == "no-store"


def test_logout_revokes_session_and_its_chains(client):
    tokens = sign_in_with_tokens(client)

    # 精确定位本次登录创建的那个会话（测试库是共享的，不能断言全局计数）
    with session_scope() as session:
        latest = (
            session.query(UserSession).order_by(UserSession.created_at.desc(), UserSession.id.desc()).first()
        )
        assert latest is not None and latest.revoked_at is None
        session_id = latest.id

    response = do_logout(client)
    assert response.status_code == 200

    with session_scope() as session:
        session_row = session.get(UserSession, session_id)
        assert session_row is not None and session_row.revoked_at is not None

        row = (
            session.query(RefreshToken)
            .filter(RefreshToken.token_hash == hash_refresh_token(tokens["refresh_token"]))
            .one()
        )
        assert row.revoked_at is not None  # 该会话派生的链被撤销
        assert row.session_id == session_id

    # cookie 被清掉（Max-Age=0 / expires 过去）
    set_cookie = " ".join(response.headers.get_list("set-cookie"))
    assert "elicloud_sso_session=" in set_cookie
    assert "Max-Age=0" in set_cookie or "expires=" in set_cookie.lower()


def authorize_with(client, *, client_id: str, username: str, verifier: str) -> str:
    """在给定 cookie jar 的客户端上走一遍授权码流程，返回 code。"""
    challenge = pkce_challenge_s256(verifier)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": OFFLINE_SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    assert get_authorize(client, params).status_code == 200
    response = post_login(client, params, username=username)
    assert response.status_code == 302, response.text
    return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]


def test_logout_does_not_kill_other_sessions_chains(client):
    """只撤销"该会话派生的链"：同账号的另一个设备不受影响。"""
    from starlette.testclient import TestClient

    tokens = sign_in_with_tokens(client)
    client_id = tokens["_client_id"]
    username = tokens["_username"]

    # 第二个浏览器：独立 cookie jar（相当于另一台设备）
    other = TestClient(client.app)
    other_verifier, _ = pkce_pair()
    code = authorize_with(other, client_id=client_id, username=username, verifier=other_verifier)
    other_tokens = token_request(
        other,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": other_verifier,
        },
    ).json()

    # 第一个浏览器登出
    assert do_logout(client).status_code == 200

    # 第二个浏览器的链仍然可用
    refreshed = token_request(
        other,
        {
            "grant_type": "refresh_token",
            "refresh_token": other_tokens["refresh_token"],
            "client_id": client_id,
        },
    )
    assert refreshed.status_code == 200, refreshed.text


# ------------------------------------------------------ 回跳地址（防开放重定向）


def test_logout_redirects_to_registered_post_logout_uri(client):
    tokens = sign_in_with_tokens(client, post_logout_redirect_uris=[LOGOUT_REDIRECT_URI])

    response = do_logout(
        client,
        params={
            "post_logout_redirect_uri": LOGOUT_REDIRECT_URI,
            "id_token_hint": tokens["id_token"],
            "state": "st-1",
        },
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(LOGOUT_REDIRECT_URI)
    assert parse_qs(urlsplit(location).query)["state"] == ["st-1"]


def test_logout_refuses_unregistered_redirect_uri(client):
    tokens = sign_in_with_tokens(client, post_logout_redirect_uris=[LOGOUT_REDIRECT_URI])

    response = do_logout(
        client,
        params={
            "post_logout_redirect_uri": "https://evil.example.com/steal",
            "id_token_hint": tokens["id_token"],
        },
    )
    assert response.status_code == 200
    assert "location" not in response.headers  # 绝不跳转
    assert "已登出" in response.text


def test_logout_refuses_redirect_without_id_token_hint(client):
    """没有 id_token_hint / client_id 就无法确认客户端 → 不跳转。"""
    sign_in_with_tokens(client, post_logout_redirect_uris=[LOGOUT_REDIRECT_URI])
    response = do_logout(client, params={"post_logout_redirect_uri": LOGOUT_REDIRECT_URI})
    assert response.status_code == 200
    assert "location" not in response.headers


def test_logout_refuses_forged_id_token_hint(client):
    """伪造的 id_token_hint（签名不对）不能被用来操纵回跳地址。"""
    sign_in_with_tokens(client, post_logout_redirect_uris=[LOGOUT_REDIRECT_URI])
    forged = pyjwt.encode(
        {"iss": "https://evil.example.com", "sub": "x", "aud": "whatever"},
        "0" * 32,  # 够长的 HMAC 密钥，避免 PyJWT 的短密钥告警
        algorithm="HS256",
    )

    response = do_logout(
        client,
        params={"post_logout_redirect_uri": LOGOUT_REDIRECT_URI, "id_token_hint": forged},
    )
    assert response.status_code == 200
    assert "location" not in response.headers


def test_logout_accepts_client_id_as_extension(client):
    """允许直接给 client_id（部分客户端不保留 id_token）；仍走精确匹配。"""
    client_id = make_public_client(client, scopes=OFFLINE_SCOPES, post_logout_redirect_uris=[LOGOUT_REDIRECT_URI])

    response = do_logout(
        client,
        params={"post_logout_redirect_uri": LOGOUT_REDIRECT_URI, "client_id": client_id},
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith(LOGOUT_REDIRECT_URI)


def test_logout_post_accepts_form_fields(client):
    tokens = sign_in_with_tokens(client, post_logout_redirect_uris=[LOGOUT_REDIRECT_URI])

    response = do_logout(
        client,
        method="POST",
        data={
            "post_logout_redirect_uri": LOGOUT_REDIRECT_URI,
            "id_token_hint": tokens["id_token"],
            "state": "posted",
        },
    )
    assert response.status_code == 302
    assert parse_qs(urlsplit(response.headers["location"]).query)["state"] == ["posted"]


# -------------------------------------------------- A3：私有 logout 已下线


def test_private_logout_route_is_gone(client):
    """A3 决策：私有 POST /v1/logout 不再存在。"""
    assert client.post("/v1/logout", json={}).status_code == 404
    assert client.post("/v1/logout").status_code == 404


def test_logout_is_idempotent(client):
    sign_in_with_tokens(client)
    assert do_logout(client).status_code == 200
    assert do_logout(client).status_code == 200  # 再来一次也不该报错

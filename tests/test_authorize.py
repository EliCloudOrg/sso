"""授权端点（/authorize）与登录页测试：docs/sso-oidc.md §2.3、§7。

重点覆盖那些"看起来能跑但其实是漏洞"的点：
开放重定向（client_id / redirect_uri 非法时**不得**重定向）、PKCE 强制、
CSRF 双重提交、防会话固定、state/nonce 透传、授权码只存哈希。
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlsplit

import pytest

from app.config import Settings, get_settings
from app.db import session_scope
from app.models import AuthorizationCode, UserSession, User
from app.oidc import pkce_challenge_s256
from app.sessions import csrf_cookie_name

ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token-not-a-real-secret"}
PASSWORD = "S3cret!pass1"
REDIRECT_URI = "https://app.example.com/callback"


# ------------------------------------------------------------------ 工具


def unique(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def make_public_client(client, *, redirect_uris=None, scopes=None) -> str:
    client_id = unique("oidc")
    response = client.post(
        "/v1/clients",
        json={
            "client_id": client_id,
            "name": "OIDC 测试客户端",
            "client_type": "public",
            "redirect_uris": redirect_uris or [REDIRECT_URI],
            "allowed_scopes": scopes or ["openid", "profile", "email"],
        },
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 201, response.text
    return client_id


def make_user(client) -> tuple[str, str]:
    username = unique("alice")
    response = client.post("/v1/register", json={"username": username, "password": PASSWORD})
    assert response.status_code == 201, response.text
    return username, response.json()["user"]["id"]


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    return verifier, pkce_challenge_s256(verifier)


def authorize_params(
    client_id: str,
    *,
    redirect_uri: str = REDIRECT_URI,
    scope: str = "openid profile email",
    state: str | None = "state-123",
    nonce: str | None = "nonce-abc",
    response_type: str | None = "code",
    verifier: str | None = None,
    challenge: str | None = None,
    challenge_method: str | None = "S256",
    prompt: str | None = None,
) -> dict[str, str]:
    params: dict[str, str] = {"client_id": client_id, "redirect_uri": redirect_uri, "scope": scope}
    if response_type is not None:
        params["response_type"] = response_type
    if state is not None:
        params["state"] = state
    if nonce is not None:
        params["nonce"] = nonce
    if challenge is None and verifier is not None:
        challenge = pkce_challenge_s256(verifier)
    if challenge is not None:
        params["code_challenge"] = challenge
        if challenge_method is not None:
            params["code_challenge_method"] = challenge_method
    if prompt is not None:
        params["prompt"] = prompt
    return params


def _adopt_cookies(client, response):
    """把本响应新下发的 cookie 以 ``Path=/`` 重新写进 jar。

    生产环境里浏览器访问的是 ``/auth/...``，所以 ``Path=/auth`` 的 cookie 会正常带上；
    而测试直连**内部**路径 ``/authorize``（网关不参与），路径不匹配就不会发送。
    这里只把**本响应新设的**值搬到 ``Path=/``，避免同名 cookie 因路径不同而出现歧义。
    """
    settings = get_settings()
    for name in (settings.session_cookie_name, csrf_cookie_name(settings)):
        value = response.cookies.get(name)
        if value is None:
            continue
        client.cookies.delete(name)
        client.cookies.set(name, value, path="/")
    return response


def get_authorize(client, params):
    return _adopt_cookies(client, client.get("/authorize", params=params, follow_redirects=False))


def post_login(client, params, *, username: str, password: str = PASSWORD, csrf_token: str | None = None):
    form = dict(params)
    form["username"] = username
    form["password"] = password

    if csrf_token is None:
        csrf_token = client.cookies.get(csrf_cookie_name(get_settings()))
    form["csrf_token"] = csrf_token or ""

    return _adopt_cookies(client, client.post("/authorize", data=form, follow_redirects=False))


def redirect_query(response) -> dict[str, list[str]]:
    location = response.headers.get("location", "")
    return parse_qs(urlsplit(location).query)


# ------------------------------------------------- 开放重定向防线（§7.1）


def test_unknown_client_renders_error_page_and_does_not_redirect(client):
    response = get_authorize(client, authorize_params("no-such-client"))
    assert response.status_code == 400
    assert "location" not in response.headers  # 绝不重定向
    assert "无法完成授权" in response.text


def test_redirect_uri_mismatch_does_not_redirect(client):
    client_id = make_public_client(client)
    params = authorize_params(client_id, redirect_uri="https://evil.example.com/steal")
    response = get_authorize(client, params)
    assert response.status_code == 400
    assert "location" not in response.headers


def test_redirect_uri_prefix_is_not_accepted(client):
    """精确匹配：注册 https://app.example.com/callback，带后缀的也要拒绝。"""
    client_id = make_public_client(client)
    response = get_authorize(client, authorize_params(client_id, redirect_uri=REDIRECT_URI + "/extra"))
    assert response.status_code == 400
    assert "location" not in response.headers


def test_missing_redirect_uri_does_not_redirect(client):
    client_id = make_public_client(client)
    params = authorize_params(client_id)
    params.pop("redirect_uri")
    response = get_authorize(client, params)
    assert response.status_code == 400
    assert "location" not in response.headers


# ------------------------------------------- 可重定向的参数错误（§2.3）


def test_unsupported_response_type_redirects_with_error(client):
    client_id = make_public_client(client)
    verifier, _ = pkce_pair()
    response = get_authorize(client, authorize_params(client_id, response_type="token", verifier=verifier))
    assert response.status_code == 302
    query = redirect_query(response)
    assert query["error"] == ["unsupported_response_type"]
    assert query["state"] == ["state-123"]


def test_scope_without_openid_is_rejected(client):
    client_id = make_public_client(client)
    verifier, _ = pkce_pair()
    response = get_authorize(client, authorize_params(client_id, scope="profile email", verifier=verifier))
    assert response.status_code == 302
    assert redirect_query(response)["error"] == ["invalid_scope"]


def test_scope_not_registered_for_client_is_rejected(client):
    client_id = make_public_client(client, scopes=["openid"])
    verifier, _ = pkce_pair()
    response = get_authorize(client, authorize_params(client_id, scope="openid profile", verifier=verifier))
    assert response.status_code == 302
    assert redirect_query(response)["error"] == ["invalid_scope"]


def test_public_client_must_send_pkce_challenge(client):
    client_id = make_public_client(client)
    response = get_authorize(client, authorize_params(client_id, challenge=None))
    assert response.status_code == 302
    assert redirect_query(response)["error"] == ["invalid_request"]


def test_plain_code_challenge_method_is_rejected(client):
    client_id = make_public_client(client)
    verifier, challenge = pkce_pair()
    response = get_authorize(
        client,
        authorize_params(client_id, challenge=challenge, challenge_method="plain"),
    )
    assert response.status_code == 302
    assert redirect_query(response)["error"] == ["invalid_request"]


def test_prompt_none_without_session_returns_login_required(client):
    client_id = make_public_client(client)
    verifier, _ = pkce_pair()
    response = get_authorize(client, authorize_params(client_id, verifier=verifier, prompt="none"))
    assert response.status_code == 302
    assert redirect_query(response)["error"] == ["login_required"]


# -------------------------------------------------------------- 登录页


def test_login_page_is_rendered_with_csrf(client):
    client_id = make_public_client(client)
    verifier, challenge = pkce_pair()
    response = get_authorize(client, authorize_params(client_id, challenge=challenge))

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "OIDC 测试客户端" in response.text
    # CSRF 同时出现在表单隐藏字段与 cookie 里（双重提交）
    token = client.cookies.get(csrf_cookie_name(get_settings()))
    assert token and token in response.text
    assert response.headers.get("cache-control") == "no-store"
    assert response.headers.get("referrer-policy") == "no-referrer"


def test_login_page_ignores_invalid_password_and_shows_generic_error(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, _ = pkce_pair()
    params = authorize_params(client_id, verifier=verifier)

    get_authorize(client, params)  # 拿 csrf cookie
    response = post_login(client, params, username=username, password="WrongPass123")

    assert response.status_code == 200
    assert "用户名或密码错误" in response.text
    assert "code=" not in response.headers.get("location", "")
    # 失败的登录不该建立会话
    assert client.cookies.get(get_settings().session_cookie_name) is None


def test_login_post_requires_csrf(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, _ = pkce_pair()
    params = authorize_params(client_id, verifier=verifier)
    get_authorize(client, params)

    response = post_login(client, params, username=username, csrf_token="forged-token")
    assert response.status_code == 403
    assert "location" not in response.headers


# --------------------------------------------------- 完整授权码流程


def test_full_authorize_flow_issues_code_and_session(client):
    client_id = make_public_client(client)
    username, user_id = make_user(client)
    verifier, challenge = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, challenge=challenge)

    # 1) 未登录 → 登录页
    assert get_authorize(client, params).status_code == 200

    # 2) 提交表单 → 302 回 redirect_uri，带 code 与 state
    response = post_login(client, params, username=username)
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(REDIRECT_URI)
    query = redirect_query(response)
    assert query["state"] == ["state-123"]
    code = query["code"][0]
    assert len(code) > 30

    # 3) 会话 cookie 属性（§7.16）
    set_cookie = ", ".join(response.headers.get_list("set-cookie"))
    assert get_settings().session_cookie_name in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie
    assert "Path=/auth" in set_cookie

    # 4) 授权码只存哈希，其余绑定字段齐全（§6.1）
    from app.authorization import hash_authorization_code

    with session_scope() as session:
        row = session.get(AuthorizationCode, hash_authorization_code(code))
        assert row is not None
        assert row.client_id == client_id
        assert row.user_id == user_id
        assert row.redirect_uri == REDIRECT_URI
        assert row.scope == "openid profile email"
        assert row.nonce == "nonce-abc"
        assert row.code_challenge == challenge
        assert row.code_challenge_method == "S256"
        assert row.used_at is None
        assert row.session_id is not None
        assert row.auth_time
        # 明文码不得出现在库里
        assert code not in (row.code_hash or "")


def test_second_authorize_reuses_session_without_login_page(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, challenge=challenge)

    get_authorize(client, params)
    assert post_login(client, params, username=username).status_code == 302

    # 已有会话 → 直接发码，不再要求登录
    second = get_authorize(client, params)
    assert second.status_code == 302
    assert "code" in redirect_query(second)


def test_prompt_login_forces_login_page_even_with_session(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, challenge=challenge)

    get_authorize(client, params)
    assert post_login(client, params, username=username).status_code == 302

    forced = get_authorize(client, authorize_params(client_id, verifier=verifier, challenge=challenge, prompt="login"))
    assert forced.status_code == 200
    assert "登录" in forced.text


def test_state_absent_still_works(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, _ = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, state=None)

    get_authorize(client, params)
    response = post_login(client, params, username=username)
    assert response.status_code == 302
    assert "state" not in redirect_query(response)
    assert "code" in redirect_query(response)


# -------------------------------------------------------- 会话安全（§7.15）


def test_login_creates_new_session_and_revokes_old(client):
    """防会话固定：每次登录都换新的会话 ID，旧会话立即撤销。"""
    client_id = make_public_client(client)
    username, user_id = make_user(client)
    verifier, challenge = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, challenge=challenge)
    cookie_name = get_settings().session_cookie_name

    get_authorize(client, params)
    assert post_login(client, params, username=username).status_code == 302
    first_cookie = client.cookies.get(cookie_name)

    # 再用 prompt=login 强制重新认证
    forced = authorize_params(client_id, verifier=verifier, challenge=challenge, prompt="login")
    get_authorize(client, forced)
    assert post_login(client, forced, username=username).status_code == 302
    second_cookie = client.cookies.get(cookie_name)

    assert first_cookie != second_cookie

    from app.sessions import hash_session_value

    with session_scope() as session:
        rows = session.query(UserSession).filter(UserSession.user_id == user_id).all()
        assert len(rows) == 2
        by_hash = {row.session_hash: row for row in rows}
        assert by_hash[hash_session_value(first_cookie)].revoked_at is not None
        assert by_hash[hash_session_value(second_cookie)].revoked_at is None


def test_revoked_session_cannot_be_reused(client):
    client_id = make_public_client(client)
    username, _ = make_user(client)
    verifier, challenge = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, challenge=challenge)

    get_authorize(client, params)
    post_login(client, params, username=username)

    # 手工撤销会话后，再次访问应重新要求登录
    with session_scope() as session:
        for row in session.query(UserSession).all():
            row.revoked_at = "2026-01-01T00:00:00Z"
        session.commit()

    response = get_authorize(client, params)
    assert response.status_code == 200  # 回到登录页


def test_disabled_user_session_is_not_accepted(client):
    client_id = make_public_client(client)
    username, user_id = make_user(client)
    verifier, challenge = pkce_pair()
    params = authorize_params(client_id, verifier=verifier, challenge=challenge)

    get_authorize(client, params)
    post_login(client, params, username=username)

    with session_scope() as session:
        user = session.get(User, user_id)
        user.status = "disabled"
        session.commit()

    assert get_authorize(client, params).status_code == 200  # 视为未登录


# ------------------------------------------------------------- cookie 属性


def test_cookie_secure_flag_follows_public_base_url():
    """https 阶段必须带 Secure（§7.16）—— IP 阶段用的是受信 IP 证书，照开。"""
    https = Settings(public_base_url="https://146.56.237.33/auth")
    http = Settings(public_base_url="http://127.0.0.1:8000/auth")
    assert https.cookie_secure is True
    assert http.cookie_secure is False
    assert https.cookie_path == "/auth"
    assert http.cookie_path == "/auth"


@pytest.mark.parametrize(
    "path,expected",
    [("https://example.com/auth", "/auth"), ("http://127.0.0.1:8000", "/")],
)
def test_cookie_path_derived_from_public_base_url(path, expected):
    assert Settings(public_base_url=path).cookie_path == expected

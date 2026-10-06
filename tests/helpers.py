"""OIDC 流程的测试共用工具（steps 4+ 复用）。

注意 ``_adopt_cookies``：测试直连**内部**路径（`/authorize`、`/token`），
而 cookie 的 ``Path`` 是对外前缀 ``/auth``；生产环境浏览器访问的正是 ``/auth/...``。
这里把**本响应新下发的** cookie 以 ``Path=/`` 重新入 jar，避免同名 cookie 路径歧义。
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlsplit

from app.config import get_settings
from app.oidc import pkce_challenge_s256
from app.sessions import csrf_cookie_name

ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token-not-a-real-secret"}
PASSWORD = "S3cret!pass1"
REDIRECT_URI = "https://app.example.com/callback"
LOGOUT_REDIRECT_URI = "https://app.example.com/logged-out"


def unique(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


# --------------------------------------------------------------- 客户端


def make_public_client(
    client,
    *,
    redirect_uris: list[str] | None = None,
    scopes: list[str] | None = None,
    grant_types: list[str] | None = None,
    post_logout_redirect_uris: list[str] | None = None,
) -> str:
    client_id = unique("oidc")
    body: dict[str, object] = {
        "client_id": client_id,
        "name": "OIDC 测试客户端",
        "client_type": "public",
        "redirect_uris": [REDIRECT_URI] if redirect_uris is None else redirect_uris,
        "allowed_scopes": ["openid", "profile", "email", "offline_access"] if scopes is None else scopes,
    }
    if grant_types is not None:
        body["allowed_grant_types"] = grant_types
    if post_logout_redirect_uris is not None:
        body["post_logout_redirect_uris"] = post_logout_redirect_uris
    response = client.post("/v1/clients", json=body, headers=ADMIN_HEADERS)
    assert response.status_code == 201, response.text
    return client_id


def make_confidential_client(
    client,
    *,
    auth_method: str = "client_secret_basic",
    redirect_uris: list[str] | None = None,
    scopes: list[str] | None = None,
    grant_types: list[str] | None = None,
) -> tuple[str, str]:
    client_id = unique("conf")
    body: dict[str, object] = {
        "client_id": client_id,
        "name": "Confidential 测试客户端",
        "client_type": "confidential",
        "token_endpoint_auth_method": auth_method,
        "redirect_uris": [REDIRECT_URI] if redirect_uris is None else redirect_uris,
        "allowed_scopes": ["openid", "profile", "email", "offline_access"] if scopes is None else scopes,
    }
    if grant_types is not None:
        body["allowed_grant_types"] = grant_types
    response = client.post("/v1/clients", json=body, headers=ADMIN_HEADERS)
    assert response.status_code == 201, response.text
    return client_id, response.json()["client_secret"]


# ----------------------------------------------------------------- 用户


def make_user(client, *, password: str = PASSWORD) -> tuple[str, str]:
    username = unique("alice")
    response = client.post("/v1/register", json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    return username, response.json()["user"]["id"]


# ----------------------------------------------------------------- PKCE


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


# -------------------------------------------------------------- 请求包装


def adopt_cookies(client, response):
    settings = get_settings()
    for name in (settings.session_cookie_name, csrf_cookie_name(settings)):
        value = response.cookies.get(name)
        if value is None:
            continue
        client.cookies.delete(name)
        client.cookies.set(name, value, path="/")
    return response


def get_authorize(client, params):
    return adopt_cookies(client, client.get("/authorize", params=params, follow_redirects=False))


def post_login(client, params, *, username: str, password: str = PASSWORD, csrf_token: str | None = None):
    form = dict(params)
    form["username"] = username
    form["password"] = password
    if csrf_token is None:
        csrf_token = client.cookies.get(csrf_cookie_name(get_settings()))
    form["csrf_token"] = csrf_token or ""
    return adopt_cookies(client, client.post("/authorize", data=form, follow_redirects=False))


def redirect_query(response) -> dict[str, list[str]]:
    return parse_qs(urlsplit(response.headers.get("location", "")).query)


def gateway_internal_path(settings, url: str) -> str:
    """把发现文档里的对外 URL 还原成**服务内**路径。

    按 docs/sso-oidc.md §8 的网关规则实现（测试直连服务，不经 Caddy）：

    * ``/auth/.well-known/<x>`` → ``/.well-known/<x>``
    * ``/auth/authorize``、``/auth/token`` …（STANDARD_ENDPOINT_PATHS）→ 原路径
    * ``/auth/v1/<x>`` → ``/v1/<x>``
    * ``/auth/<x>`` → ``/v1/<x>``
    """
    from app.constants import STANDARD_ENDPOINT_PATHS

    assert url.startswith(settings.issuer), f"{url} 不以 issuer 开头"
    rest = url[len(settings.issuer) :] or "/"

    if rest.startswith("/.well-known/"):
        return rest
    if rest in STANDARD_ENDPOINT_PATHS:
        return rest
    if rest.startswith("/v1/"):
        return rest
    return "/v1" + rest


# ------------------------------------------------------------ 完整拿码


def obtain_code(
    client,
    *,
    client_id: str,
    username: str,
    verifier: str | None = None,
    challenge: str | None = None,
    scope: str = "openid profile email",
    state: str | None = "state-123",
    nonce: str | None = "nonce-abc",
    redirect_uri: str = REDIRECT_URI,
    prompt: str | None = None,
) -> tuple[str, dict[str, str]]:
    """走完 /authorize（登录页 → 提交）并返回 (授权码, 参数)。"""
    params = authorize_params(
        client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        nonce=nonce,
        verifier=verifier,
        challenge=challenge,
        prompt=prompt,
    )
    page = get_authorize(client, params)
    assert page.status_code == 200, page.text
    response = post_login(client, params, username=username)
    assert response.status_code == 302, response.text
    query = redirect_query(response)
    assert "code" in query, response.headers.get("location")
    return query["code"][0], params

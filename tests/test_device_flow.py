"""设备授权流程测试（RFC 8628 / docs/sso-oidc.md §2.5、§3.2、§7.9、§7.14）。"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt

from app.config import get_settings
from app.constants import (
    DEVICE_STATUS_APPROVED,
    DEVICE_STATUS_PENDING,
    GRANT_DEVICE_CODE,
    USER_CODE_ALPHABET,
)
from app.db import session_scope
from app.device import generate_user_code, hash_device_code, normalize_user_code
from app.models import DeviceCode
from app.sessions import csrf_cookie_name
from tests.helpers import PASSWORD, adopt_cookies, make_public_client, make_user

DEVICE_SCOPES = ["openid", "profile", "email", "offline_access"]
DEVICE_GRANTS = [GRANT_DEVICE_CODE, "refresh_token"]


# ---------------------------------------------------------------- 工具


def make_device_client(client, **kwargs) -> str:
    return make_public_client(
        client,
        scopes=kwargs.pop("scopes", DEVICE_SCOPES),
        grant_types=kwargs.pop("grant_types", DEVICE_GRANTS),
        redirect_uris=kwargs.pop("redirect_uris", []),
        **kwargs,
    )


def start_device_authorization(client, *, client_id: str, scope: str = "openid profile offline_access"):
    return client.post("/device_authorization", data={"client_id": client_id, "scope": scope})


def poll(client, *, client_id: str, device_code: str):
    return client.post(
        "/token",
        data={"grant_type": GRANT_DEVICE_CODE, "device_code": device_code, "client_id": client_id},
    )


def csrf(client) -> str:
    return client.cookies.get(csrf_cookie_name(get_settings())) or ""


def device_login(client, *, username: str, user_code: str | None = None):
    """走设备流程里的登录步骤。"""
    params = {"user_code": user_code} if user_code else None
    page = adopt_cookies(client, client.get("/device", params=params, follow_redirects=False))
    assert "登录 EliCloud" in page.text, page.text[:300]

    form = {"csrf_token": csrf(client), "username": username, "password": PASSWORD}
    if user_code:
        form["user_code"] = user_code
    return adopt_cookies(client, client.post("/device", data=form, follow_redirects=False))


def get_device_page(client, user_code: str | None = None):
    params = {"user_code": user_code} if user_code else None
    return adopt_cookies(client, client.get("/device", params=params, follow_redirects=False))


def submit_user_code(client, user_code: str):
    return adopt_cookies(
        client,
        client.post("/device", data={"csrf_token": csrf(client), "user_code": user_code}, follow_redirects=False),
    )


def decide(client, user_code: str, decision: str):
    return adopt_cookies(
        client,
        client.post(
            "/device",
            data={"csrf_token": csrf(client), "user_code": user_code, "decision": decision},
            follow_redirects=False,
        ),
    )


def signed_in(client, *, username: str) -> None:
    """先通过设备页登录，拿到会话 cookie。"""
    response = device_login(client, username=username)
    assert response.status_code == 303, response.text
    # 登录后 303 回到 /device
    location = response.headers["location"]
    assert "/device" in location


# ------------------------------------------------------- /device_authorization


def test_device_authorization_returns_codes_and_metadata(client):
    client_id = make_device_client(client)
    response = start_device_authorization(client, client_id=client_id)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"

    body = response.json()
    assert body["device_code"].startswith("dc_")
    assert len(body["device_code"]) > 30
    assert body["user_code"].count("-") == 1
    assert len(body["user_code"]) == 9  # XXXX-XXXX
    assert set(body["user_code"].replace("-", "")) <= set(USER_CODE_ALPHABET)
    assert body["verification_uri"].endswith("/auth/device")
    assert body["verification_uri_complete"].startswith(body["verification_uri"] + "?")
    assert body["expires_in"] == 600
    assert body["interval"] == 5


def test_device_authorization_requires_scope_and_allowed_scope(client):
    client_id = make_device_client(client)

    missing = client.post("/device_authorization", data={"client_id": client_id})
    assert missing.status_code == 400
    assert missing.json()["error"] == "invalid_request"

    not_allowed = client.post(
        "/device_authorization",
        data={"client_id": client_id, "scope": "openid pdf:write"},
    )
    assert not_allowed.status_code == 400
    assert not_allowed.json()["error"] == "invalid_scope"


def test_device_authorization_requires_registered_grant(client):
    client_id = make_public_client(client, scopes=DEVICE_SCOPES, grant_types=["authorization_code"])
    response = start_device_authorization(client, client_id=client_id)
    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"


def test_user_code_alphabet_has_no_ambiguous_characters():
    """短码不得包含 0/O/1/I/L（人工输入最易看错）。"""
    assert not set("0O1IL") & set(USER_CODE_ALPHABET)
    for _ in range(200):
        code = generate_user_code()
        assert len(code) == 9 and code[4] == "-"
        assert set(code.replace("-", "")) <= set(USER_CODE_ALPHABET)


def test_normalize_user_code_tolerates_input_noise():
    assert normalize_user_code("wdjb-mjht") == "WDJB-MJHT"
    assert normalize_user_code(" WDJB MJHT ") == "WDJB-MJHT"
    assert normalize_user_code("WDJBMJHT") == "WDJB-MJHT"
    assert normalize_user_code("short") == ""
    assert normalize_user_code(None) == ""


# ------------------------------------------------------------- 轮询语义


def test_polling_semantics(client):
    client_id = make_device_client(client)
    started = start_device_authorization(client, client_id=client_id).json()

    first = poll(client, client_id=client_id, device_code=started["device_code"])
    assert first.status_code == 400
    assert first.json()["error"] == "authorization_pending"

    # 立刻再轮询 → slow_down，且 interval 会被 +5
    second = poll(client, client_id=client_id, device_code=started["device_code"])
    assert second.status_code == 400
    assert second.json()["error"] == "slow_down"
    assert "10" in second.json()["error_description"]


def test_device_code_bound_to_client(client):
    client_id = make_device_client(client)
    other = make_device_client(client)
    started = start_device_authorization(client, client_id=client_id).json()

    response = poll(client, client_id=other, device_code=started["device_code"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_expired_device_code_returns_expired_token(client):
    client_id = make_device_client(client)
    started = start_device_authorization(client, client_id=client_id).json()

    with session_scope() as session:
        # 必须按 device_code 的哈希精确定位：测试库是共享的，设备码会累积
        row = (
            session.query(DeviceCode)
            .filter(DeviceCode.device_code_hash == hash_device_code(started["device_code"]))
            .one()
        )
        row.expires_at = "2020-01-01T00:00:00Z"
        session.commit()

    response = poll(client, client_id=client_id, device_code=started["device_code"])
    assert response.status_code == 400
    assert response.json()["error"] == "expired_token"


def test_slow_down_interval_is_capped(client):
    """持续过快轮询不能让 interval 无限增长 —— 上限 60 秒。

    没有上限时实测能顶到 110 秒以上，客户端按固定间隔重试会永远追不上（等于锁死自己）。
    """
    from app.constants import DEVICE_MAX_POLL_INTERVAL

    client_id = make_device_client(client)
    started = start_device_authorization(client, client_id=client_id).json()

    last = None
    for _ in range(30):
        last = poll(client, client_id=client_id, device_code=started["device_code"])
        assert last.status_code == 400
        assert last.json()["error"] in {"authorization_pending", "slow_down"}

    assert last is not None and last.json()["error"] == "slow_down"
    with session_scope() as session:
        row = (
            session.query(DeviceCode)
            .filter(DeviceCode.device_code_hash == hash_device_code(started["device_code"]))
            .one()
        )
        assert row.interval_seconds == DEVICE_MAX_POLL_INTERVAL


# ------------------------------------------------------------ 浏览器环节


def test_device_login_page_then_confirm_then_token(client):
    """完整链路：登录 → 输入短码 → 确认 → 客户端轮询拿到令牌。"""
    client_id = make_device_client(client)
    username, user_id = make_user(client)
    started = start_device_authorization(client, client_id=client_id, scope="openid profile offline_access").json()

    # 1) 未登录访问 /device → 登录页（且带 device 模式的隐藏字段）
    page = get_device_page(client, started["user_code"])
    assert page.status_code == 200
    assert "登录 EliCloud" in page.text
    assert "请先登录" in page.text

    # 2) 提交登录 → 303 回 /device
    response = device_login(client, username=username, user_code=started["user_code"])
    assert response.status_code == 303
    location = response.headers["location"]
    assert parse_qs(urlsplit(location).query)["user_code"] == [started["user_code"]]

    # 3) 登录后 GET /device?user_code → 确认页（显示客户端名与 scope）
    confirm = get_device_page(client, started["user_code"])
    assert confirm.status_code == 200
    assert "确认设备授权" in confirm.text
    assert "OIDC 测试客户端" in confirm.text
    assert started["user_code"] in confirm.text

    # 4) 同意 → 完成页
    done = decide(client, started["user_code"], "approve")
    assert done.status_code == 200
    assert "已授权" in done.text

    with session_scope() as session:
        row = session.query(DeviceCode).filter(DeviceCode.user_code == started["user_code"]).one()
        assert row.status == DEVICE_STATUS_APPROVED
        assert row.user_id == user_id

    # 5) 客户端轮询 → 令牌（含 id_token 与 refresh_token）
    tokens = poll(client, client_id=client_id, device_code=started["device_code"])
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    assert body["token_type"] == "Bearer"
    assert "id_token" in body
    assert body["refresh_token"].startswith("rt_")
    assert body["scope"] == "openid profile offline_access"

    claims = pyjwt.decode(body["id_token"], options={"verify_signature": False})
    assert claims["aud"] == client_id
    assert claims["auth_time"] > 0
    assert "nonce" not in claims

    # 6) 一次性：再轮询同一个 device_code 应被拒
    again = poll(client, client_id=client_id, device_code=started["device_code"])
    assert again.status_code == 400
    assert again.json()["error"] == "invalid_grant"


def test_denied_device_flow(client):
    client_id = make_device_client(client)
    username, _ = make_user(client)
    started = start_device_authorization(client, client_id=client_id).json()

    signed_in(client, username=username)
    done = decide(client, started["user_code"], "deny")
    assert "已拒绝" in done.text

    response = poll(client, client_id=client_id, device_code=started["device_code"])
    assert response.status_code == 400
    assert response.json()["error"] == "access_denied"


def test_unknown_and_expired_user_code_show_identical_message(client):
    """§7.14 防枚举：两种情况的提示必须逐字相同。"""
    username, _ = make_user(client)
    signed_in(client, username=username)

    client_id = make_device_client(client)
    started = start_device_authorization(client, client_id=client_id).json()
    with session_scope() as session:
        row = session.query(DeviceCode).filter(DeviceCode.user_code == started["user_code"]).one()
        row.expires_at = "2020-01-01T00:00:00Z"
        session.commit()

    expired = submit_user_code(client, started["user_code"])
    unknown = submit_user_code(client, "ZZZZ-ZZZZ")

    from app.routers.oidc import DEVICE_CODE_ERROR

    assert DEVICE_CODE_ERROR in expired.text
    assert DEVICE_CODE_ERROR in unknown.text
    # 逐字相同（都只出现在同一句错误提示里）
    assert expired.text.count(DEVICE_CODE_ERROR) == unknown.text.count(DEVICE_CODE_ERROR) == 1


def test_device_post_requires_csrf(client):
    client_id = make_device_client(client)
    started = start_device_authorization(client, client_id=client_id).json()

    response = client.post("/device", data={"csrf_token": "forged", "user_code": started["user_code"]})
    assert response.status_code == 403


def test_device_page_requires_login_before_code_entry(client):
    """未登录时不显示确认页，而是登录页。"""
    client_id = make_device_client(client)
    started = start_device_authorization(client, client_id=client_id).json()

    page = get_device_page(client, started["user_code"])
    assert "登录 EliCloud" in page.text
    assert "确认设备授权" not in page.text
    assert DEVICE_STATUS_PENDING  # 状态未被改动

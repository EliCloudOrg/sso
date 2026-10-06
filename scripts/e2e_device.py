"""设备授权流程（RFC 8628）的线上验收脚本（docs/sso-oidc.md §3.2）。

用真实 HTTP 扮演两个角色：**设备（CLI）** 与 **浏览器**（带 cookie jar 走登录/确认表单）。

    docker run --rm --network host \
      -e SSO_BASE=https://146.56.237.33/auth \
      -e SSO_USER=alice -e SSO_PASS="$PW" \
      -e SSO_CLIENT_ID=elicloud-cli \
      elicloud-sso:1.0.0 python scripts/e2e_device.py

覆盖：发起设备授权 → 轮询 authorization_pending → slow_down → 浏览器登录 →
输入短码 → 确认页 → 同意 → 轮询拿到令牌 → 一次性。全部通过时退出码 0。
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt
from jwt.algorithms import RSAAlgorithm

BASE = os.environ["SSO_BASE"].rstrip("/")
USERNAME = os.environ["SSO_USER"]
PASSWORD = os.environ["SSO_PASS"]
CLIENT_ID = os.environ.get("SSO_CLIENT_ID", "elicloud-cli")
SCOPE = os.environ.get("SSO_SCOPE", "openid profile offline_access")
AUDIENCE = os.environ.get("SSO_AUDIENCE", "elicloud-services")

CTX = ssl.create_default_context()
RESULTS: list[tuple[bool, str]] = []
CSRF_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def check(ok: bool, label: str, extra: str = "") -> None:
    RESULTS.append((bool(ok), label))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}{(' | ' + extra) if extra else ''}")


def _lower(response) -> dict[str, str]:
    return {key.lower(): value for key, value in response.headers.items()}


def opener_with_jar() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=CTX),
    )


def call(opener, method: str, path: str, *, data: dict | None = None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(BASE + path, data=body, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(request, timeout=25) as response:
            return response.status, response.read().decode(), _lower(response)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), _lower(exc)


def poll_until_done(opener, device_code: str, *, attempts: int = 12):
    """按**服务端广告的 interval** 重试轮询，直到拿到令牌或遇到**终态**错误。

    ``authorization_pending``（用户还没点确认）与 ``slow_down``（本次轮询过快）
    都是"继续等"的信号。``slow_down`` 时要从错误描述里取出新的 interval 再等 ——
    固定间隔重试会让服务端每次都判定"过快"并继续加大 interval，永远追不上。
    """
    last_status, last_body = 0, ""
    for _ in range(attempts):
        last_status, last_body, _ = call(
            opener,
            "POST",
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": CLIENT_ID,
            },
        )
        if last_status == 200:
            return last_status, last_body
        error = json.loads(last_body).get("error") if last_body else None
        if error not in {"authorization_pending", "slow_down"}:
            return last_status, last_body

        description = json.loads(last_body).get("error_description", "")
        match = re.search(r"(\d+)", description)
        wait = min(float(match.group(1)) if match else 5.0, 60.0)
        print(f"[INFO] 轮询得到 {error}，按服务端 interval 等待 {wait:g}s 后重试")
        time.sleep(wait + 0.5)
    return last_status, last_body


def main() -> int:
    print(f"target = {BASE}\nclient = {CLIENT_ID}\n")
    device = opener_with_jar()  # 扮演 CLI
    browser = opener_with_jar()  # 扮演浏览器

    # 1) 发起设备授权
    status, body, headers = call(
        device, "POST", "/device_authorization", data={"client_id": CLIENT_ID, "scope": SCOPE}
    )
    check(status == 200, "POST /device_authorization 成功", f"status={status}")
    check(headers.get("cache-control") == "no-store", "设备授权响应不可缓存")
    if status != 200:
        print(body[:300])
        return 1

    info = json.loads(body)
    device_code = info["device_code"]
    user_code = info["user_code"]
    check(bool(device_code) and device_code.startswith("dc_"), "返回 device_code")
    check(len(user_code) == 9 and user_code[4] == "-", "返回 XXXX-XXXX 形式的人读短码", f"user_code={user_code}")
    check(
        not set("0O1IL") & set(user_code.replace("-", "")),
        "短码不含易混淆字符 0/O/1/I/L",
    )
    check(info["verification_uri"].endswith("/auth/device"), "verification_uri 指向设备页")
    check(info["interval"] >= 1 and info["expires_in"] > 0, "返回 interval / expires_in")

    # 2) 用户尚未确认 → authorization_pending
    status, body, _ = call(
        device,
        "POST",
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": CLIENT_ID,
        },
    )
    check(status == 400 and json.loads(body).get("error") == "authorization_pending",
          "未确认时轮询得到 authorization_pending", f"status={status}")

    # 3) 立刻再轮询 → slow_down
    status, body, _ = call(
        device, "POST", "/token", data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                        "device_code": device_code, "client_id": CLIENT_ID}
    )
    check(status == 400 and json.loads(body).get("error") == "slow_down",
          "轮询过快得到 slow_down", f"status={status}")

    # 4) 浏览器打开设备页 → 未登录 → 登录页
    status, page, _ = call(browser, "GET", "/device?" + urllib.parse.urlencode({"user_code": user_code}))
    check(status == 200 and "登录 EliCloud" in page, "浏览器打开 /auth/device 得到登录页", f"status={status}")
    match = CSRF_RE.search(page)
    check(match is not None, "登录页带 CSRF 隐藏字段")

    # 5) 浏览器登录 → 303 回 /device
    token = match.group(1) if match else ""
    status, body, headers = call(
        browser,
        "POST",
        "/device",
        data={"csrf_token": token, "username": USERNAME, "password": PASSWORD, "user_code": user_code},
    )
    check(status == 303, "在设备页登录后 303 回跳", f"status={status}")
    check("/device" in headers.get("location", ""), "回跳到设备页", headers.get("location", "")[:80])

    # 6) 登录后回到设备页 → 确认页
    status, page, _ = call(browser, "GET", "/device?" + urllib.parse.urlencode({"user_code": user_code}))
    check(status == 200 and "确认设备授权" in page, "得到确认页", f"status={status}")
    check(user_code in page, "确认页显示短码")
    match = CSRF_RE.search(page)
    token = match.group(1) if match else ""

    # 7) 确认授权
    status, page, _ = call(
        browser,
        "POST",
        "/device",
        data={"csrf_token": token, "user_code": user_code, "decision": "approve"},
    )
    check(status == 200 and "已授权" in page, "确认页提交后提示已授权", f"status={status}")

    # 8) 设备轮询 → 令牌
    #    ⚠️ 前面那两次"立刻轮询"已把 interval 顶到 10 秒，而浏览器那几步花不了那么久，
    #    所以这里必须**按 interval 重试**（真实客户端就该这么做），否则只会一直拿到 slow_down。
    status, body = poll_until_done(device, device_code)
    check(status == 200, "确认后轮询拿到令牌", f"status={status} body={body[:120]}")
    if status == 200:
        tokens = json.loads(body)
        access = tokens["access_token"]
        check(tokens["scope"] == SCOPE, "scope 与请求一致", f"scope={tokens.get('scope')}")
        check("id_token" in tokens, "签发 id_token")
        check(tokens.get("refresh_token", "").startswith("rt_"), "offline_access → 签发 refresh_token")

        status_jwks, jwks_body, _ = call(device, "GET", "/.well-known/jwks.json")
        keys = json.loads(jwks_body)["keys"]
        header = jwt.get_unverified_header(access)
        jwk = next((key for key in keys if key["kid"] == header["kid"]), None)
        try:
            claims = jwt.decode(
                access, RSAAlgorithm.from_jwk(json.dumps(jwk)), algorithms=["RS256"],
                issuer=BASE, audience=AUDIENCE,
            )
            check(True, "access token 用 JWKS 验签通过（iss/aud/exp）")
        except Exception as exc:  # noqa: BLE001
            claims = {}
            check(False, "access token 用 JWKS 验签通过", f"{type(exc).__name__}: {exc}")
        check(claims.get("client_id") == CLIENT_ID, "access token 带 client_id claim")

        # 9) 一次性：同一个 device_code 不能再换
        status, body, _ = call(
            device, "POST", "/token", data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                            "device_code": device_code, "client_id": CLIENT_ID}
        )
        check(status == 400 and json.loads(body).get("error") == "invalid_grant",
              "device_code 一次性（重复兑换被拒）", f"status={status}")

    failed = [label for ok, label in RESULTS if not ok]
    print(f"\n==== {len(RESULTS) - len(failed)}/{len(RESULTS)} 项通过 ====")
    for label in failed:
        print(" -", label)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

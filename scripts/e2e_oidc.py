"""OIDC 授权码 + PKCE 全流程的线上验收脚本（docs/sso-oidc.md §3.1）。

用法（在部署目录下执行；口令通过环境变量注入，脚本不打印口令与令牌原文）：

    docker run --rm --network host \
      -e SSO_BASE=https://146.56.237.33/auth \
      -e SSO_USER=alice -e SSO_PASS="$PW" \
      -e SSO_CLIENT_ID=elipese-app -e SSO_REDIRECT_URI=elipese://callback \
      -e SSO_SCOPE="openid profile offline_access" \
      elicloud-sso:1.0.0 python scripts/e2e_oidc.py

覆盖：发现文档 → /authorize 登录页 + CSRF → 表单登录拿到 code（校验 state 原样回传）
→ /token 用 code+PKCE 换令牌 → 用 JWKS 独立验签 → /userinfo → 授权码重放被拒。
全部通过时退出码 0。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

import jwt
from jwt.algorithms import RSAAlgorithm

BASE = os.environ["SSO_BASE"].rstrip("/")
USERNAME = os.environ["SSO_USER"]
PASSWORD = os.environ["SSO_PASS"]
CLIENT_ID = os.environ.get("SSO_CLIENT_ID", "elipese-web")
REDIRECT_URI = os.environ.get("SSO_REDIRECT_URI", "https://146.56.237.33/callback")
SCOPE = os.environ.get("SSO_SCOPE", "openid profile email")
# access token 的 aud 必须是业务服务用的那个值（§4.1），验签时必须一起校验
AUDIENCE = os.environ.get("SSO_AUDIENCE", "elicloud-services")
EXPECT_REFRESH = os.environ.get("SSO_EXPECT_REFRESH", "auto")  # auto / yes / no

CTX = ssl.create_default_context()
RESULTS: list[tuple[bool, str]] = []
CSRF_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拦住 302，自己读 Location（授权码就在里面）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def check(ok: bool, label: str, extra: str = "") -> None:
    RESULTS.append((bool(ok), label))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}{(' | ' + extra) if extra else ''}")


def build_opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=CTX),
    )


def request(opener, method: str, path: str, *, data: dict | None = None, token: str | None = None):
    url = BASE + path
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with opener.open(req, timeout=25) as response:
            return response.status, response.read().decode(), _lower_headers(response)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), _lower_headers(exc)


def _lower_headers(response) -> dict[str, str]:
    """HTTP/1.1 到达时头名是小写的，统一小写再查，免得大小写踩坑。"""
    return {key.lower(): value for key, value in response.headers.items()}


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def main() -> int:
    print(f"target = {BASE}\nclient = {CLIENT_ID}\n")

    # 1) 发现文档
    opener = build_opener()
    status, body, _ = request(opener, "GET", "/.well-known/openid-configuration")
    discovery = json.loads(body) if status == 200 else {}
    check(discovery.get("issuer") == BASE, "发现文档 issuer 与访问地址一致", f"issuer={discovery.get('issuer')}")

    # 2) /authorize 渲染登录页
    verifier, challenge = pkce_pair()
    state = f"st-{secrets.token_hex(6)}"
    nonce = f"no-{secrets.token_hex(6)}"
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    status, page, _ = request(opener, "GET", "/authorize?" + urllib.parse.urlencode(params))
    check(status == 200 and "登录 EliCloud" in page, "/authorize 渲染登录页", f"status={status}")
    match = CSRF_RE.search(page)
    check(match is not None, "登录页带 CSRF 隐藏字段")

    # 3) 提交登录表单 → 302 拿 code
    form = dict(params)
    form.update({"username": USERNAME, "password": PASSWORD, "csrf_token": match.group(1) if match else ""})
    status, body, headers = request(opener, "POST", "/authorize", data=form)
    location = headers.get("location", "")
    check(status == 302, "/authorize 表单登录后 302 回跳", f"status={status}")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    check(query.get("state") == [state], "state 原样回传")
    code = (query.get("code") or [None])[0]
    check(bool(code), "拿到授权码", f"redirect={location.split('?')[0]}")
    if not code:
        print(body[:400])
        return 1

    # 4) /token 兑换
    status, body, headers = request(
        opener,
        "POST",
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    check(status == 200, "/token 兑换成功", f"status={status}")
    check(headers.get("cache-control") == "no-store", "令牌响应不可缓存")
    if status != 200:
        print(body[:400])
        return 1
    tokens = json.loads(body)
    access = tokens["access_token"]
    check(tokens.get("token_type") == "Bearer" and tokens.get("expires_in"), "返回 token_type / expires_in")
    check(tokens.get("scope") == SCOPE, "scope 与请求一致", f"scope={tokens.get('scope')}")

    wants_refresh = "offline_access" in SCOPE
    has_refresh = "refresh_token" in tokens
    if EXPECT_REFRESH == "yes" or (EXPECT_REFRESH == "auto" and wants_refresh):
        check(has_refresh and tokens["refresh_token"].startswith("rt_"), "offline_access → 签发 refresh_token")
    elif EXPECT_REFRESH == "no":
        check(not has_refresh, "未请求 offline_access → 不发 refresh_token")
    else:
        print(f"[INFO] refresh_token 存在={has_refresh}（scope 含 offline_access={wants_refresh}）")

    # 5) 用 JWKS 独立验签
    status, jwks_body, _ = request(opener, "GET", "/.well-known/jwks.json")
    keys = json.loads(jwks_body)["keys"]
    header = jwt.get_unverified_header(access)
    jwk = next((key for key in keys if key["kid"] == header["kid"]), None)
    check(jwk is not None, "access token 的 kid 在 JWKS 中", f"kid={header['kid']}")
    try:
        claims = jwt.decode(
            access,
            RSAAlgorithm.from_jwk(json.dumps(jwk)),
            algorithms=["RS256"],
            issuer=BASE,
            audience=AUDIENCE,
        )
        check(True, "access token 用 JWKS 验签通过（iss/aud/exp）")
    except Exception as exc:  # noqa: BLE001
        claims = {}
        check(False, "access token 用 JWKS 验签通过", f"{type(exc).__name__}: {exc}")
    check(claims.get("client_id") == CLIENT_ID, "access token 带 client_id claim")
    check(claims.get("nonce") is None, "nonce 不写进 access token（应只在 id_token 里）")

    # 5b) id_token：aud 必须是 client_id，且不能拿来访问业务 API
    if "id_token" in tokens:
        id_token = tokens["id_token"]
        id_header = jwt.get_unverified_header(id_token)
        id_jwk = next((key for key in keys if key["kid"] == id_header["kid"]), None)
        check(id_jwk is not None, "id_token 的 kid 在 JWKS 中")
        try:
            id_claims = jwt.decode(
                id_token,
                RSAAlgorithm.from_jwk(json.dumps(id_jwk)),
                algorithms=["RS256"],
                issuer=BASE,
                audience=CLIENT_ID,
            )
            check(True, "id_token 用 JWKS 验签通过（aud=client_id）")
        except Exception as exc:  # noqa: BLE001
            id_claims = {}
            check(False, "id_token 用 JWKS 验签通过", f"{type(exc).__name__}: {exc}")
        check(id_claims.get("aud") == CLIENT_ID, "id_token 的 aud 是 client_id", f"aud={id_claims.get('aud')}")
        check(id_claims.get("nonce") == nonce, "nonce 原样回传进 id_token")
        check(bool(id_claims.get("auth_time")), "id_token 带 auth_time")
        status_id, _, _ = request(opener, "GET", "/userinfo", token=id_token)
        check(status_id == 401, "id_token 不能用于访问 /userinfo（aud 不同）", f"status={status_id}")
    else:
        check(False, "scope 含 openid → 应签发 id_token")

    # 6) userinfo
    status, body, _ = request(opener, "GET", "/userinfo", token=access)
    check(status == 200, "/userinfo 接受该 access token", f"status={status}")
    if status == 200:
        info = json.loads(body)
        check(info.get("sub") == claims.get("sub"), "/userinfo 的 sub 与令牌一致", f"sub={info.get('sub')}")

    # 7) refresh_token 轮换
    #    ⚠️ 必须排在"授权码重放"**之前**：重放会撤销该码派生的整条 refresh 链（§7.4），
    #    先做重放的话后面就没东西可刷新了 —— 第一版脚本就是顺序错了，报 invalid_grant
    #    「refresh_token 已失效」，一度看起来像产品 bug。
    if tokens.get("refresh_token"):
        original = tokens["refresh_token"]
        status, body, _ = request(
            opener,
            "POST",
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": original, "client_id": CLIENT_ID},
        )
        check(status == 200, "grant_type=refresh_token 轮换成功", f"status={status} body={body[:140]}")
        if status == 200:
            refreshed = json.loads(body)
            latest = refreshed.get("refresh_token")
            check(bool(latest) and latest != original, "refresh_token 已轮换")
            check("id_token" in refreshed, "刷新时重新签发 id_token")

            status_old, body_old, _ = request(
                opener,
                "POST",
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": original, "client_id": CLIENT_ID},
            )
            check(
                status_old == 400 and json.loads(body_old).get("error") == "invalid_grant",
                "旧 refresh_token 重放被拒",
                f"status={status_old}",
            )
            status_latest, _, _ = request(
                opener,
                "POST",
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": latest, "client_id": CLIENT_ID},
            )
            check(
                status_latest == 400,
                "重放判定后整链（含最新令牌）全部撤销",
                f"status={status_latest}",
            )
    else:
        print("[INFO] 本次未签发 refresh_token（scope 未含 offline_access），跳过刷新验收")

    # 8) 授权码重放被拒 —— **放在最后**：它会撤销该码派生的整条 refresh 链（§7.4）
    status, body, _ = request(
        opener,
        "POST",
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    check(status == 400 and json.loads(body).get("error") == "invalid_grant", "授权码重放被拒", f"status={status}")

    failed = [label for ok, label in RESULTS if not ok]
    print(f"\n==== {len(RESULTS) - len(failed)}/{len(RESULTS)} 项通过 ====")
    for label in failed:
        print(" -", label)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

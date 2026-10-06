"""部署后冒烟验收：以「外部客户端」身份打一遍公网地址。

用法（在部署目录下执行，密码通过环境变量注入，绝不写进命令行）：

    docker run --rm -e SSO_BASE=https://146.56.237.33/auth \
        -e SSO_USER=alice -e SSO_PASS="$(cat /tmp/pw)" \
        elicloud-sso:1.0.0 python scripts/e2e_smoke.py

覆盖：JWKS/OIDC 契约、注册开关、登录、用 JWKS 公钥独立验签、userinfo、
HS256 混淆拒绝、refresh 轮换、重放整链撤销、logout、限流、网关路径重写。
脚本不打印口令与令牌原文；全部通过时退出码 0。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

import jwt
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

BASE = os.environ["SSO_BASE"].rstrip("/")
USERNAME = os.environ["SSO_USER"]
PASSWORD = os.environ["SSO_PASS"]
AUDIENCE = os.environ.get("SSO_AUDIENCE", "elicloud-services")
LOGIN_LIMIT = int(os.environ.get("SSO_LOGIN_LIMIT", "10"))

CTX = ssl.create_default_context()
RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, label: str, extra: str = "") -> None:
    RESULTS.append((bool(ok), label))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}{(' | ' + extra) if extra else ''}")


def call(method: str, path: str, body=None, token: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=25, context=CTX) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def build_hs256(claims: dict, secret: bytes, kid: str) -> str:
    """手工构造 HS256 令牌：拿公开的公钥 PEM 当 HMAC 密钥（算法混淆攻击）。"""

    def segment(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

    signing_input = f"{segment({'alg': 'HS256', 'typ': 'JWT', 'kid': kid})}.{segment(claims)}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def main() -> int:
    print(f"target = {BASE}\n")

    # 1) JWKS（匿名）
    status, body = call("GET", "/.well-known/jwks.json")
    jwks = json.loads(body) if status == 200 else {}
    keys = jwks.get("keys", [])
    check(
        status == 200 and bool(keys),
        "GET /auth/.well-known/jwks.json 匿名可访问",
        f"status={status} kids={[k['kid'] for k in keys]}",
    )
    check(
        all(k["alg"] == "RS256" and k["use"] == "sig" and k["kty"] == "RSA" for k in keys),
        "JWKS 全部为 RS256/sig/RSA",
    )

    # 2) OIDC 发现：issuer / jwks_uri 必须与运行地址逐字一致
    status, body = call("GET", "/.well-known/openid-configuration")
    discovery = json.loads(body) if status == 200 else {}
    check(discovery.get("issuer") == BASE, "issuer 与外部访问地址逐字一致", f"issuer={discovery.get('issuer')}")
    check(
        discovery.get("jwks_uri") == f"{BASE}/.well-known/jwks.json",
        "jwks_uri 由同一 base 派生",
        f"jwks_uri={discovery.get('jwks_uri')}",
    )

    # 3) 自助注册按配置关闭
    status, _ = call("POST", "/register", {"username": "should_not_exist", "password": "Whatever123"})
    check(status == 403, "ALLOW_REGISTRATION=false 时 /auth/register 返回 403", f"status={status}")

    # 4) 登录（外部主契约 /auth/login -> 内部 /v1/login）
    status, body = call("POST", "/login", {"username": USERNAME, "password": PASSWORD})
    check(status == 200, "POST /auth/login 成功签发令牌", f"status={status}")
    if status != 200:
        print(body)
        return 1
    tokens = json.loads(body)
    access, refresh = tokens["access_token"], tokens["refresh_token"]
    check(
        tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600,
        "login 返回 token_type/expires_in 契约",
    )
    check(refresh.startswith("rt_"), "refresh_token 是不透明随机串（非 JWT）")

    # 5) 用 JWKS 公钥独立验签（模拟业务服务）
    header = jwt.get_unverified_header(access)
    jwk = next((key for key in keys if key["kid"] == header["kid"]), None)
    check(jwk is not None, "Access Token 的 kid 能在 JWKS 中找到", f"kid={header['kid']}")
    if jwk is None:
        return 1

    claims: dict = {}
    try:
        claims = jwt.decode(
            access,
            RSAAlgorithm.from_jwk(json.dumps(jwk)),
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=BASE,
        )
        check(True, "业务服务可用 JWKS 公钥验签（iss/aud/exp 全部通过）")
    except Exception as exc:  # noqa: BLE001
        check(False, "业务服务可用 JWKS 公钥验签", f"{type(exc).__name__}: {exc}")

    check(
        claims.get("username") == USERNAME and str(claims.get("sub", "")).startswith("user_") and claims.get("scope"),
        "claim 契约：sub/username/scope 齐备",
        f"sub={claims.get('sub')} scope={claims.get('scope')}",
    )

    # 6) userinfo
    status, body = call("GET", "/userinfo", token=access)
    info = json.loads(body) if status == 200 else {}
    check(status == 200 and info.get("sub") == claims.get("sub"), "GET /auth/userinfo 返回当前用户", f"status={status}")
    status, _ = call("GET", "/userinfo")
    check(status == 401, "无令牌访问 /auth/userinfo 返回 401", f"status={status}")
    status, _ = call("GET", "/userinfo", token="garbage.token.here")
    check(status == 401, "错误令牌访问 /auth/userinfo 返回 401", f"status={status}")
    status, _ = call("GET", "/v1/userinfo", token=access)
    check(status == 200, "兼容写法 /auth/v1/userinfo 同样可达", f"status={status}")

    # 7) 算法白名单：HS256 用公钥 PEM 当 HMAC 密钥 → 必须拒绝
    public_pem = RSAAlgorithm.from_jwk(json.dumps(jwk)).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    status, _ = call("GET", "/userinfo", token=build_hs256(claims, public_pem, header["kid"]))
    check(status == 401, "HS256 算法混淆令牌被拒绝", f"status={status}")

    # 8) refresh 轮换 + 重放整链撤销
    status, body = call("POST", "/refresh", {"refresh_token": refresh})
    check(status == 200, "POST /auth/refresh 成功轮换", f"status={status}")
    rotated = json.loads(body)["refresh_token"] if status == 200 else None
    check(rotated is not None and rotated != refresh, "轮换后 refresh_token 已更换")
    status, _ = call("POST", "/refresh", {"refresh_token": refresh})
    check(status == 401, "重放旧 refresh_token 返回 401", f"status={status}")
    status, _ = call("POST", "/refresh", {"refresh_token": rotated})
    check(status == 401, "重放判定后整条链（含最新令牌）全部撤销", f"status={status}")

    # 9) 注销：私有 /v1/logout 已按 A3 下线，标准登出走 /auth/logout（需浏览器会话）
    status, body = call("POST", "/logout")
    check(status == 200, "POST /auth/logout 无会话时渲染已登出页", f"status={status}")
    status, _ = call("POST", "/v1/logout")
    check(status == 404, "私有 POST /auth/v1/logout 已按 A3 下线", f"status={status}")

    # 10) 限流（放最后：会污染该用户名/IP 的计数）
    blocked_at = None
    for attempt in range(1, LOGIN_LIMIT + 4):
        status, _ = call("POST", "/login", {"username": f"{USERNAME}_rl", "password": "WrongPass123"})
        if status == 429:
            blocked_at = attempt
            break
    check(blocked_at is not None, "登录失败达阈值后触发 429 限流", f"第 {blocked_at} 次被拦")

    # 11) 网关路径重写：不存在的路径应为 404
    status, _ = call("GET", "/definitely-not-a-route")
    check(status == 404, "未知路径返回 404（网关重写正确）", f"status={status}")

    failed = [label for ok, label in RESULTS if not ok]
    print(f"\n==== {len(RESULTS) - len(failed)}/{len(RESULTS)} 项通过 ====")
    if failed:
        print("失败项：")
        for label in failed:
            print(" -", label)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

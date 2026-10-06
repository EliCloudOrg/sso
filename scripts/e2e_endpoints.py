"""线上「发现文档 ↔ 网关 ↔ 实现」三方一致性验收。

对应 docs/sso-oidc.md §2.2 硬规则 1（声明的端点必须真的存在）与 §11 的遍历断言，
但打的是**真实公网地址**，因此同时验证了 Caddy 的路径重写。

    docker run --rm --network host -e SSO_BASE=https://146.56.237.33/auth \
      elicloud-sso:1.0.0 python scripts/e2e_endpoints.py

全部通过时退出码 0。
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ["SSO_BASE"].rstrip("/")
CTX = ssl.create_default_context()
RESULTS: list[tuple[bool, str]] = []

# 服务内**保持原路径**的标准端点（必须与 app/constants.py 的 STANDARD_ENDPOINT_PATHS 一致）
STANDARD_PATHS = ("/authorize", "/token", "/device_authorization", "/device", "/logout")

ENDPOINT_KEYS = (
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "device_authorization_endpoint",
    "end_session_endpoint",
)


def check(ok: bool, label: str, extra: str = "") -> None:
    RESULTS.append((bool(ok), label))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}{(' | ' + extra) if extra else ''}")


def request(method: str, url: str, *, data: dict | None = None, headers: dict | None = None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=25, context=CTX) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main() -> int:
    print(f"target = {BASE}\n")

    status, body = request("GET", f"{BASE}/.well-known/openid-configuration")
    check(status == 200, "发现文档可匿名访问", f"status={status}")
    if status != 200:
        return 1
    discovery = json.loads(body)
    check(discovery.get("issuer") == BASE, "issuer 与访问地址逐字一致", discovery.get("issuer", ""))

    # 1) 遍历发现文档里声明的每个端点：都必须不是 404
    for key in ENDPOINT_KEYS:
        url = discovery.get(key)
        if not url:
            check(False, f"{key} 未声明", "（应声明：对应功能已实现）")
            continue
        check(url.startswith(BASE), f"{key} 与 issuer 同源", url)
        status, _ = request("GET", url)
        check(status != 404, f"{key} 真实存在", f"{url} -> {status}")

    # 2) 标准端点必须**保持原路径**（网关只剥 /auth，不重写成 /v1/*）
    for path in STANDARD_PATHS:
        status, _ = request("GET", f"{BASE}{path}")
        check(status != 404, f"标准端点 {path} 未被重写成 /v1{path}", f"status={status}")

    # 3) 私有端点仍走 /auth/<x> → /v1/<x> 重写
    status, body = request(
        "POST",
        f"{BASE}/v1/clients",
        headers={"Authorization": "Bearer definitely-wrong-token"},
    )
    check(status == 401, "私有 /auth/v1/clients 可达且受鉴权保护", f"status={status}")

    status, body = request(
        "POST",
        f"{BASE}/login",
        data={"username": "__nobody__", "password": "WrongPass123"},
        headers={"Content-Type": "application/json"},
    )
    check(status in (401, 400), "私有 /auth/login 可达（错误凭据被拒）", f"status={status}")

    # 4) A3：私有 logout 已下线
    status, _ = request("POST", f"{BASE}/v1/logout")
    check(status == 404, "私有 POST /auth/v1/logout 已下线（A3）", f"status={status}")

    # 5) 登出端点对未注册回跳不跳转（防开放重定向）
    status, _ = request(
        "GET",
        f"{BASE}/logout?" + urllib.parse.urlencode({"post_logout_redirect_uri": "https://evil.example.com/x"}),
    )
    check(status == 200, "未注册的 post_logout_redirect_uri 不跳转", f"status={status}")

    failed = [label for ok, label in RESULTS if not ok]
    print(f"\n==== {len(RESULTS) - len(failed)}/{len(RESULTS)} 项通过 ====")
    for label in failed:
        print(" -", label)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

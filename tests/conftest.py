"""测试环境准备。

关键点：环境变量必须在**任何** app 模块被导入之前写入（config 在导入期读环境），
所以这里在 conftest 顶层就设置好，然后用 app.main.create_app() 构造测试应用。
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_TEST_DIR = Path(tempfile.mkdtemp(prefix="sso-tests-"))

# 与生产同一套派生逻辑，只是 base URL 换成本地测试值
TEST_PUBLIC_BASE_URL = "http://127.0.0.1:8000/auth"
TEST_KID = "test-kid"
TEST_LOGIN_ATTEMPTS = 5
TEST_LOGIN_WINDOW = 60
TEST_ADMIN_TOKEN = "test-admin-token-not-a-real-secret"

os.environ.update(
    {
        "PUBLIC_BASE_URL": TEST_PUBLIC_BASE_URL,
        "CORS_ORIGINS": "http://localhost:3000,http://127.0.0.1:3000",
        "DATABASE_URL": f"sqlite:///{(_TEST_DIR / 'sso-test.db').as_posix()}",
        "JWT_PRIVATE_KEY_PATH": str(_TEST_DIR / "jwt_private.pem"),
        "JWT_KEYS_DIR": str(_TEST_DIR / "keys"),
        "JWT_ALG": "RS256",
        "JWT_KID": TEST_KID,
        "ACCESS_TOKEN_TTL": "3600",
        "REFRESH_TOKEN_TTL": "2592000",
        "ALLOW_REGISTRATION": "true",
        "AUDIENCE": "elicloud-services",
        "DEFAULT_SCOPE": "openid profile email pdf:read pdf:write mc:whitelist",
        "LOGIN_ATTEMPTS_PER_WINDOW": str(TEST_LOGIN_ATTEMPTS),
        "LOGIN_WINDOW_SECONDS": str(TEST_LOGIN_WINDOW),
        "ADMIN_TOKEN": TEST_ADMIN_TOKEN,
        "LOG_LEVEL": "warning",
    }
)


@pytest.fixture(scope="session")
def app_module():
    from app import main

    return main


@pytest.fixture(scope="session")
def settings():
    from app.config import get_settings

    return get_settings()


@pytest.fixture(scope="session")
def client(app_module):
    from fastapi.testclient import TestClient

    with TestClient(app_module.create_app()) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _clean_rate_limiter():
    """限流是进程内状态，测试之间必须隔离。"""
    from app.errors import limiter

    limiter.clear()
    yield
    limiter.clear()


@pytest.fixture(autouse=True)
def _reset_client_cookies(client):
    """TestClient 是 session 级的，cookie 会跨用例泄漏 —— 每个用例前后清空。"""
    client.cookies.clear()
    yield
    client.cookies.clear()

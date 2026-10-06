"""全部配置从环境变量读取。

硬约束（docs/architecture.md §0.4 / §0.9）：issuer 与 jwks_uri 都从
``PUBLIC_BASE_URL`` 派生，代码里零硬编码域名或 IP。域名阶段上线时只改环境变量。

OIDC 扩展（docs/sso-oidc.md §9）：新增的每个端点 URL 同样由 ``external_url(...)``
派生，不写第二份地址、不硬编码。
"""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    # ---- 对外地址：唯一需要随部署阶段改动的配置 -------------------------------
    public_base_url: str = "http://127.0.0.1:8000/auth"
    cors_origins: str = "http://localhost:3000"

    # ---- 存储 ---------------------------------------------------------------
    database_url: str = "sqlite:////data/sso.db"
    jwt_private_key_path: str = "/data/jwt_private.pem"
    jwt_keys_dir: str = "/data/keys"

    # ---- 令牌 ---------------------------------------------------------------
    jwt_alg: str = "RS256"
    jwt_kid: str = "2026-01"
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 2592000  # 30 天
    audience: str = "elicloud-services"
    default_scope: str = "openid profile email pdf:read pdf:write mc:whitelist"

    # ---- OIDC（docs/sso-oidc.md §9）-----------------------------------------
    authorization_code_ttl: int = 60
    id_token_ttl: int = 600
    session_ttl: int = 43200  # 12 小时
    session_cookie_name: str = "elicloud_sso_session"
    device_code_ttl: int = 600
    device_poll_interval: int = 5
    # 客户端管理接口的鉴权令牌。未设置时管理接口整体关闭（fail closed）。
    admin_token: str | None = None

    # ---- 行为 ---------------------------------------------------------------
    allow_registration: bool = False
    login_attempts_per_window: int = 10
    login_window_seconds: int = 900
    log_level: str = "info"

    # ------------------------------------------------------------------ 校验
    @field_validator("public_base_url")
    @classmethod
    def _check_base_url(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        if not cleaned.startswith(("http://", "https://")):
            raise ValueError("PUBLIC_BASE_URL 必须以 http:// 或 https:// 开头")
        if cleaned.endswith("/v1") or "/.well-known" in cleaned:
            raise ValueError("PUBLIC_BASE_URL 只应到服务前缀（如 .../auth），不要带 /v1 或 /.well-known")
        return cleaned

    @field_validator("jwt_alg")
    @classmethod
    def _check_alg(cls, value: str) -> str:
        # 非对称签名是硬约束：业务服务只应拿到公钥，绝不能持有共享密钥。
        if value.strip().upper() != "RS256":
            raise ValueError("JWT_ALG 只允许 RS256（禁止 HS256 等对称算法）")
        return "RS256"

    @field_validator("session_cookie_name")
    @classmethod
    def _check_cookie_name(cls, value: str) -> str:
        name = value.strip()
        if not name or any(ch in name for ch in " ;,=\t\r\n"):
            raise ValueError("SESSION_COOKIE_NAME 不能为空，且不能包含空格或 ; , = 等分隔符")
        return name

    # ------------------------------------------------------------ 派生地址
    @property
    def issuer(self) -> str:
        """JWT 的 iss / OIDC 的 issuer，必须与运行时的对外访问地址逐字一致。"""
        return self.public_base_url.rstrip("/")

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def openid_configuration_uri(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    # OIDC 端点：全部由 PUBLIC_BASE_URL 派生，网关负责把它们映射到服务内路径
    @property
    def authorization_endpoint(self) -> str:
        return self.external_url("authorize")

    @property
    def token_endpoint(self) -> str:
        return self.external_url("token")

    @property
    def userinfo_endpoint(self) -> str:
        return self.external_url("userinfo")

    @property
    def device_authorization_endpoint(self) -> str:
        return self.external_url("device_authorization")

    @property
    def device_verification_uri(self) -> str:
        return self.external_url("device")

    @property
    def end_session_endpoint(self) -> str:
        return self.external_url("logout")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def cookie_path(self) -> str:
        """会话 cookie 的 Path：浏览器看到的是带前缀的对外路径（如 /auth）。"""
        path = urlparse(self.public_base_url).path or "/"
        return path.rstrip("/") or "/"

    @property
    def cookie_secure(self) -> bool:
        """HTTPS 阶段必须开 Secure；IP 阶段用的是受信 IP 证书，可以且应当开。"""
        return self.public_base_url.startswith("https://")

    def external_url(self, path: str) -> str:
        """把服务内路径拼成对外地址（用于 OIDC 发现文档）。"""
        return f"{self.issuer}/{path.lstrip('/')}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """测试用：清掉缓存，让下一次 get_settings() 重新读环境变量。"""
    get_settings.cache_clear()

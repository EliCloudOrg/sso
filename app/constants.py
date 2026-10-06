"""OIDC / OAuth 2.0 协议常量（单一真源，无任何导入依赖）。

放在独立模块是为了避免循环导入：``models.py``（表结构）与 ``oidc.py``（协议校验）
都从这里取值，谁都不用依赖谁。
"""

from __future__ import annotations

# ---------------------------------------------------------------- scope
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "profile"
SCOPE_EMAIL = "email"
SCOPE_OFFLINE_ACCESS = "offline_access"
SCOPE_PDF_READ = "pdf:read"
SCOPE_PDF_WRITE = "pdf:write"
# MC 白名单服务（/mc/*）—— 业务服务按自己的 scope 做授权边界，
# 详见 docs/mc-whitelist.md §6.1 / §12.4。
SCOPE_MC_WHITELIST = "mc:whitelist"

# 与 sso-oidc.md §2.2 的 scopes_supported 保持一致
# ⚠️ 加新 scope 时**四处都要改**：本文件、config.default_scope、
#    device.SCOPE_LABELS（确认页中文说明）、tests/conftest.py 的测试环境变量。
SUPPORTED_SCOPES: tuple[str, ...] = (
    SCOPE_OPENID,
    SCOPE_PROFILE,
    SCOPE_EMAIL,
    SCOPE_OFFLINE_ACCESS,
    SCOPE_PDF_READ,
    SCOPE_PDF_WRITE,
    SCOPE_MC_WHITELIST,
)

# ------------------------------------------------- grant / response type
GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_REFRESH_TOKEN = "refresh_token"
GRANT_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"

SUPPORTED_GRANT_TYPES: tuple[str, ...] = (
    GRANT_AUTHORIZATION_CODE,
    GRANT_REFRESH_TOKEN,
    GRANT_DEVICE_CODE,
)

RESPONSE_TYPE_CODE = "code"
SUPPORTED_RESPONSE_TYPES: tuple[str, ...] = (RESPONSE_TYPE_CODE,)
SUPPORTED_RESPONSE_MODES: tuple[str, ...] = ("query",)

# ------------------------------------------------------ 客户端与认证方式
CLIENT_TYPE_PUBLIC = "public"
CLIENT_TYPE_CONFIDENTIAL = "confidential"
SUPPORTED_CLIENT_TYPES: tuple[str, ...] = (CLIENT_TYPE_PUBLIC, CLIENT_TYPE_CONFIDENTIAL)

AUTH_METHOD_NONE = "none"
AUTH_METHOD_BASIC = "client_secret_basic"
AUTH_METHOD_POST = "client_secret_post"
SUPPORTED_AUTH_METHODS: tuple[str, ...] = (AUTH_METHOD_NONE, AUTH_METHOD_BASIC, AUTH_METHOD_POST)

# ---------------------------------------------------------------- PKCE
CODE_CHALLENGE_S256 = "S256"
CODE_CHALLENGE_PLAIN = "plain"
SUPPORTED_CODE_CHALLENGE_METHODS: tuple[str, ...] = (CODE_CHALLENGE_S256,)
PKCE_VERIFIER_MIN = 43
PKCE_VERIFIER_MAX = 128

# ------------------------------------------------------------ 设备码状态
DEVICE_STATUS_PENDING = "pending"
DEVICE_STATUS_APPROVED = "approved"
DEVICE_STATUS_DENIED = "denied"
DEVICE_STATUS_EXPIRED = "expired"
# 超出文档的一处扩展：设备码一次性，兑换成功后标记为 used
# （否则同一次批准可以被反复兑换出多组令牌）
DEVICE_STATUS_USED = "used"

# 人读短码：去掉易混淆的 0/O/1/I/L，形如 XXXX-XXXX
USER_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
USER_CODE_LENGTH = 8
# 轮询过快时把 interval 递增的步长（RFC 8628 §3.5）
DEVICE_SLOW_DOWN_STEP = 5
# interval 的上限。**必须有上限**：否则一个持续过快轮询的客户端会把 interval
# 一路顶到几百秒（实测到过 110 秒），等于自己把自己锁死 —— 这属于服务端设计缺陷。
DEVICE_MAX_POLL_INTERVAL = 60

# --------------------------------------------------------------- 其他
# 实际会返回的 claim（发现文档的 claims_supported）
SUPPORTED_CLAIMS: tuple[str, ...] = ("sub", "preferred_username", "email", "email_verified")

# 服务内路径**保持原样**的标准 OIDC 端点（网关只剥 /auth，不做 /v1 重写）。
# ⚠️ 这份清单必须与 dsh-nas Caddyfile 里 ② 块的 @standard_oidc 列表一致：
#    本文件用于测试断言，Caddyfile 是真正生效的地方，加端点时两处都要改。
STANDARD_ENDPOINT_PATHS: tuple[str, ...] = (
    "/authorize",
    "/token",
    "/device_authorization",
    "/device",
    "/logout",
)

SESSION_COOKIE_DEFAULT_PATH = "/"

# EliCloud SSO

EliCloud 平台的统一身份认证服务（容器名 `sso`，对外路径前缀 `/auth/*`）：
账号注册/登录、RS256 JWT 签发与刷新、`userinfo`、JWKS 与 OIDC 发现。

> 契约正文见 `docs/architecture.md`（§5 API 契约、§6 模块设计、§0.9 当前 IP 阶段）。

---

## 1. 目录结构

```text
sso/
├── app/
│   ├── main.py            # FastAPI 装配、CORS、统一错误处理、访问日志
│   ├── config.py          # 全部配置从环境变量读；issuer/jwks_uri 由 PUBLIC_BASE_URL 派生
│   ├── db.py              # 引擎/会话/建表（SQLite 起步，可换 PG）
│   ├── models.py          # users / refresh_tokens / oauth_clients
│   ├── keys.py            # RSA 私钥加载与首启生成、JWKS 生成、密钥轮换
│   ├── security.py        # bcrypt 口令哈希、口令强度、JWT 签发与验签
│   ├── deps.py            # 依赖注入、客户端 IP、Bearer 鉴权
│   ├── errors.py          # 统一错误结构 + 进程内限流器
│   ├── cli.py             # 管理员命令（建号/改状态/改密/轮换密钥）
│   └── routers/
│       ├── auth.py        # /v1/register /v1/login /v1/refresh（+ 见 oidc.py）
│       ├── userinfo.py    # /v1/userinfo
│       └── wellknown.py   # /.well-known/jwks.json、/.well-known/openid-configuration
├── tests/                 # 全链路 + 契约 + 令牌安全测试
├── Dockerfile
├── requirements.txt / requirements-dev.txt
├── docker-compose.yml     # IP 阶段部署编排
├── .env.example
└── README.md
```

## 2. 接口清单（服务内路径）

| 方法 | 服务内路径 | 对外路径（经网关） | 说明 |
|---|---|---|---|
| POST | `/v1/register` | `/auth/register` | 注册；`ALLOW_REGISTRATION=false` 时返回 403 |
| POST | `/v1/login` | `/auth/login` | 签发 access + refresh token |
| POST | `/v1/refresh` | `/auth/refresh` | 轮换 refresh token |
| GET/POST | `/v1/userinfo` | `/auth/userinfo` | 标准 UserInfo；**按 scope 过滤 claim**，只返回 `preferred_username` |
| GET/POST | `/logout` | `/auth/logout` | 标准 RP-Initiated Logout（清会话、撤销该会话的链、按注册值回跳） |
| GET | `/.well-known/jwks.json` | `/auth/.well-known/jwks.json` | 匿名公钥集 |
| GET | `/.well-known/openid-configuration` | `/auth/.well-known/openid-configuration` | OIDC 发现 |
| GET/POST | `/authorize` | `/auth/authorize` | OIDC 授权端点（渲染登录页或 302 带 `code`） |
| POST | `/token` | `/auth/token` | 令牌端点（`authorization_code` + `refresh_token` + `device_code`） |
| POST | `/device_authorization` | `/auth/device_authorization` | 设备流程入口，返回 `device_code` 与人读短码 |
| GET/POST | `/device` | `/auth/device` | 设备流程的浏览器页面（登录 / 输入短码 / 确认） |
| POST | `/v1/clients` | `/auth/v1/clients` | 创建 OIDC 客户端（需 `ADMIN_TOKEN`） |
| GET | `/v1/clients` | `/auth/v1/clients` | 列出客户端（需 `ADMIN_TOKEN`） |
| GET/PATCH/DELETE | `/v1/clients/{id}` | `/auth/v1/clients/{id}` | 详情 / 修改 / 删除（需 `ADMIN_TOKEN`） |
| POST | `/v1/clients/{id}/rotate-secret` | `/auth/v1/clients/{id}/rotate-secret` | 轮换客户端 secret |
| GET | `/healthz` | （不经网关） | 容器内健康检查 |

错误结构统一为 `{"error": "...", "error_description": "..."}`；
状态码 `400/401/403/404/409/429`。请求/响应示例见 `docs/architecture.md` §5。

**注意网关做了重写，不是简单剥前缀**（外部路径没有 `/v1`，服务内路径有 `/v1`）：

```text
/auth/.well-known/<x>  ->  /.well-known/<x>
/auth/v1/<x>           ->  /v1/<x>      （兼容写法）
/auth/<x>              ->  /v1/<x>      （§2.2 / §3.1 的主契约）
```

## 3. 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000/auth` | **唯一必须随阶段改的地址**；issuer 与 jwks_uri 由它派生 |
| `CORS_ORIGINS` | `http://localhost:3000` | 逗号分隔的前端来源 |
| `DATABASE_URL` | `sqlite:////data/sso.db` | SQLAlchemy URL；换 PG 改这里 |
| `JWT_PRIVATE_KEY_PATH` | `/data/jwt_private.pem` | 签名私钥，挂卷持久化，权限 600 |
| `JWT_KEYS_DIR` | `/data/keys` | 历史公钥目录，`<kid>.public.pem` 会被发布进 JWKS |
| `JWT_ALG` | `RS256` | 只允许 RS256，配错直接启动失败 |
| `JWT_KID` | `2026-01` | 当前签名密钥标识 |
| `ACCESS_TOKEN_TTL` | `3600` | 秒 |
| `REFRESH_TOKEN_TTL` | `2592000` | 秒（30 天） |
| `AUDIENCE` | `elicloud-services` | JWT `aud` |
| `DEFAULT_SCOPE` | `openid profile email pdf:read pdf:write mc:whitelist` | JWT `scope`；当前不是授权边界。**必须与 `app/config.py` 的 `default_scope` 一致**：环境变量会覆盖代码默认值，只改一处会让新 scope 签不出来（2026-10-06 新增 `mc:whitelist` 时踩过） |
| `ALLOW_REGISTRATION` | `false` | 是否开放自助注册 |
| `LOGIN_ATTEMPTS_PER_WINDOW` | `10` | 同一 IP+用户名 在窗口内的登录尝试上限 |
| `LOGIN_WINDOW_SECONDS` | `900` | 限流窗口（秒） |
| `ADMIN_TOKEN` | （空 = 关闭） | 客户端管理接口 `/v1/clients` 的 Bearer 令牌；**未配置时整组接口返回 403** |
| `AUTHORIZATION_CODE_TTL` | `60` | 授权码有效期（秒） |
| `ID_TOKEN_TTL` | `600` | `id_token` 有效期（秒） |
| `SESSION_TTL` | `43200` | 浏览器登录会话有效期（12 小时） |
| `SESSION_COOKIE_NAME` | `elicloud_sso_session` | 会话 cookie 名 |
| `DEVICE_CODE_TTL` | `600` | 设备码有效期（秒） |
| `DEVICE_POLL_INTERVAL` | `5` | 设备流程轮询间隔（秒） |
| `LOG_LEVEL` | `info` | 日志级别 |

`issuer` / `jwks_uri` **不单独配置**，避免两者不一致：

```text
issuer   = PUBLIC_BASE_URL.rstrip("/")
jwks_uri = issuer + "/.well-known/jwks.json"
```

## 4. 启动方式

### 4.1 容器（推荐，本平台的标准形态）

```bash
cd /home/docker-admin/elicloud/sso
cp .env.example .env          # 按当前阶段改 PUBLIC_BASE_URL / CORS_ORIGINS
mkdir -p data                 # 必须存在且属于 uid 1002（docker-admin）
docker compose up -d --build
docker compose logs -f sso
```

本服务**不向公网暴露端口**：只加入 `dsh-caddy` 所在的 external 网络，
再由网关把 `/auth/*` 转发进来；`127.0.0.1:8000` 的回环映射只为本机调试。

建第一个账号（关闭自助注册时）：

```bash
docker compose exec sso python -m app.cli create-user --username alice --password-stdin
docker compose exec sso python -m app.cli list-users
docker compose exec sso python -m app.cli show-config      # 打印生效配置（不含私钥内容）
```

### 4.2 本地开发

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
export PUBLIC_BASE_URL=http://127.0.0.1:8000/auth JWT_PRIVATE_KEY_PATH=$PWD/data/jwt_private.pem \
       DATABASE_URL=sqlite:///$PWD/data/sso.db JWT_KEYS_DIR=$PWD/data/keys ALLOW_REGISTRATION=true
uvicorn app.main:app --reload --port 8000
```

### 4.3 网关配置（dsh-caddy）

SSO 由既有的 `dsh-caddy`（`/home/docker-admin/dsh-nas/caddy/Caddyfile`）对外提供 HTTPS。
关键片段（这组规则已在隔离容器里逐条验证过映射结果）：

```caddyfile
# ⚠️ 站点地址必须带 /auth/* 路径：同一 host 上若有两个裸地址相同的站点块，
#    Caddy 会直接报 "ambiguous site definition" 并拒绝启动。
https://146.56.237.33/auth/* {
	tls { issuer acme { profile shortlived } }   # Let's Encrypt 的 IP 证书
	log

	# 1) /.well-known 挂在服务根：只剥 /auth，不能再补任何段
	handle /auth/.well-known/* {
		uri strip_prefix /auth
		reverse_proxy sso:8000
	}

	# 2) 兼容写法：外部也接受 /auth/v1/...
	handle /auth/v1/* {
		uri strip_prefix /auth
		reverse_proxy sso:8000
	}

	# 3) 主契约：/auth/<x> -> /v1/<x>
	handle_path /auth/* {
		rewrite * /v1{uri}
		reverse_proxy sso:8000
	}
}
```

站点地址里的 `/auth/*` 只用来**选中这个站点块**，请求路径本身不变，
所以块内仍然匹配完整的 `/auth/...` 路径。

验证过的映射：

```text
POST /auth/login                            -> POST /v1/login
POST /auth/register?x=1                     -> POST /v1/register?x=1
GET  /auth/.well-known/jwks.json            -> GET  /.well-known/jwks.json
GET  /auth/.well-known/openid-configuration -> GET  /.well-known/openid-configuration
GET  /auth/v1/userinfo                      -> GET  /v1/userinfo     （兼容写法）
GET  /auth/userinfo                         -> GET  /v1/userinfo
```

> ⚠️ Caddy 没有 `uri prepend`；`/auth/<x>` → `/v1/<x>` 必须写成
> `handle_path /auth/*` + `rewrite * /v1{uri}`（顺序由 `handle_path` 结构性保证）。
> 另外注意 **不要**用 `handle_path /auth/.well-known/*`——它会把
> `/auth/.well-known` 整段剥掉，只剩 `/jwks.json`。

改配置后**先用一次性容器校验，再热加载**（校验失败时容器根本不会启动，
若直接 `docker restart` 会让网关进入崩溃循环、公网全部 502）：

```bash
# 1) 校验（不依赖正在运行的容器，配置写错也不会影响线上）
docker run --rm --entrypoint caddy -v /home/docker-admin/dsh-nas/caddy:/etc/caddy:ro \
  caddy:2-alpine validate --config /etc/caddy/Caddyfile     # 必须看到 Valid configuration

# 2) 通过后再热加载（不中断现有连接）
docker exec dsh-caddy caddy reload --config /etc/caddy/Caddyfile
```

> Caddyfile 挂载的是**目录**而非单文件，所以就地编辑即可生效（单文件绑定会因 inode 替换而读到旧内容）。

> ⚠️ IP 字面量访问时客户端不发送 SNI，全局块里必须保留
> `default_sni <本机公网IP>`，否则 TLS 握手会失败。

## 5. 令牌语义与已知取舍

- **Access Token**：无状态 RS256 JWT，`iss/sub/username/scope/aud/iat/exp/jti`，
  默认 1 小时。业务服务从 JWKS 拉公钥验签，只信任 `alg=RS256`（`HS256`、`alg:none`、未知 `kid` 一律拒绝）。
- **⚠️ 注销后 access token 在 TTL 内仍然有效**。这是无状态 JWT 的固有取舍：
  标准 `/logout` 只能立即撤销会话与 refresh token，无法让已签发的 access token 失效。
  要做到即时失效必须引入吊销名单（每次请求查库/查 Redis），本项目一期**不引入**，
  改用**短 TTL + refresh 轮换**把风险窗口压到 1 小时。
  需要更严格时可把 `ACCESS_TOKEN_TTL` 调到 `900`（15 分钟）。
- **Refresh Token**：`rt_` 前缀的不透明随机串（`secrets.token_urlsafe(32)`），
  库里只存 SHA-256，可即时撤销。每次刷新**轮换**：旧令牌立即标记 `used_at`。
- **重放检测**：已轮换过的旧令牌再次出现，说明令牌可能被窃取，
  该令牌所属 **family（一次登录 = 一条链）** 的全部 refresh token 立即整体撤销，强制重新登录。
  这比"按 user_id 全撤"更精确，不会误伤同一账号的其它设备。
- **登出**：标准 `/logout` 撤销的是**该浏览器会话派生的整条链**（靠 `refresh_tokens.session_id` 精确定位），
  同一账号在其它设备上的登录不受影响。私有 `POST /v1/logout` 已按 §1.3 的 A3 决策**下线**
  （详见 §18）。
- **`sub` 一经签发永不变更**，是业务数据隔离的唯一依据；用户名/邮箱可变。

## 6. 表结构

```sql
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,          -- 如 user_0001，对外即 sub
  username      TEXT UNIQUE NOT NULL,
  email         TEXT UNIQUE,               -- 可空，唯一
  password_hash TEXT NOT NULL,             -- bcrypt(cost=12)，绝不存明文/摘要
  status        TEXT NOT NULL DEFAULT 'active',   -- active / disabled
  created_at    TEXT NOT NULL,             -- ISO8601 UTC，如 2026-01-01T00:00:00Z
  updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id),
  family_id   TEXT NOT NULL,               -- 令牌链（一次登录 = 一条链）
  token_hash  TEXT NOT NULL UNIQUE,        -- sha256(refresh_token)
  expires_at  TEXT NOT NULL,
  used_at     TEXT,                        -- 已被轮换使用的时间，再次使用即判定为重放
  revoked_at  TEXT,
  created_at  TEXT NOT NULL,
  user_agent  TEXT,
  ip          TEXT
);

CREATE TABLE IF NOT EXISTS oauth_clients (  -- 本期只建表不使用
  client_id     TEXT PRIMARY KEY,
  client_secret_hash TEXT NOT NULL,
  name          TEXT NOT NULL,
  redirect_uris TEXT,
  scopes        TEXT,
  created_at    TEXT NOT NULL
);
```

只用 SQLite 也支持的通用类型（TEXT + ISO8601 字符串），换 PostgreSQL 不需要改表。
建表是 `CREATE TABLE IF NOT EXISTS` 语义，启动时自动执行，不引入 Alembic。

## 7. 密钥管理

- 私钥 `JWT_PRIVATE_KEY_PATH` 落在挂卷目录（`./data`），权限 `600`，
  **绝不打进镜像层、绝不进 Git**。首次启动自动生成，之后永不重新生成——
  容器重建若重新生成密钥，所有已签发令牌会立即失效。
- 私钥不进日志、不进接口响应；`app/cli.py show-config` 也只打印路径与 kid。
- **密钥轮换**（新旧公钥并存，轮换瞬间业务服务不会全部验签失败）：

```bash
docker compose exec sso python -m app.cli rotate-key --new-kid 2026-07
# 把 .env 里的 JWT_KID 改为 2026-07，然后
docker compose up -d sso
```

  旧公钥被归档到 `JWT_KEYS_DIR/<旧kid>.public.pem` 并**继续出现在 JWKS 里**，
  因此旧 access token 在过期前仍可验签；确认全部过期后即可从该目录删除旧公钥。

## 8. 安全设计要点

- 口令只存 **bcrypt（cost=12）** 哈希；强度要求：≥8 位、≤64 位、≤72 字节、
  必须同时含字母与数字、不得是常见弱口令。
- 登录失败**不区分**「用户不存在 / 密码错误 / 账号被禁用」，响应逐字相同；
  用户不存在时也会执行一次 bcrypt 校验，避免用响应时间枚举账号。
- 登录限流按 **IP + 用户名** 双维度（默认 10 次 / 15 分钟），成功后清零；
  同一 IP 跨用户名的总尝试放宽 5 倍以免误伤共享出口。超限返回 `429` 带 `Retry-After`。
- 日志**绝不记录**密码与令牌原文，只记 `user_id`、结果、耗时；响应不回显 `password_hash`。
- 验签算法白名单只有 RS256；未知 `kid` 拒绝。
- 客户端 IP 取 `X-Forwarded-For` 的**最后一段**（Caddy 追加的真实来源），
  取第一段会被调用方伪造。**前提是服务不直接暴露端口**（本编排满足）。

已知限制（一期接受）：

- 限流器是**进程内**内存计数；多副本部署时各副本独立计数，需要时换 Redis。
- 无状态 access token 在 TTL 内无法即时吊销（见 §5 的取舍说明）。

> **OIDC 扩展已全部落地**（规格 `docs/sso-oidc.md`）：授权码 + PKCE(S256)、refresh 轮换、
> 设备流程（RFC 8628）、`id_token`、会话 cookie + CSRF 登录页、标准 RP-Initiated Logout、
> 客户端静态注册与管理接口、发现文档与网关对齐。
> 原先本节记录的"`/authorize` 未实现、`token_endpoint` 指向 `/refresh`"两个占位问题**都已修复**。
> 各流程见 §14–§18。

## 9. 阶段切换：IP → 域名（域名 `api.elipese.cloud` 可用后）

1. 改 `.env` 两行并重启：

```bash
PUBLIC_BASE_URL=https://api.elipese.cloud/auth
CORS_ORIGINS=https://elipese.cloud,https://www.elipese.cloud
docker compose up -d sso
```

2. 网关侧：`dsh-nas/caddy/Caddyfile` 里把 SSO 站点地址改为 `https://api.elipese.cloud`
   （去掉 `tls { issuer acme { profile shortlived } }`，域名走正常的 Let's Encrypt 证书），
   同样 `caddy validate` + `caddy reload`。
3. **清空 `refresh_tokens`**（避免遗留无效令牌），用户重新登录一次：

```bash
docker compose exec sso python -c "from app.db import init_db,session_scope; from app.config import get_settings; from app.models import RefreshToken; init_db(get_settings()); s=session_scope(); s.query(RefreshToken).delete(); s.commit()"
```

4. 业务服务侧只需把各自的 `SSO_ISSUER` / `SSO_JWKS_URL` 换成新地址，**代码一行不用改**。

**已知影响**：切换后旧 issuer 签发的 access/refresh token 全部失效，用户需重新登录一次
（一次性代价，可接受）；**用户数据（`users` 表）不受影响**。
需要保留兼容期时，可在网关同时保留旧地址路由，等服务端缓存过期后再下线。

`PUBLIC_BASE_URL` 的 scheme 必须与实际情况一致（HTTP 阶段不要写 `https://`），
否则客户端按 issuer 拼出来的 JWKS 地址连不上。

## 10. 运维

```bash
docker compose ps                      # 状态（应显示 healthy）
docker compose logs -f sso             # 应用日志（不含密码/令牌）
curl -s http://127.0.0.1:8000/.well-known/jwks.json | head -c 200   # 容器内自检
curl -sS https://<IP>/auth/.well-known/jwks.json                    # 经网关自检
```

排错顺序：

1. **所有令牌验签失败** → 先比对 SSO 的 `PUBLIC_BASE_URL` 与业务服务的 `SSO_ISSUER` 是否逐字相同。
2. TLS 握手失败 → 检查 Caddyfile 全局块的 `default_sni` 是否为本机公网 IP。
3. `/auth/*` 返回 404 → 检查网关重写规则（外部 `/auth/login` → 内部 `/v1/login`）。
4. 健康检查失败 → `docker compose logs sso` 看是否有配置校验或密钥加载错误。

备份：`./data` 目录（`sso.db` + `jwt_private.pem` + `keys/`）。
私钥丢失 = 所有已签发令牌失效且无法恢复；请与数据库一并备份。

## 11. 测试

### 11.1 单元/契约测试（172 项）

一条命令跑通，覆盖：

| 覆盖面 | 文件 |
|---|---|
| 私有密码直连全链路、重放整链撤销、JWKS/OIDC 契约、HS256/alg:none 拒绝、限流、密钥持久化与轮换 | `tests/test_auth_flow.py` |
| 幂等迁移（旧表重建、非空拒绝、补列幂等） | `tests/test_db_migration.py` |
| 客户端注册与管理接口 | `tests/test_clients.py` |
| PKCE / scope 纯函数（含 RFC 7636 已知向量） | `tests/test_oidc_helpers.py` |
| `/authorize`（开放重定向防线、PKCE、CSRF、防会话固定） | `tests/test_authorize.py` |
| `/token`（客户端认证、绑定关系、一次性、重放） | `tests/test_token.py` |
| `id_token`（aud 差异、nonce、auth_time、不可用于 API） | `tests/test_id_token.py` |
| `/userinfo`（scope 过滤、GET/POST、B2 回归防线） | `tests/test_userinfo.py` |
| refresh grant（跨客户端、防提权、私有/OIDC 令牌互不通用） | `tests/test_refresh_grant.py` |
| 设备流程（短码、轮询状态机、interval 封顶、防枚举） | `tests/test_device_flow.py` |
| 标准登出（防开放重定向、多设备隔离、A3 下线回归） | `tests/test_logout.py` |
| 发现文档自我一致性（遍历所有声明端点断言非 404） | `tests/test_discovery.py` |

```bash
pip install -r requirements-dev.txt
pytest -q
```

容器内跑（本机不必装 Python 环境）。注意容器以非 root 运行，需要 `HOME` 可写：

```bash
docker compose run --rm --no-deps --entrypoint sh -e HOME=/tmp sso -c \
  "pip install -q --target /tmp/testdeps -r requirements-dev.txt; \
   PYTHONPATH=/tmp/testdeps python -m pytest -q -p no:cacheprovider tests"
```

### 11.2 部署后冒烟验收（公网，4 个脚本）

四个脚本都以「外部客户端」身份打**公网地址**，口令通过环境变量注入，脚本不打印口令与令牌原文。

| 脚本 | 项数 | 覆盖 |
|---|---|---|
| `scripts/e2e_smoke.py` | 24 | 私有端点全链路（注册/登录/刷新/userinfo/JWKS/限流/A3 后的注销检查） |
| `scripts/e2e_oidc.py` | 29 | 授权码 + PKCE + 刷新轮换 + `id_token` 验签 + 重放 |
| `scripts/e2e_device.py` | 23 | 设备流程 RFC 8628（同时扮演设备与浏览器） |
| `scripts/e2e_endpoints.py` | 23 | **发现文档 ↔ 网关 ↔ 实现** 三方一致性（遍历每个声明的端点） |

```bash
docker run --rm --network host -e SSO_BASE=https://146.56.237.33/auth \
  elicloud-sso:1.0.0 python scripts/e2e_endpoints.py    # 不需要账号，随时可跑
```

### 11.3 密钥持久化验收

重建容器后旧令牌必须仍然有效（否则等于每次部署把所有人踢下线）：

```bash
docker compose up -d --force-recreate
# 用重建前拿到的 access_token 打 /auth/userinfo，应仍返回 200
```

---

## 12. 本机部署记录（ElipeseServer / IP 阶段）

| 项 | 值 |
|---|---|
| 公网 IP | `146.56.237.33` |
| 部署入口（自托管部署框架） | `/srv/sso/deploy.sh` + `/srv/sso/app.env`，见 [`README-deploy.md`](README-deploy.md) |
| Docker 可见的项目目录 | `/home/deploy/elicloud-sso`（compose 项目 `sso`，编排由 `deploy.sh` 生成；snap Docker 看不到 `/srv`） |
| 数据目录 | `/home/docker-admin/elicloud/sso/data`（`jwt_private.pem` 600 + `sso.db`），属主 uid 1002:1003，**不随部署移动** |
| 容器 | `sso`，`ghcr.io/elicloudorg/sso:prod`（由 Actions 构建推送），以 `1002:1003` 运行，`restart: unless-stopped` |
| 网络 | 加入 external 网络 `dsh-nas_dsh-net`（复用既有 dsh-caddy，不改 dsh-nas 编排） |
| 端口 | 仅 `127.0.0.1:8000`（本机调试）；公网入口是网关的 80/443 |
| 网关 | 既有 `dsh-caddy` v2.11.4（静态 Caddyfile，**不是** caddy-docker-proxy） |
| Caddyfile | `/home/docker-admin/dsh-nas/caddy/Caddyfile`，备份 `Caddyfile.bak.20260925-163602`、`Caddyfile.bak.20260925-164*` |
| 证书 | Let's Encrypt **IP 证书**（`tls { issuer acme { profile shortlived } }`，6 天期自动续期，SAN = IP） |

> **2026-10-06 起：部署方式改由自托管部署框架接管**（触发与部署器分离，见
> [`README-deploy.md`](README-deploy.md) 与 `docs/deploy-framework.md`）。
> 网关、证书、公网行为与上面这张表**都不变**；变的只是「谁把新版本送到服务器上」：
> 以前是在 `/home/docker-admin/elicloud/sso` 里 `docker compose up -d --build`（本地构建），
> 现在是 Actions 构建并推送 `ghcr.io/elicloudorg/sso:prod`，再由 `/srv/sso/deploy.sh` 拉取重建。
> 因此本文档下文里的 `docker compose ...` 命令，操作目录已改为 `/home/deploy/elicloud-sso`
> （属主 `deploy`），例如：
>
> ```bash
> sudo -u deploy docker compose --project-directory /home/deploy/elicloud-sso ps
> sudo -u deploy docker compose --project-directory /home/deploy/elicloud-sso exec sso python -m app.cli list-users
> ```

网关与相关配置的改动（公网 IP 因服务器被攻击而更换，被攻击前的旧 IP 已完全不可达）：

1. 全局块 `default_sni` → `146.56.237.33`（IP 字面量访问不发 SNI，缺了它 TLS 握手失败）；
2. 面板站点块地址：从被攻击前的旧 IP 改为 `https://146.56.237.33`；
3. 文件末尾追加 SSO 站点块，地址为 `https://146.56.237.33/auth/*`（正文另存 `/home/docker-admin/elicloud/sso-caddy-block.Caddyfile`）；
4. `dsh-nas/docker-compose.yml` 的 `DSH_TRUSTED_HOSTS` → `146.56.237.33` 并重建 `dsh-web`（面板中断约 15 秒，`./data` 不受影响）；
5. `dsh-nas/set-password.sh` 的自检 Host 改为从 `default_sni` 派生（原来写死旧 IP，导致自检假成功）；
6. `dsh-nas/README.md`、`docs/architecture.md` 里的旧地址；
7. `/etc/vsftpd.conf` 的 `pasv_address`（需 root，用 `ubuntu` 账号的免密 sudo 完成）。

另外删掉了 Caddy 存储里属于旧 IP 的失效证书，避免一直做无意义的 ACME 续期。

**当前公网行为（已实测）**：

```text
https://146.56.237.33/                        -> 401 Basic Auth（面板，进入后由 DSH 自己再做一次令牌鉴权）
http://146.56.237.33/                         -> 308 跳转到 HTTPS
https://146.56.237.33/auth/.well-known/jwks.json -> 200（匿名，SSO）
https://146.56.237.33/auth/login              -> 200/405（匿名，SSO）
```

> 面板链路的实现细节：浏览器 → `dsh-caddy`(Basic Auth + 注入 DSH 会话 cookie)
> → `dsh-web:3081`（容器内另有一层 Caddy，把 `Host`/`Origin` 改写成 `127.0.0.1:3080`
> 以满足 DSH 特权 API 的 anti-DNS-rebinding 要求）→ `dsh`(3080)。
> 因为内层做了这个改写，`DSH_TRUSTED_HOSTS` 对公网路径其实不是必需的，
> 但它既然是白名单式配置，就不该留着失效的旧 IP。

同一 host 上「带 Basic Auth 的面板块 + SSO 块」共存也已验证：`/` 由面板独占（401），
`/auth/*` 匿名可达 —— Caddy 按 path matcher 具体程度排序，无 matcher 的兜底路由排在后面。

> ⚠️ **再换 IP 时的完整清单**（漏一处就会出现「所有令牌验签失败」或「面板打不开」）：
>
> | # | 位置 | 改什么 |
> |---|---|---|
> | 1 | `sso/.env` | `PUBLIC_BASE_URL`（改完 `docker compose up -d sso`，issuer 变化会让旧令牌全失效） |
> | 2 | `dsh-nas/caddy/Caddyfile` 全局块 | `default_sni` |
> | 3 | `dsh-nas/caddy/Caddyfile` 面板站点块 + SSO 站点块 | 两个站点地址里的 IP |
> | 4 | `dsh-nas/docker-compose.yml` | `DSH_TRUSTED_HOSTS`（改完重建 `dsh-web`） |
> | 5 | `/etc/vsftpd.conf` | `pasv_address`（需 root；用 `ubuntu` 账号的免密 sudo） |
>
> 排查手法：直接全盘搜一遍，比逐个文件猜可靠得多。
>
> ```bash
> # 服务器：文件 + 运行时容器
> grep -rIl '<旧IP>' /home /root /etc /srv /opt /usr/local 2>/dev/null | grep -v '\.bak'
> for c in $(docker ps -aq); do docker inspect "$c" | grep -q '<旧IP>' && echo "容器命中: $c"; done
> # 本机：SSH 配置与 known_hosts
> grep -rn '<旧IP>' ~/.ssh/
> ```
>
> 强烈建议把公网 IP 固定为**弹性 IP**，从此不必再改这些。
> 改完记得删掉 Caddy 存储里旧 IP 的证书目录：
> `/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<旧IP>/`。
>
> ### ✅ 顺带修掉的：`/etc/vsftpd.conf` 的 `pasv_address`
>
> 全盘替换时发现 **vsftpd 把被动模式地址广告成旧 IP**，而它是 `active` + `enabled`：
> FTP 客户端默认走被动模式，连数据通道时会去连一个已死的地址，**传输必然失败**。
>
> 已改为 `pasv_address=146.56.237.33` 并重启服务（备份 `/etc/vsftpd.conf.bak.20260925-213911`）。
> 权限提示：**`docker-admin` 没有免密 sudo，`ubuntu` 账号有** —— 改系统配置请用后者。
>
> 另注：被动端口段 `50000-50100` 目前**未对公网放行**（实测不可达），
> 所以从公网用 FTP 仍然连不上数据通道；真要启用还得在云安全组放行该端口段。

---

## 13. OIDC 客户端管理（`docs/sso-oidc.md` §5）

OIDC 客户端是**静态注册**的（一期不做 RFC 7591 动态注册），有两条等价路径：
容器内 CLI（日常用这个，不需要令牌）与 HTTP 管理接口（需要 `ADMIN_TOKEN`）。

### 13.1 CLI（推荐）

```bash
cd /home/docker-admin/elicloud/sso
CLI="docker compose exec sso python -m app.cli"

$CLI create-client --client-id elipese-web --name "Elipese Web" --type public \
  --redirect-uri https://146.56.237.33/callback \
  --redirect-uri http://localhost:5173/callback \
  --scope "openid profile email"
$CLI list-clients
$CLI show-client   --client-id elipese-web
$CLI rotate-client-secret --client-id <confidential 客户端>
$CLI delete-client --client-id elipese-web        # 加 --yes 跳过交互确认
```

- `--redirect-uri` 可重复，**必须与客户端实际回跳地址逐字一致**（校验是精确匹配，见 §13.3）。
- `--scope` 空格分隔；`--grant-type` 可重复，不传则默认 `authorization_code refresh_token`。
- 纯设备码客户端（如 `elicloud-cli`）**不需要** `redirect_uri`。
- **confidential 客户端的 `client_secret` 明文只在创建 / 轮换那一次打印**，之后任何入口都不回显（库里只有 SHA-256）。

### 13.2 HTTP 管理接口

需要 `.env` 里的 `ADMIN_TOKEN`（生成：`openssl rand -hex 32`）。**未配置时整组接口返回 403**（fail closed，不是放行）。

| 方法 | 对外路径 | 说明 |
|---|---|---|
| POST | `/auth/v1/clients` | 创建；响应里带一次性的 `client_secret` |
| GET | `/auth/v1/clients` | 列出（永不回显 secret / 其哈希） |
| GET | `/auth/v1/clients/{id}` | 详情 |
| PATCH | `/auth/v1/clients/{id}` | 改 `name` / `redirect_uris` / `post_logout_redirect_uris` / `allowed_scopes` / `allowed_grant_types` |
| DELETE | `/auth/v1/clients/{id}` | 删除，并撤销其 refresh 链、清掉授权码/设备码/同意记录 |
| POST | `/auth/v1/clients/{id}/rotate-secret` | 轮换 secret（旧 secret 立即失效） |

```bash
TOKEN=$(grep '^ADMIN_TOKEN=' .env | cut -d= -f2-)
curl -s -H "Authorization: Bearer $TOKEN" https://146.56.237.33/auth/v1/clients
```

`client_type` 与 `token_endpoint_auth_method` **刻意不可 PATCH**：它们决定认证强度，
要改就删除重建 —— 避免悄悄把 public 客户端改成 confidential（或反过来）。
请求体带未知字段会直接 400（`extra=forbid`），不会被静默忽略。

### 13.3 校验规则（踩坑速查）

| 项 | 规则 |
|---|---|
| `client_id` | 2~64 位，以字母/数字开头，仅含字母、数字、`_ . : -` |
| `redirect_uri` | 必须是**绝对 URI**、不得含 `#`；`http(s)` 必须带主机；拒绝 `javascript:` / `data:` / `file:` / `vbscript:`；自定义 scheme（如 `elipese://callback`）允许 |
| 是否需要 `redirect_uri` | 只有含 `authorization_code` 的客户端才要求 |
| `allowed_scopes` | 必须是平台支持集合的子集：`openid` `profile` `email` `offline_access` `pdf:read` `pdf:write`（保序保存，`openid` 打头） |
| `allowed_grant_types` | 仅 `authorization_code` / `refresh_token` / `urn:ietf:params:oauth:grant-type:device_code` |
| public 客户端 | `token_endpoint_auth_method` 只能是 `none`（认证靠 PKCE S256） |
| confidential 客户端 | 必须是 `client_secret_basic` 或 `client_secret_post` |

### 13.4 一期已预置的客户端

按 `docs/sso-oidc.md` §5.4（并把 §12.3 说的 IP 阶段回跳地址一并登记）：

| client_id | 类型 | redirect_uris | scopes |
|---|---|---|---|
| `elipese-web` | public | `https://146.56.237.33/callback`、`http://localhost:5173/callback`、`http://127.0.0.1:5173/callback`、`https://elipese.cloud/callback` | `openid profile email` |
| `elipese-app` | public | `elipese://callback` | `openid profile email offline_access` |
| `elicloud-cli` | public | （无，走设备码） | `openid profile offline_access` |

域名上线后记得把 `redirect_uris` 更新为域名形态（CLI `PATCH` 或 `update_client`）。

---

## 14. 授权端点与登录页（`docs/sso-oidc.md` §2.3）

这是服务里**唯一有浏览器会话 cookie**的部分（此前全是纯 Bearer、零 cookie），所以安全约束最密。

### 14.1 流程

```text
GET  /auth/authorize?response_type=code&client_id&redirect_uri&scope&state&nonce&code_challenge&code_challenge_method=S256&prompt
  ├─ client_id / redirect_uri 不可信 → 400 渲染错误页（**不重定向**）
  ├─ 其它参数不合法        → 302 redirect_uri?error=...&state=...
  ├─ 已有有效会话          → 直接 302 redirect_uri?code=...&state=...
  ├─ prompt=none 且无会话   → 302 redirect_uri?error=login_required
  └─ 否则                 → 渲染登录页（下发 CSRF cookie + 隐藏字段）

POST /auth/authorize   （表单：username/password/csrf_token + 原样透传的授权参数）
  ├─ 重新校验**每一个**参数（隐藏字段可被篡改，一律不信任）
  ├─ CSRF 双重提交校验失败 → 403 错误页
  ├─ 口令错误             → 重新渲染登录页 + 统一文案（不区分失败原因）
  └─ 成功 → 撤销旧会话、新建会话（防会话固定）→ 302 redirect_uri?code=...&state=...
```

### 14.2 落地在代码里的防线（逐条对应 §7）

| 风险 | 做法 |
|---|---|
| 开放重定向 | `client_id` / `redirect_uri` 校验失败时**只渲染错误页，绝不 302**；`redirect_uri` 对注册值**精确匹配**（前缀、后缀、通配都不认） |
| PKCE 降级 | 公开客户端**必须**带 `code_challenge`；`code_challenge_method` 只接受 `S256`（`plain` 直接拒） |
| CSRF | 双重提交 cookie：token 同时下发到 cookie 与表单隐藏字段，POST 时常量时间比对；cookie `SameSite=Lax` |
| 会话固定 | 登录成功一律**新建**会话并撤销请求里带的旧会话，绝不复用 cookie |
| 会话 cookie 泄漏 | 值只用 `secrets.token_urlsafe(32)`，库里只存 SHA-256；`HttpOnly` + `SameSite=Lax` + `Path=<对外前缀>` + `Secure`(https) |
| 授权码泄漏 | 只存 SHA-256、明文只回给客户端一次、TTL 60 秒、一次性（兑换在 §4 实现） |
| 缓存泄漏 | 登录页 / 错误页 / 重定向一律 `Cache-Control: no-store` + `Referrer-Policy: no-referrer` |
| 账号枚举 | 登录页失败文案与 JSON 端点一致、逐字相同；失败仍走同一套 IP+用户名限流 |
| 用户被禁用 | 会话对应的用户若 `disabled`，该会话**立即被视为无效**，回到登录页 |

### 14.3 登录页

`app/templates/login.html`：服务端渲染、**零第三方 JS**、无外部资源请求；Light/Dark 跟随系统。
CSRF token 与全部授权参数放在隐藏字段里，但 POST 时**全部重新校验**（不信任隐藏字段）。

### 14.4 网关要求

`/auth/authorize` 必须**保持原路径**转发（服务内是 `/authorize`），
即 `docs/sso-oidc.md` §8 的 ② 块。当前 Caddyfile 里 ② 只有 `/auth/authorize` 与 `/auth/token`，
后续 `/device*`、`/logout` 落地时逐个加入 —— **不要提前加**，否则标准客户端会拿到 404。

> ⚠️ ② 块里多个路径**必须写成具名 matcher** `@standard_oidc path /auth/authorize /auth/token`。
> `handle /auth/authorize /auth/token { }` 这种简写只接受一个 matcher，
> Caddy 会报 `wrong argument count or unexpected line ending after '/auth/token'` 并拒绝启动
> （已实测；幸好先 `validate` 才没把网关打挂）。

---

## 15. 令牌端点 `/token`（`docs/sso-oidc.md` §2.4）

`Content-Type: application/x-www-form-urlencoded`；**所有响应**（含错误）都带
`Cache-Control: no-store`。

### 15.1 客户端认证（`app/client_auth.py`）

| 方式 | 用法 | 适用 |
|---|---|---|
| `client_secret_basic` | `Authorization: Basic base64(urlencode(id):urlencode(secret))` | 保密客户端 |
| `client_secret_post` | 表单字段 `client_id` + `client_secret` | 保密客户端 |
| `none` | 只给 `client_id` | 公开客户端（安全性由 PKCE 保证） |

- 认证方式**必须与客户端注册值一致**，否则 `invalid_client`。
- 同一请求**不得混用**多种方式（RFC 6749 §2.3.1）→ `invalid_request`。
- 用 `Authorization` 头认证失败时按 RFC 6749 §5.2 返回 **401 + `WWW-Authenticate`**；
  其余情况返回 **400**（这是对文档"统一 400"的一处刻意偏离，为了标准客户端能正确识别认证失败）。
- 先判"服务端是否支持该 `grant_type`"（→ `unsupported_grant_type`），再判"该客户端是否被允许"（→ `unauthorized_client`）。

### 15.2 `grant_type=authorization_code` 的逐项校验

| # | 校验 | 失败 |
|---|---|---|
| 1 | 码存在 | `invalid_grant` |
| 2 | **码未被用过**；若已用过 → 撤销该码派生的整条 refresh 链 | `invalid_grant` |
| 3 | 未过期（默认 60 秒） | `invalid_grant` |
| 4 | 码归属的 `client_id` == 请求方 | `invalid_grant` |
| 5 | `redirect_uri` 与授权时**逐字相同** | `invalid_grant` |
| 6 | PKCE：`BASE64URL(SHA256(code_verifier)) == code_challenge` | `invalid_grant` |
| 7 | 用户仍存在且 `active` | `invalid_grant` |

两个**刻意**的行为，写清楚免得踩：

1. **码在开始兑换时就标记已用并落库**，即使后续校验失败也不回滚 ——
   否则 `code_verifier` 可以被在线暴力试错，PKCE 的保护就白做了。
   代价：客户端把自己的 verifier 写错一次，必须重新走授权。
2. **只有请求了 `offline_access` 才签发 `refresh_token`**（OIDC 惯例）。
   浏览器类客户端（如 `elipese-web`）不请求它，就靠会话 cookie 静默重跑 `/authorize` 续期，
   不必持有长期凭据。需要 refresh 的客户端请在注册 scope 与请求 scope 里都加 `offline_access`。

### 15.3 令牌语义

- `access_token`：RS256 JWT，`aud` **保持** `elicloud-services`（业务服务按它校验），
  另加 `client_id` claim 供审计（§4.1）。**不要**把 `aud` 改成 client_id，否则所有业务服务验签都要改。
- `refresh_token`：`rt_` 前缀不透明串，绑定 `client_id` + `scope` + `session_id`（§4.3），
  轮换与整链撤销逻辑与私有端点共用同一份实现（`app/tokens.py`）。
- `id_token`：`aud` = client_id（见 §16）。
- `device_code` 分支见 §17（`grant_type=urn:ietf:params:oauth:grant-type:device_code`）。

### 15.5 `grant_type=refresh_token`

```text
grant_type=refresh_token
refresh_token=rt_...
client_id=...            # 或 client_secret_basic / client_secret_post
scope=...                # 可选；只能**收窄**，不能扩大
```

返回新的 `access_token` + **轮换后的** `refresh_token` + 新的 `id_token`（若 scope 含 openid）。

| 规则 | 说明 |
|---|---|
| **客户端绑定** | 令牌只能由**签发它的那个 `client_id`** 兑换；换客户端 → `invalid_grant`（§7.5） |
| **私有令牌不通用** | 密码直连（`/v1/login`）签发的令牌没有 `client_id`，在 `/token` 上会被拒 |
| **反向也拦** | 绑定了客户端的令牌不能在私有 `/v1/refresh` 兑换（否则可绕过客户端认证） |
| **防提权** | 带 `scope` 时必须原子令牌 scope，否则 `invalid_scope`；收窄允许，且新令牌只带收窄后的 scope |
| **轮换与重放** | 旧令牌立即失效；重放 → **整条链**撤销（含最新那枚） |
| **`auth_time`** | 取登录会话的 `auth_time`；会话已过期则取该链最早一枚的创建时间；都取不到就**省略**该 claim，绝不拿签发时间冒充 |
| **`nonce`** | 刷新与原始 nonce 无关，重新签发的 `id_token` **不带** nonce |

> ⚠️ 顺带一个坑：**授权码重放会撤销该码派生的整条 refresh 链**（§7.4）。
> 写验收脚本时若先测"授权码重放"再测"刷新"，后者必然失败（报 `refresh_token 已失效`）——
> 看起来像 bug，其实是设计如此。`scripts/e2e_oidc.py` 特意把重放放在**最后**。

### 15.4 线上验收脚本

`scripts/e2e_oidc.py` 用真实 HTTP 走完「登录页 → 授权码 → 换令牌 → 验签 → userinfo → 重放被拒」：

```bash
docker run --rm --network host \
  -e SSO_BASE=https://146.56.237.33/auth -e SSO_USER=<用户名> -e SSO_PASS="$PW" \
  -e SSO_CLIENT_ID=elipese-app -e SSO_REDIRECT_URI='elipese://callback' \
  -e SSO_SCOPE='openid profile offline_access' -e SSO_EXPECT_REFRESH=yes \
  elicloud-sso:1.0.0 python scripts/e2e_oidc.py
```

> 单独提醒：脚本用 PyJWT 验签访问令牌时**必须同时传 `audience`** ——
> 令牌带 `aud` 而不校验它会直接抛 `InvalidAudienceError`（我第一版脚本就踩了这个）。

---

## 16. `id_token` 与 `/userinfo` 的 claim（`docs/sso-oidc.md` §4.2、§2.6）

### 16.1 最容易搞混的一点：两个令牌的 `aud` 不一样

| 令牌 | `aud` | 用途 |
|---|---|---|
| `access_token` | **`elicloud-services`**（业务服务按它校验） | 访问业务 API |
| `id_token` | **`client_id`** | 只证明"这个人是谁"，**绝不可用于访问 API** |

两条防线保证不会混用：业务服务按 `aud` 拒绝 id_token；
`/userinfo` 也会因为 `aud` 不匹配返回 **401**（有测试 `test_id_token_cannot_be_used_as_access_token` 锁住）。

### 16.2 `id_token` 的 claim

```text
iss / sub / aud=client_id / iat / exp(=iat+ID_TOKEN_TTL，默认 600s) / auth_time
+ nonce（仅当授权请求带了 nonce）
+ 按 scope 附加：profile → preferred_username；email → email + email_verified
```

- `auth_time` 是用户**实际认证时间**（取自登录会话），不是签发时间。
- 签名用同一把 RS256 密钥，`kid` 与 JWKS 一致。
- `at_hash` / `c_hash` 按 §13 一期**不实现**。

### 16.3 claim 的单一来源

`app/claims.py::user_claims(user, scopes)` 是 **id_token 与 /userinfo 共用**的映射函数。
分开写两份迟早会漂移成「id_token 里有 email、userinfo 里没有」这类难查的不一致。

### 16.4 `/userinfo` 的过滤规则（B2）

| scope | 返回 |
|---|---|
| （总是） | `sub` |
| `profile` | `preferred_username` |
| `email` | `email` + `email_verified` |

- **只给标准名 `preferred_username`，不再返回非标准的 `username`**（B2 决策）。
- 响应里还保留一个 `scope` 字段：它不是"用户 claim"，不受上面的过滤规则约束，保留是为了方便调用方自检。
- **`email_verified` 恒为 `false`**：本平台没有邮箱验证流程，如实标注而不是假装已验证。
  将来若要做"邮箱可信"，得先引入验证流程再把这里改成真实值。
- 账号没填邮箱时，即使 scope 里有 `email` 也**不返回** `email`/`email_verified`（不返回空串）。
- `GET` 与 `POST` 都支持（OIDC 要求），两者返回体完全一致。

### 16.5 发现文档只声明已实现的能力

`grant_types_supported` 当前为 `authorization_code` + `refresh_token` + `urn:ietf:params:oauth:grant-type:device_code`，
与 `app/routers/wellknown.py::IMPLEMENTED_GRANT_TYPES` 严格一致（有测试比对）。
`end_session_endpoint` 在第 8 步实现前**不会**出现在发现文档里。

`tests/test_discovery.py` 会**遍历发现文档里声明的每一个端点**，按网关规则还原成服务内路径并断言"不是 404"
—— 这条测试专门防止再次出现"声明了却没实现"（本次扩展的起因之一）。

---

## 17. 设备授权流程（RFC 8628，`docs/sso-oidc.md` §2.5、§3.2）

给**没有浏览器**的客户端用（CLI、桌面工具）：设备拿 `device_code` 轮询，人在浏览器里输入短码完成授权。

### 17.1 三个端点

```text
POST /auth/device_authorization   设备 → 拿 device_code + user_code(人读) + verification_uri + interval
GET  /auth/device?user_code=…      人 → 登录 / 输入短码 / 看到确认页
POST /auth/device                  人 → 登录、提交短码、点同意或拒绝
POST /auth/token  (device_code)    设备 → 轮询换令牌
```

```bash
# 设备侧
curl -s -X POST https://146.56.237.33/auth/device_authorization \
  -d 'client_id=elicloud-cli' -d 'scope=openid profile offline_access'
# → {"device_code":"dc_…","user_code":"RZ6P-77GU","verification_uri":"https://…/auth/device",
#    "verification_uri_complete":"https://…/auth/device?user_code=RZ6P-77GU",
#    "expires_in":600,"interval":5}
# 然后提示用户打开 verification_uri_complete，并按 interval 轮询 /auth/token
```

### 17.2 `/token` 的 `device_code` 分支返回码

| 情形 | 错误码 |
|---|---|
| 用户还没确认 | `authorization_pending` |
| 上次轮询太快 | `slow_down`（并把 interval +5，**上限 60 秒**） |
| 用户拒绝 | `access_denied` |
| 设备码过期 | `expired_token` |
| 已被兑换过 | `invalid_grant` |
| 客户端不匹配 / 未知码 | `invalid_grant` |

**终态错误优先于限流**：已过期 / 已拒绝 / 已兑换的码会**立刻**给出确定答复，
而不是被"轮询过快"掩盖成 `slow_down`（否则客户端会一直重试一个已经结束的流程）。

> ⚠️ **interval 必须有上限**（实现时踩到的真问题）：按 §2.4c 每次过快就给 interval +5，
> 若没有上限，一个持续过快轮询的客户端能把 interval 顶到 **110 秒以上**并继续增长 ——
> 它永远追不上，等于自己把自己锁死。现在封顶 **60 秒**，并有测试
> `test_slow_down_interval_is_capped` 锁住这个行为。
>
> 客户端侧的正确做法：收到 `slow_down` 后**按服务端新给出的 interval 等待**再重试；
> 固定间隔重试只会让情况越来越糟（`scripts/e2e_device.py` 就是这么做的）。

### 17.3 安全设计

| 项 | 做法 |
|---|---|
| 短码字符集 | 去掉易混淆的 `0/O/1/I/L`，形如 `XXXX-XXXX`（31 字符 × 8 位） |
| 短码 TTL | 默认 **600 秒**，过期即失效 |
| **防枚举** | 「短码不存在」与「短码已过期」给出**逐字相同**的提示（§7.14，有测试断言两者文本一致） |
| 发起限流 | `/device_authorization` 按 IP 限制（默认 30 次 / 5 分钟），防止刷爆短码空间 |
| 客户端绑定 | `device_code` 绑定发起它的 `client_id`，别的客户端不能代领 |
| **一次性** | 兑换成功即置 `used`（文档外的必要扩展），同一次批准不会被反复换成令牌 |
| CSRF | 设备页的登录 / 短码 / 确认表单都做 CSRF 双重提交校验 |
| 会话固定 | 设备页登录成功同样**新建**会话，不复用旧 cookie |

### 17.4 与文档的两处偏离（都是必要扩展）

1. `DEVICE_STATUS_USED`：文档 §6.1 的状态只有 `pending/approved/denied/expired`，没有"已兑换"。
   没有它，同一次批准可以被反复兑换出多组令牌 —— 必须补。
2. `/device` 的登录步骤复用了 `login.html`（新增 `device_mode` 分支），
   而不是为设备流程再写一个登录页；表单 `action` 指向 `/auth/device`。

### 17.5 线上验收脚本

```bash
docker run --rm --network host \
  -e SSO_BASE=https://146.56.237.33/auth -e SSO_USER=<用户名> -e SSO_PASS="$PW" \
  -e SSO_CLIENT_ID=elicloud-cli -e SSO_SCOPE='openid profile offline_access' \
  elicloud-sso:1.0.0 python scripts/e2e_device.py
```

它同时扮演"设备"与"浏览器"两个角色，走完 23 项检查（含 `authorization_pending`、`slow_down`、
短码字符集、确认页、一次性）。

---

## 18. 标准登出（RP-Initiated Logout，`docs/sso-oidc.md` §2.7）

### 18.1 用法

```text
GET  /auth/logout?post_logout_redirect_uri=<已注册>&id_token_hint=<可选>&state=<可选>
POST /auth/logout   同上，字段可放表单体（表单优先，其次 query）
```

行为：**清会话 cookie → 撤销该会话派生的 refresh 链 → 按注册值决定是否 302 回跳**；
不带 `post_logout_redirect_uri` 时渲染"已登出"页。

### 18.2 两条安全规则

1. **`post_logout_redirect_uri` 必须精确匹配客户端注册值**，否则**不跳转**，只渲染带提示的登出页。
2. **`id_token_hint` 必须验签**（允许已过期）：只校验签名与 `iss`。绝不能拿未经验证的 `aud`
   去决定回跳地址 —— 那等于把开放重定向交到攻击者手里。
   另外也接受直接传 `client_id`（文档外的便利扩展，部分客户端不保留 id_token），同样走精确匹配。

### 18.3 撤销范围

只撤销**该浏览器会话派生的链**（`refresh_tokens.session_id` 精确定位），
同一账号在**其它设备**上的登录不受影响 —— 有测试
`test_logout_does_not_kill_other_sessions_chains` 用两个独立 cookie jar 验证这一点。

### 18.4 ⚠️ A3 决策的后果（你需要知道）

按 `docs/sso-oidc.md` §1.3 的 **A3**，私有 `POST /v1/logout` **已删除**（线上实测返回 404）。
这带来一个**功能缺口**：

> **密码直连（`/v1/login`）签发的 refresh token 没有会话绑定（`session_id` 为空），
> 标准 `/logout` 找不到它，因此这类客户端*无法主动撤销*自己的 refresh token。**

这是 A3 的必然结果，不是 bug。三条出路：

| 方案 | 说明 |
|---|---|
| **改用授权码 + PKCE**（推荐） | App/前端本来就需要它（系统浏览器登录），改完就自然有会话与标准登出 |
| 等 TTL 自然过期 | refresh token 默认 30 天；把 `REFRESH_TOKEN_TTL` 调小可缩短暴露窗口 |
| 加 RFC 7009 撤销端点 | 文档 §13 明确本期不做；将来需要时再加 `/token/revoke` 更标准 |

在此之前，**私有密码直连请只用于开发联调**，不要给长期运行的第一方客户端用。

### 18.5 迁移检查表（给已有调用方）

| 原来 | 现在 |
|---|---|
| `POST /auth/logout` + Bearer + `{refresh_token}` → 204 | 已不存在；改用 `GET /auth/logout?...`（浏览器跳转语义） |
| 依赖"注销后 refresh 立刻失效" | 需先有浏览器会话；否则见 §18.4 |
| discovery 里没有 `end_session_endpoint` | 现在有了，标准客户端会用它 |

`scripts/e2e_smoke.py` 里原来的两条注销检查已按新语义改写为：
「`POST /auth/logout` 无会话时渲染已登出页 → 200」与「私有 `POST /auth/v1/logout` → 404」，
总数仍是 24 项。

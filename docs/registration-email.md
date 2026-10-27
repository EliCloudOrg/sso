# 注册邮箱验证：服务端契约与状态机

> 本文是 `sso` 与 `email` 两个服务之间的注册契约，也是桌面客户端只读的架构说明。
> 实现：`app/registration.py`、`app/routers/registration.py`、`app/email_client.py`。

## 1. 流程

```text
Desktop                       SSO                         email 服务
   │ POST /auth/register        │                             │
   │───────────────────────────>│ 校验/限流                    │
   │                            │ 写 pending_registrations     │
   │                            │ POST /v1/verify ───────────>│
   │                            │<──── 202 {id, expires_at} ──│
   │<── 202 registration_id ────│                             │ 发确认邮件
   │ 轮询 /auth/register/status  │                             │
   │───────────────────────────>│ 可选 GET /v1/verify/{id} ──>│
   │                            │<── 用户点击邮件链接 ────────│
   │                            │<── HMAC 回调 ───────────────│
   │                            │ 创建 users + email_verified_at
   │<── status=verified ────────│                             │
   │ POST /auth/login           │                             │
   │───────────────────────────>│ 签发令牌                    │
```

账号只在邮箱确认成功后创建；email 服务不保存账号，也不提供 `trusted?email=` 全局可信邮箱判断。

## 2. 状态机

```text
pending --approved callback--> verified
pending --denied/timeout-----> expired --resend--> pending
pending --建号冲突/发信失败---> failed  --resend--> pending
pending --用户取消-----------> cancelled
```

- `pending`：等待确认；用户名/邮箱在 pending 表内被占用，TTL 15 分钟。
- `verified`：`users` 行已创建，记录 `user_id`/`verified_at`。
- `expired`：超时或被 email 服务拒绝；保留期内可重发。
- `failed`：邮件发送失败或最终建号冲突；可重发或取消。
- `cancelled`：旧邮件链接仍可能被点，但回调被忽略。

## 3. 公开 API

所有响应 `Cache-Control: no-store`。

### `POST /v1/register`

```json
{"username":"alice","password":"S3cret!pass1","email":"alice@example.com"}
```

`202`：

```json
{"registration_id":"reg_...","status":"pending","email_masked":"a***@example.com",
 "expires_at":"2026-10-25T00:15:00Z","resend_after":60}
```

- 同用户名/邮箱且密码匹配 → 恢复同一 pending（应用重启后重新提交同一表单即可）。
- 用户名/邮箱已被真实账号占用 → `409 user_exists/email_exists`。
- 密码不匹配的 pending → `409 registration_pending`。
- email 服务不可用 → `503 email_service_unavailable`；SMTP 失败 → `502 email_delivery_failed`。

### `POST /v1/register/status`

```json
{"registration_id":"reg_..."}
```

`200`：`status` 为 `pending/verified/expired/failed`；`verified` 时带 `user`；
`expired/failed` 时带 `reason`。不存在/已取消 → `404 registration_not_found`。

### `POST /v1/register/resend`

同一请求体；成功 `202` 返回新的 pending 结构。冷却内 `429 + Retry-After`；
已验证 `409 already_verified`；保留期外/已取消 `410 registration_expired`。

### `POST /v1/register/cancel`

成功 `204`；不存在也返回 `204`（幂等）；已验证 `409 already_verified`。

## 4. 内部回调

`POST /internal/email/verification`（不在 `/auth` 路由下，Caddy 不暴露）。

校验：

- `X-EliCloud-Event: email.verification`
- `X-EliCloud-Timestamp` 与当前时间相差 ≤ 300 秒
- `X-EliCloud-Signature: sha256=HMAC_SHA256(secret, timestamp + "." + raw_body)`
- `metadata.registration_id`、`email`、`purpose=register`、`source=sso`

`status=approved` → 创建用户（`email_verified_at=now`），重复回调幂等；
`status=denied` → `expired`。未知 registration 返回 404，签名错 401。

## 5. 为什么不用你提出的两种替代方案

### `trusted?email=` 全局可信邮箱列表：不可用

邮箱地址是公开标识，不是秘密。`trusted` 只能证明“这个邮箱曾经被验证过”，
不能证明当前注册者控制它。攻击者知道 `alice@example.com` 后，只要该邮箱曾在
trusted 列表里，就能用 Alice 的邮箱注册并自设密码。长期列表还会引入 PII 留存、
邮箱回收后的信任残留、`trusted?email=` 枚举 oracle 与检查/建号之间的 TOCTOU。

### email 服务签发 token、SSO 用 token 换邮箱：方向对，但本次不采用

token 必须一次性、短 TTL、绑定 `email+purpose`、只存哈希、原子消费；不能放进
`email` 字段（会破坏邮箱校验），也不能进 query/log。真正的难点是 token 如何从
浏览器到桌面：复制粘贴体验差、深链要协议注册与防劫持、短码本质是 OTP。
若 callback 直接把 token 给 SSO，桌面不需要 token，SSO 又需要一个注册意图来关联，
已经等价于两步式 intent。

### 如果以后产品明确要求“先验证邮箱，再填用户名/密码”

用 SSO 持有的 `registration_intent`：先 `start` 验证邮箱，callback 标记 intent，
再 `complete` 提交用户名/密码建号并原子消费 intent。不要用 trusted 列表，
也不要让用户复制 token。

## 6. 配置与部署

SSO 环境变量见 `README.md` §3；两个 secret 必须分别与 email 的
`EMAIL_INTERNAL_TOKEN` / `CALLBACK_SIGNING_SECRET` 一致。

email 生产额外要求：

- `CALLBACK_ALLOWED_HOSTS` 含 `sso`
- `MAX_ACTIVE_PER_EMAIL=10`（避免 60 秒重发冷却与默认 3 个 pending 冲突）
- `SMTP_TIMEOUT=10`（SSO 的 `EMAIL_HTTP_TIMEOUT_SECONDS=20` 必须大于它）

## 7. 测试

- `tests/test_registration.py`：注册、状态、重发、取消、回调、签名、幂等、对账。
- `tests/test_auth_flow.py`：注册后登录/刷新/userinfo 全链路。
- `tests/test_db_migration.py`：`users.email_verified_at` 补列。

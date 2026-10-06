# SSO 部署说明

本仓库使用「GitHub Actions 触发 + 服务器自管」的自托管部署框架。

框架只负责**触发和调用**，不关心项目怎么构建、怎么运行；一切具体部署逻辑都在服务器的
`/srv/sso/deploy.sh` 里。

## 本项目实际信息

| 项 | 值 |
|---|---|
| 技术栈 | Python 3.12（FastAPI + Uvicorn + SQLAlchemy + PyJWT，SQLite 起步） |
| 应用名 `<app>` | `sso` → 远程目录 **`/srv/sso`** |
| 仓库 | `EliCloudOrg/sso`（public；免费版 private 仓库配不了分支保护） |
| 部署目标 | `146.56.237.33`（Ubuntu），SSH 用户 `deploy`，端口 `22` |
| CI 命令 | `pip install -r requirements-dev.txt` → `pytest -q` → `docker build -t sso:ci .` |
| 镜像 | `ghcr.io/elicloudorg/sso:prod` 与 `:sha-<short>`（`DEPLOY_MODE=image`） |
| 部署入口 | `/srv/sso/deploy.sh`（`deploy:deploy` 0750，每次由 Actions 上传覆盖） |
| Docker 可见的项目目录 | `/home/deploy/elicloud-sso`（compose 项目名 `sso`，由 `deploy.sh` 生成编排） |
| 数据目录 | `/home/docker-admin/elicloud/sso/data`（`jwt_private.pem` + `sso.db`，**保持原位、不随部署移动**） |
| 网关网络 | `dsh-nas_dsh-net`（external，dsh-caddy 在其中；容器内端口 8000，仅回环发布） |
| 运行时变量 | `/srv/sso/app.env`（0600 `deploy:deploy`） |
| 密钥 | 仓库 Actions Secret `SSH_KEY`（部署私钥）；公钥在 `/home/deploy/.ssh/authorized_keys` |

## ⚠️ 本机环境的三条硬约束（决定了 `deploy.sh` 为什么长这样）

1. **Docker 是 snap 安装的**（`/snap/bin/docker`），snap 沙箱**看不到 `/srv`**。
   任何把 `/srv` 路径交给 docker 的写法都会失败：
   `-v /srv/...`、`--env-file /srv/...`、`docker build /srv/...`。
   → 所以 `deploy.sh` 自己（bash，不受 snap 限制）在 `/srv/sso/app.env` 读变量，
   写到 `/home/deploy/elicloud-sso/.env`，交给 docker 的**只有 `/home` 下的路径**。
2. **数据（RSA 私钥 + SQLite）留在 `/home/docker-admin/elicloud/sso/data`**，不迁移。
   迁移数据目录会让 issuer 之外的运维面（权限、uid 1002:1003、Caddy 路由）一起变动，
   收益为零、风险不为零。`deploy.sh` 只把它 bind mount 进容器。
3. **`/home/docker-admin` 对 `deploy` 用户不可遍历**（home 目录权限如此，实测）。
   bind mount 由 root 的 docker daemon 完成，所以容器挂载不受影响；但 `deploy.sh`
   里**不能用 shell 去 `test -d` 数据目录**（首次部署就是这样失败过一次：
   `[deploy] 数据目录不存在：/home/docker-admin/elicloud/sso/data`）。
   脚本改用「借容器校验」替代 —— `docker run -v /home/docker-admin/elicloud/sso:/elicloud:ro`
   再在容器里检查 `data/`、`jwt_private.pem`、`sso.db` 是否都在。
   这个校验不能省：docker 会为「不存在的 bind 源」**静默创建空目录**，
   私钥一旦缺失，应用会重新生成 RSA 密钥，所有已签发令牌立即失效。

## 部署架构

```
      feature/* ──PR──▶ main ──PR──▶ prod
                         │            │
                    push │            │ push / workflow_dispatch(ref)
                         ▼            ▼
              ┌──────────────────┐  ┌───────────────────────────────────────┐
              │ CI  ci.yml       │  │ Deploy  deploy-prod.yml               │
              │  检出            │  │  ① 构建镜像 → ghcr.io/elicloudorg/sso  │
              │  安装依赖        │  │     仅当 vars.DEPLOY_MODE == image    │
              │  pytest -q       │  │  ② scp deploy/deploy.sh → /srv/sso    │
              │  docker build    │  │  ③ ssh 执行 /srv/sso/deploy.sh REF    │
              └──────────────────┘  │  environment: production（人工审批）  │
                                    └──────────────────┬────────────────────┘
                                                       │ SSH（deploy 用户 + 私钥）
                                                       ▼
                                    ┌───────────────────────────────────────┐
                                    │ 服务器  /srv/sso/                     │
                                    │   deploy.sh   ← 随仓库版本管理         │
                                    │   app.env     ← 运行时环境变量（600）  │
                                    │  ↓ bash 读 /srv、写 /home              │
                                    │ /home/deploy/elicloud-sso/            │
                                    │   .env + docker-compose.yml（生成物）  │
                                    │  ↓ docker compose up -d               │
                                    │ 容器 sso ← ghcr.io/elicloudorg/sso    │
                                    │   /data ← /home/docker-admin/elicloud/ │
                                    │           sso/data（私钥 + SQLite）    │
                                    │  ↓ 只加入 dsh-nas_dsh-net              │
                                    │ dsh-caddy: /auth/* → sso:8000         │
                                    └───────────────────────────────────────┘
```

## 分支模型

| 分支 | 用途 | 合并规则 |
|---|---|---|
| `main` | 集成分支，日常 PR 合入，跑 CI | 需要 PR + CI 通过 |
| `prod` | 发布分支，受保护 | 只允许从 `main` 发 PR 合并；合并即触发部署 |
| `feature/*` | 功能分支 | 从 `main` 拉出，PR 回 `main` |

## 首次部署

1. **服务器初始化**（root；本机用有 sudo 的 `ubuntu` 账号）
   ```bash
   scp scripts/bootstrap-server.sh ubuntu@146.56.237.33:/tmp/
   ssh ubuntu@146.56.237.33 'sudo bash /tmp/bootstrap-server.sh sso'
   ```
   脚本创建 `deploy` 用户（本机已存在）、`/srv/sso`（deploy:deploy 750）、
   空的 `/srv/sso/app.env`，并把 `deploy` 加入 docker 组（本机已加入）。

2. **配置 SSH 免密**：生成部署专用密钥对，公钥写入 `/home/deploy/.ssh/authorized_keys`，
   私钥内容写入 GitHub Secrets `SSH_KEY`。

3. **填写 GitHub 配置**：见下面「GitHub 配置清单（本仓库实际值）」。

4. **填充运行时变量**：编辑 `/srv/sso/app.env`（值见「配置与密钥放置表」）。
   本仓库初始化时已从旧的 `/home/docker-admin/elicloud/sso/.env` 原样迁入，
   内容不变。

5. **首次发布**：GitHub → Actions → **Deploy to production** → *Run workflow*，
   `ref` 填 `prod`。人工审批通过后，Actions 会构建并推送镜像，把 `deploy.sh` 上传到
   `/srv/sso/deploy.sh` 并执行。

> **一次性中断**：首次部署时 `deploy.sh` 需要把旧 compose 项目
> （`/home/docker-admin/elicloud/sso`）管理的同名容器 `sso` 移除，再由本项目重建，
> SSO 中断约 5–15 秒。`/data` 是 bind mount，不受影响 → **issuer 不变、已签发令牌仍有效**。
> 之后每次部署由 `docker compose up -d` 原地重建，不再有这步迁移。

## GitHub 配置清单（本仓库实际值）

### Secrets（Settings → Secrets and variables → Actions → Secrets）

| Secret | 值 |
|---|---|
| `SSH_HOST` | `146.56.237.33` |
| `SSH_USER` | `deploy` |
| `SSH_PORT` | `22` |
| `SSH_KEY` | 部署私钥全文（ed25519；公钥在服务器 `/home/deploy/.ssh/authorized_keys`） |
| `GHCR_TOKEN` | 不需要（同仓库推 `ghcr.io` 用内置 `GITHUB_TOKEN`） |

```bash
gh secret set SSH_HOST --body '146.56.237.33'
gh secret set SSH_USER --body 'deploy'
gh secret set SSH_PORT --body '22'
gh secret set SSH_KEY < ./sso_deploy_ed25519     # 部署私钥文件
```

### Variables（同页面 Variables 标签，**必须是仓库级**）

| Variable | 值 | 说明 |
|---|---|---|
| `DEPLOY_MODE` | `image` | `image` → 阶段一构建并推镜像；其它值/留空 → 阶段一跳过，只跑阶段二 |

```bash
gh variable set DEPLOY_MODE --body 'image'
```

> `image` job 没有 `environment:`，读不到 Environment 级变量，所以 `DEPLOY_MODE` 必须配成仓库级。

### Environment：`production`

- **Required reviewers**：部署前必须人工 Approve
- **Deployment branches**：仅 `prod`
- ⚠️ 一旦限制了部署分支，用 `workflow_dispatch` 回滚时**必须在 UI 里把分支选成 `prod`**；
  用默认分支（main）会被策略直接拒绝，job 在 2 秒内失败且没有任何步骤日志。
- ⚠️ **GitHub 不允许自己批准自己触发的部署**。本仓库目前是单账号（`Elipese568`），
  所以 Environment 先**不挂 Required reviewers**（挂了会把自己锁死：push 触发的部署
  无人能批）。加协作者或机器人账号后，把它的账号加进 Required reviewers 即可启用人工审批。

### 分支保护

| 分支 | 规则 |
|---|---|
| `main` | 需要 PR；必过检查 `Test and build`（勾选 Require branches to be up to date）；禁 force push / 禁删除 |
| `prod` | 需要 PR；必过检查 `Test and build` + `Guard prod source`；禁 force push / 禁删除 |

> 单账号**无法给自己的 PR 审批**，所以 `required_approving_review_count` 设为 0
> （仍是「必须走 PR」，且 prod 只能由 `main` 合入，由 `Guard prod source` 强制）。
> 加了协作者之后建议调到 1（main）/ 2（prod）。

> 注：`SSH_USER=deploy` 时 Actions 会把日志里的 "deploy" 打码成 `***`
> （`Trigger remote ***`、`/srv/sso` 显示成 `/srv/***`），属正常行为。

### 镜像包可见性

`ghcr.io/elicloudorg/sso` 若是 **private** 包，服务器上的 `docker pull` 会 401。
二选一：

- 把包设为 public：GitHub → 组织 → Packages → `sso` → Package settings → Change visibility；
- 或在 `/srv/sso/app.env` 里填 `SSO_GHCR_USER` / `SSO_GHCR_TOKEN`（PAT，需 `read:packages`），
  `deploy.sh` 会先 `docker login ghcr.io` 再拉取。

## 配置与密钥放置表

| 变量 / 配置 | 位置 | 用途 |
|---|---|---|
| `SSH_HOST` / `SSH_USER` / `SSH_PORT` | GitHub Secrets | Actions 连哪台机器、以谁登录 |
| `SSH_KEY` | GitHub Secrets | 部署私钥（Actions 侧唯一凭据） |
| 对应公钥 | 服务器 `/home/deploy/.ssh/authorized_keys`（600） | 校验上面的私钥 |
| `GITHUB_TOKEN` | Actions 内置，无需配置 | 同仓库推 `ghcr.io` 镜像（靠 `packages: write`） |
| `DEPLOY_MODE` | GitHub Variables（仓库级） | `image` → 阶段一构建推镜像 |
| `PUBLIC_BASE_URL` | `/srv/sso/app.env` | **issuer / jwks_uri 的唯一来源**；当前为 `https://146.56.237.33/auth` |
| `CORS_ORIGINS` | `/srv/sso/app.env` | 允许的浏览器来源（逗号分隔） |
| `ALLOW_REGISTRATION` | `/srv/sso/app.env` | 是否开放自助注册（当前 `false`） |
| `JWT_KID` | `/srv/sso/app.env` | 签名密钥标识，轮换密钥时改这里 |
| `ADMIN_TOKEN` | `/srv/sso/app.env` | `/v1/clients` 管理接口的 Bearer 令牌；留空 = 该组接口关闭 |
| `SSO_IMAGE_REPO` / `SSO_IMAGE_TAG` | `/srv/sso/app.env`（可选） | 覆盖镜像仓库/tag（默认 `ghcr.io/elicloudorg/sso:prod`） |
| `SSO_GATEWAY_NETWORK` | `/srv/sso/app.env`（可选） | 覆盖网关网络（默认 `dsh-nas_dsh-net`） |
| `SSO_GHCR_USER` / `SSO_GHCR_TOKEN` | `/srv/sso/app.env`（可选） | private 镜像包的拉取凭据 |
| RSA 私钥 `jwt_private.pem` | 服务器 `/home/docker-admin/elicloud/sso/data`（容器内 `/data`） | **绝不进仓库、绝不进镜像** |
| SQLite `sso.db` | 同上 | 用户 / refresh token / 客户端注册 |
| 部署 ref（`prod` / tag / commit SHA） | 由 Actions 作为参数传给 `deploy.sh` | 决定这次部署哪个版本 |
| 人工运维私钥 | 本机 `~/.ssh/`（Windows：`C:\Users\<you>\.ssh\...`） | 仅供人登录服务器，与 Actions 无关 |

规则：**部署环节的凭据只走 GitHub Secrets；应用运行时的变量只在服务器 `app.env`。**
两边都不要写进仓库，也不要在 workflow 里 `echo` 出来。

## 日常发布流程

```bash
git switch main && git pull
git switch -c feature/xxx
# ... 开发 ...
git push -u origin feature/xxx        # 开 PR → main，等 CI 通过并合并
```
然后发 PR：`main` → `prod`。合并到 `prod` 即自动走 `deploy-prod.yml`：
先构建推镜像，再上传并执行 `/srv/sso/deploy.sh prod`。

## 回滚流程

两种方式，都只是把同一个 `deploy.sh` 用另一个 ref 再跑一次：

1. **GitHub Actions 回滚（推荐）**
   Actions → *Deploy to production* → *Run workflow* →
   `ref` 填上一个可用版本：`prod` 之前的 tag（如 `v1.3.0`）、commit SHA，或分支名。
   - 阶段一会**按 `ref` 输入检出并构建那个版本**（`deploy-prod.yml` 里的
     `ref: ${{ github.event.inputs.ref || github.ref }}`），并把 `:prod` 指回它，
     `sha-<short>` 也取自该 commit。因此 `deploy.sh` 固定拉 `:prod` 就是正确的回滚语义。
   - ⚠️ 若 Environment 限制了 Deployment branches（`prod`），UI 里的**分支必须选 `prod`**，
     否则 job 会被策略直接拒绝（2 秒失败、无步骤日志）。

2. **服务器上手工回滚**
   ```bash
   # 方式 A：把 :prod 已经指向的版本重新部署一遍（等价于重放上一次部署）
   sudo -u deploy /srv/sso/deploy.sh prod

   # 方式 B（真正的应急回滚）：直接指定不可变的 sha tag
   sudo -u deploy env SSO_IMAGE_TAG=sha-1a2b3c4 /srv/sso/deploy.sh prod
   ```
   方式 A 不构建镜像（没有 Actions 的阶段一），所以它只在 `:prod` **已经指向目标版本**
   时才有意义；方式 B 依赖那个 `sha-<short>` tag 还在 ghcr 上，`deploy.sh` 会优先读
   进程环境变量 `SSO_IMAGE_TAG`，其次 `/srv/sso/app.env`，最后回落到 `prod`。

   适合 Actions 不可用时应急；注意这是绕过审批的路径，操作后请补记录。

镜像 tag 保留策略：每次部署推两个 tag —— `prod`（移动）与 `sha-<short>`（不可变）。
`sha-<short>` 是回滚锚点，建议保留最近 ≥10 个；`prod` 永远指向当前线上版本。

## 常见问题排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| Actions 里 scp 一步失败 | `SSH_HOST`/`SSH_USER`/`SSH_PORT` 写错；私钥与服务器公钥不匹配；`/srv/sso` 不存在或不可写 | 用 `ssh -i sso_deploy_ed25519 deploy@146.56.237.33` 复现；确认目录 `deploy:deploy 750` |
| `deploy.sh: Permission denied` | 服务器上文件没有可执行位 | workflow 已 `chmod +x`；手工上传时记得 `chmod +x` |
| `deploy.sh` 报 `bad interpreter: ...^M` | 上传/提交时带了 CRLF 换行 | `.gitattributes` 里已有 `*.sh text eol=lf`，重新提交 |
| `docker pull` 报 `unauthorized` | `ghcr.io/elicloudorg/sso` 是 private 包 | 设为 public，或在 `app.env` 填 `SSO_GHCR_USER`/`SSO_GHCR_TOKEN` |
| 阶段一镜像构建报 `HTTP error 403 ... pypi.tuna.tsinghua.edu.cn` | 构建发生在 GitHub runner（境外出口 IP），清华源会间歇性 403 | Dockerfile 的 `PIP_INDEX_URL` 默认已是官方 PyPI；国内本地构建请用 `--build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple` |
| `docker: permission denied ... /var/run/docker.sock` | `deploy` 不在 docker 组，或改组后没重新登录 | `id deploy` 确认；`usermod -aG docker deploy` 后重新登录 |
| `deploy.sh` 报找不到 `/srv/sso/app.env` | bootstrap 没跑或文件被删 | 重跑 `scripts/bootstrap-server.sh sso` 并填写变量 |
| `deploy.sh` 报「数据目录不存在」 | 旧版脚本用 `test -d` 检查数据目录，而 `deploy` 用户无权遍历 `/home/docker-admin` | 现版本已改为「借容器校验」；若仍报错，检查 `/home/docker-admin/elicloud/sso/data` 是否真的还在 |
| `deploy.sh` 报「缺少 jwt_private.pem」 | 数据目录被移动/清空 | 立刻从备份恢复 `jwt_private.pem`；**在没有私钥的情况下启动应用会让它重新生成密钥，所有已签发令牌立即失效** |
| 容器起不来 / unhealthy | 变量缺失（`PUBLIC_BASE_URL`）、私钥路径、端口被占 | `deploy.sh` 失败时会打印 `docker logs --tail 50 sso`；也可手工 `docker logs sso` |
| 部署成功但 `/auth/*` 仍 404 | 容器没加入 `dsh-nas_dsh-net`，或 dsh-caddy 的 Caddyfile 路由被改 | `docker inspect sso --format '{{json .NetworkSettings.Networks}}'`；检查 dsh-nas 的 Caddyfile |
| Actions 拿不到运行时变量 | 运行时变量属于服务器 `app.env`，不在 Actions 里 | 在服务器上编辑 `/srv/sso/app.env` |

## 相关文件与配置位置

| 文件 / 配置 | 位置 | 说明 |
|---|---|---|
| CI 工作流 | `.github/workflows/ci.yml` | PR 到 main/prod、push 到 main |
| 部署工作流 | `.github/workflows/deploy-prod.yml` | push 到 prod、workflow_dispatch |
| 部署脚本（版本管理） | `deploy/deploy.sh` | 上传到 `/srv/sso/deploy.sh` 执行；**生产编排也在这里生成** |
| 服务器初始化脚本 | `scripts/bootstrap-server.sh` | 在服务器上以 root 跑一次 |
| 部署密钥与服务器信息 | GitHub Secrets | `SSH_HOST`/`SSH_USER`/`SSH_KEY`/`SSH_PORT` |
| 部署模式开关 | GitHub Variables | `DEPLOY_MODE=image` 才构建推镜像 |
| 运行时环境变量 | 服务器 `/srv/sso/app.env` | 600，`deploy:deploy`，不进仓库 |
| 本地/手工编排 | 仓库根 `docker-compose.yml` | `build: .` 的本地版本，**不用于生产**；生产编排由 `deploy.sh` 生成 |

> `docker-compose.yml` 与 `deploy/deploy.sh` 里生成的编排是**两份、用途不同**：
> 前者以 `build: .` 在本地构建镜像，供开发与手工排障；后者是线上实际执行的那份
> （拉 `ghcr.io` 镜像、数据指向 `/home/docker-admin/elicloud/sso/data`）。
> 改环境变量优先改 `/srv/sso/app.env`，不要两边都改一遍。

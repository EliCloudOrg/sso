#!/usr/bin/env bash
set -euo pipefail

# 远程部署入口。由 GitHub Actions（.github/workflows/deploy-prod.yml）通过 SSH 调用：
#
#   /srv/sso/deploy.sh [ref]
#
# 约定：
#   - 参数：要部署的 Git ref，默认 prod
#   - 幂等：可重复执行，重复跑同一 ref 不产生破坏性副作用
#   - 失败必须非 0 退出（set -e 已保证，但请勿自己吞掉错误）
#   - 本文件由仓库 deploy/deploy.sh 同步而来，不要在服务器上直接改；
#     改动请提交到仓库，再由 deploy-prod.yml 上传
#   - 运行时环境变量放在 /srv/sso/app.env，不要写进本文件
#
# ===== 本项目自定义部署逻辑 =====
#
# 形态：DEPLOY_MODE=image —— 阶段一在 Actions 里用仓库 Dockerfile 构建镜像并推送
#       ghcr.io/elicloudorg/sso:prod（同时打 :sha-<short>），deploy.sh 只负责
#       拉镜像 + 重建容器 + 健康检查。
#
# 为什么长这样（本机环境的两个硬约束）：
#   1. 本机 Docker 是 **snap 装的**，snap 沙箱**看不到 /srv**：任何把 /srv 路径
#      交给 docker 的写法（-v /srv/...、--env-file /srv/...、build context /srv/...）
#      都会失败。所以：本脚本（bash，不受 snap 限制）在 /srv 侧读 app.env，
#      把内容写到 /home 下 docker 可见的项目目录；交给 docker 的只有 /home 路径。
#   2. 数据（RSA 私钥 + SQLite）留在原位 /home/docker-admin/elicloud/sso/data，
#      不随本次部署移动 —— issuer 与已签发令牌因此完全不受影响。
#      注意 /home/docker-admin 对 deploy 用户**不可遍历**（宿主机 home 权限），
#      所以本脚本不能用 shell 去 stat 数据目录；bind mount 由 root 的 docker daemon
#      完成，不受影响 —— 校验改用「借容器看」的方式（见步骤 3b）。
#
# 回滚：Actions → Deploy to production → Run workflow → ref 填旧 ref。
#       阶段一会按该 ref 重新构建并把 :prod 指向它，所以这里固定拉 :prod 即可
#       （见 README-deploy.md「回滚流程」）。
# ============================

REF="${1:-prod}"
APP_DIR="/srv/sso"
APP_ENV="${APP_DIR}/app.env"

PROJECT_NAME="sso"
PROJECT_DIR="/home/deploy/elicloud-sso"           # deploy 可写 + snap docker 可见
DATA_PARENT="/home/docker-admin/elicloud/sso"      # 数据目录的父目录（deploy 不可遍历）
DATA_DIR="${DATA_PARENT}/data"                     # 私钥 + SQLite（容器内 /data）
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
HEALTH_TIMEOUT=180                                # 秒

echo "[deploy] ref=${REF} dir=${APP_DIR}"

# ---------- 0) 前置检查 ----------
command -v docker >/dev/null 2>&1 || { echo "[deploy] 找不到 docker" >&2; exit 1; }
[[ -f "${APP_ENV}" ]] || { echo "[deploy] 缺少运行时变量文件 ${APP_ENV}（格式见 README-deploy.md）" >&2; exit 1; }
# 数据目录**不能**在这里用 test -d 检查：/home/docker-admin 对 deploy 用户不可遍历
# （docker daemon 以 root 运行，bind mount 没问题，但 shell 侧的 stat 会失败）。
# 校验挪到 docker pull 之后、用容器来做 —— 见步骤 3b。

# 从 app.env 安全取值：不做 shell eval，避免值里的特殊字符被当作命令执行
env_get() { sed -n "s/^$1=//p" "${APP_ENV}" | tail -n 1; }

IMAGE_REPO="$(env_get SSO_IMAGE_REPO)";           IMAGE_REPO="${IMAGE_REPO:-ghcr.io/elicloudorg/sso}"
# tag 优先取「进程环境变量」，再取 app.env，最后默认 prod：
# 这样应急回滚可以 `sudo -u deploy env SSO_IMAGE_TAG=sha-1a2b3c4 /srv/sso/deploy.sh prod`
IMAGE_TAG="${SSO_IMAGE_TAG:-$(env_get SSO_IMAGE_TAG)}"; IMAGE_TAG="${IMAGE_TAG:-prod}"
GATEWAY_NETWORK="$(env_get SSO_GATEWAY_NETWORK)"; GATEWAY_NETWORK="${GATEWAY_NETWORK:-dsh-nas_dsh-net}"
GHCR_USER="$(env_get SSO_GHCR_USER)"
GHCR_TOKEN="$(env_get SSO_GHCR_TOKEN)"
IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

docker network inspect "${GATEWAY_NETWORK}" >/dev/null 2>&1 || {
  echo "[deploy] 网关网络不存在：${GATEWAY_NETWORK}（dsh-nas 的 Caddy 依赖它接入 sso）" >&2; exit 1; }

# ---------- 1) 准备 docker 可见的项目目录 ----------
install -d -m 0755 "${PROJECT_DIR}"

# 1a) app.env -> ${PROJECT_DIR}/.env：docker compose 用它做变量插值。
#     bash 读 /srv，写 /home —— 全程没有把 /srv 路径交给 docker。
{
  cat "${APP_ENV}"
  echo ""
  echo "# ---- 以下由 deploy.sh 追加，不在 app.env 里维护 ----"
  echo "SSO_IMAGE=${IMAGE}"
  echo "SSO_DATA_DIR=${DATA_DIR}"
  echo "SSO_GATEWAY_NETWORK=${GATEWAY_NETWORK}"
} > "${PROJECT_DIR}/.env"
chmod 0600 "${PROJECT_DIR}/.env"

# 1b) 生成编排文件（单一真源是本仓库，生成物不要手工改）
cat > "${COMPOSE_FILE}" <<'YAML'
# 本文件由 /srv/sso/deploy.sh 生成，请勿在服务器上直接修改。
# 单一真源：仓库 deploy/deploy.sh（deploy-prod.yml 每次部署都会覆盖它）。
name: sso

services:
  sso:
    image: ${SSO_IMAGE}
    container_name: sso
    restart: unless-stopped
    # 以宿主机 docker-admin(1002:1003) 运行，挂卷目录才可写
    user: "1002:1003"
    volumes:
      - ${SSO_DATA_DIR}:/data
    environment:
      PUBLIC_BASE_URL: "${PUBLIC_BASE_URL:?PUBLIC_BASE_URL 未在 /srv/sso/app.env 中设置}"
      CORS_ORIGINS: "${CORS_ORIGINS:-http://localhost:3000}"
      # issuer / jwks_uri 由 PUBLIC_BASE_URL 派生，不单独配置，避免两者不一致
      DATABASE_URL: "sqlite:////data/sso.db"
      JWT_ALG: "RS256"
      JWT_KID: "${JWT_KID:-2026-01}"
      JWT_PRIVATE_KEY_PATH: "/data/jwt_private.pem"
      JWT_KEYS_DIR: "/data/keys"
      ACCESS_TOKEN_TTL: "3600"
      REFRESH_TOKEN_TTL: "2592000"
      ALLOW_REGISTRATION: "${ALLOW_REGISTRATION:-false}"
      AUDIENCE: "elicloud-services"
      DEFAULT_SCOPE: "openid profile email pdf:read pdf:write"
      # ---- OIDC（docs/sso-oidc.md §9）----
      AUTHORIZATION_CODE_TTL: "60"
      ID_TOKEN_TTL: "600"
      SESSION_TTL: "43200"
      SESSION_COOKIE_NAME: "elicloud_sso_session"
      DEVICE_CODE_TTL: "600"
      DEVICE_POLL_INTERVAL: "5"
      # 客户端管理接口（/v1/clients）的 Bearer 令牌；留空 = 该组接口整体关闭
      ADMIN_TOKEN: "${ADMIN_TOKEN:-}"
      LOGIN_ATTEMPTS_PER_WINDOW: "10"
      LOGIN_WINDOW_SECONDS: "900"
      LOG_LEVEL: "info"
    ports:
      # 仅回环：本机 curl / SSH 隧道调试用，公网不可达
      - "127.0.0.1:8000:8000"
    networks:
      - gateway
    healthcheck:
      test:
        - "CMD"
        - "python"
        - "-c"
        - "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/.well-known/jwks.json', timeout=3).status == 200 else 1)"
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

networks:
  # 复用 dsh-caddy 所在网络（IP 阶段）。域名阶段换成独立网络时只改 app.env 里的
  # SSO_GATEWAY_NETWORK，不动本文件。
  gateway:
    external: true
    name: ${SSO_GATEWAY_NETWORK}
YAML

# ---------- 2) 迁移：清掉「属于另一个 compose 项目」的同名容器 ----------
# compose 不接受同名的外来容器。本项目切换时旧项目名恰好也是 sso，compose 会自行
# 原地重建，这里不会触发；保留它是为了别的项目名/手工创建的容器这种情形。
if docker inspect sso >/dev/null 2>&1; then
  existing_project="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' sso 2>/dev/null || true)"
  if [ "${existing_project}" != "${PROJECT_NAME}" ]; then
    echo "[deploy] 迁移：现有 sso 容器属于旧部署（project='${existing_project:-非 compose}'），先移除"
    docker rm -f sso >/dev/null
  fi
fi

# ---------- 3) 拉取本次要部署的镜像 ----------
# 镜像默认是 private 包时需要凭据：在 app.env 里给 SSO_GHCR_USER / SSO_GHCR_TOKEN
# （token 需 read:packages）。两者留空 = 匿名拉取（包设为 public 时即可）。
if [[ -n "${GHCR_USER}" && -n "${GHCR_TOKEN}" ]]; then
  echo "[deploy] docker login ${IMAGE_REPO%%/*}（用户 ${GHCR_USER}）"
  printf '%s' "${GHCR_TOKEN}" | docker login "${IMAGE_REPO%%/*}" -u "${GHCR_USER}" --password-stdin >/dev/null
fi

echo "[deploy] docker pull ${IMAGE}"
docker pull "${IMAGE}"

# ---------- 3b) 校验数据卷（借容器看，deploy 用户自己无权 stat 该路径） ----------
# 为什么必须校验：docker 会为「不存在的 bind 源」静默创建空目录，
# 而私钥一旦缺失，应用会**重新生成 RSA 密钥** —— 所有已签发令牌立即全部失效。
# 所以宁可在这里失败，也不能让 docker 悄悄建一个空 data 目录。
echo "[deploy] 校验数据目录 ${DATA_DIR}"
docker run --rm --entrypoint sh -v "${DATA_PARENT}:/elicloud:ro" "${IMAGE}" -c '
  set -e
  test -d /elicloud/data || { echo "缺少 /elicloud/data" >&2; exit 1; }
  test -f /elicloud/data/jwt_private.pem || { echo "缺少 jwt_private.pem：绝不能让应用重新生成密钥" >&2; exit 1; }
  test -f /elicloud/data/sso.db || { echo "缺少 sso.db" >&2; exit 1; }
  echo "数据目录 OK（jwt_private.pem + sso.db 都在）"
'

# ---------- 4) 重建容器（幂等：镜像没变则 compose 不做任何事） ----------
docker compose --project-directory "${PROJECT_DIR}" -f "${COMPOSE_FILE}" up -d

# ---------- 5) 等健康检查通过 ----------
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
while :; do
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' sso 2>/dev/null || echo missing)"
  case "${status}" in
    healthy)
      echo "[deploy] 容器健康：${status}"
      break
      ;;
    unhealthy)
      echo "[deploy] 容器健康检查失败，最近日志：" >&2
      docker logs --tail 50 sso >&2 2>&1 || true
      exit 1
      ;;
    missing|exited|dead)
      echo "[deploy] 容器状态异常：${status}，最近日志：" >&2
      docker logs --tail 50 sso >&2 2>&1 || true
      exit 1
      ;;
  esac
  if [ "$(date +%s)" -ge "${deadline}" ]; then
    echo "[deploy] 等待健康检查超时（${HEALTH_TIMEOUT}s），当前状态：${status}" >&2
    docker logs --tail 50 sso >&2 2>&1 || true
    exit 1
  fi
  sleep 5
done

# ---------- 6) 容器外自检：回环端口上的发现文档 ----------
if command -v curl >/dev/null 2>&1; then
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8000/.well-known/openid-configuration || true)"
  echo "[deploy] 自检 GET http://127.0.0.1:8000/.well-known/openid-configuration -> ${code}"
  if [ "${code}" != "200" ]; then
    echo "[deploy] 自检失败：期望 200" >&2
    exit 1
  fi
fi

echo "[deploy] 镜像：${IMAGE}"
echo "[deploy] done"

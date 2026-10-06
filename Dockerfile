# EliCloud SSO 运行时镜像
#
# 设计要点：
#   1. 私钥与 SQLite 都落在 /data（compose 里是挂卷），绝不进镜像层；
#   2. 容器内以 uid 1002:1003（宿主机 docker-admin）运行，挂卷目录才能被写入；
#   3. PIP_INDEX_URL 可覆盖：国内直连 PyPI 很慢，默认走清华镜像。
FROM python:3.12-slim

ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_INDEX_URL=${PIP_INDEX_URL}

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY tests ./tests

# /data 是私钥与数据库的落点；镜像内先建好并交给运行用户
RUN mkdir -p /data && chown -R 1002:1003 /data

USER 1002:1003

EXPOSE 8000

# 注意：这里不加 --proxy-headers/--forwarded-allow-ips，
# 客户端 IP 由 app 自己从 X-Forwarded-For 末尾取值（见 app/deps.py::client_ip），
# 行为显式可控，不依赖 uvicorn 的信任链推断。
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

"""FastAPI 应用装配。

服务内路由**不带 /auth 前缀**（/auth 由网关剥离并按契约重写，见 README 的网关一节）：

    POST /v1/register  POST /v1/login  POST /v1/refresh  POST /v1/logout
    GET  /v1/userinfo  GET  /.well-known/jwks.json  GET /.well-known/openid-configuration
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import Settings, get_settings
from .db import init_db
from .keys import get_keystore
from .routers import auth, clients, oidc, userinfo, wellknown

logger = logging.getLogger("sso")


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.strip().upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    # 启动即校验：issuer / jwks_uri / 数据库 / 密钥是否就绪
    logger.info("sso starting version=%s issuer=%s", __version__, settings.issuer)
    logger.info("sso jwks_uri=%s database=%s", settings.jwks_uri, settings.database_url)
    logger.info(
        "sso allow_registration=%s access_token_ttl=%s refresh_token_ttl=%s cors_origins=%s",
        settings.allow_registration,
        settings.access_token_ttl,
        settings.refresh_token_ttl,
        settings.cors_origin_list,
    )
    if not settings.allow_registration:
        logger.info("sso 自助注册已关闭；建号请用 `python -m app.cli create-user`")
    yield
    logger.info("sso stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    init_db(settings)
    keystore = get_keystore(settings)  # 首次启动时生成并持久化 RSA 私钥
    logger.info("sso signing key ready kid=%s published_kids=%s", keystore.signing_kid, sorted(keystore.public_keys))

    app = FastAPI(
        title="EliCloud SSO",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.keystore = keystore

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # 令牌与密码原文绝不进日志；这里只记路径与耗时
            logger.exception("unhandled error path=%s", request.url.path)
            raise
        elapsed_ms = (time.perf_counter() - started) * 1000
        user_id = getattr(request.state, "user_id", "-")
        # .well-known 会被高频轮询，降到 debug
        log = logger.debug if request.url.path.startswith("/.well-known") else logger.info
        log(
            "%s %s -> %s user=%s %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            user_id,
            elapsed_ms,
        )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            content = detail
        else:
            content = {"error": "http_error", "error_description": str(detail)}
        return JSONResponse(status_code=exc.status_code, content=content, headers=dict(exc.headers or {}))

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {"loc": list(item.get("loc", ())), "msg": item.get("msg"), "type": item.get("type")}
            for item in exc.errors()
        ]
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "请求参数不合法", "details": details},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled exception")
        return JSONResponse(
            status_code=500,
            content={"error": "server_error", "error_description": "服务内部错误"},
        )

    app.include_router(auth.router)
    app.include_router(userinfo.router)
    app.include_router(wellknown.router)
    app.include_router(clients.router)
    app.include_router(oidc.router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "issuer": settings.issuer, "version": __version__}

    return app


app = create_app()

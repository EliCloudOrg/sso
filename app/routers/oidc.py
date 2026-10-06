"""标准 OIDC 端点（docs/sso-oidc.md §2.3）。

服务内路径**不带 /auth**：`/authorize`、`/token`、`/logout`、`/device*` 由网关保持原路径，
只有私有 `/v1/*` 才走重写（见 docs/sso-oidc.md §8）。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from ..authentication import authenticate
from ..authorization import (
    AuthorizeFatalError,
    AuthorizeParams,
    AuthorizeRedirectError,
    build_params,
    consume_authorization_code,
    error_redirect_url,
    issue_authorization_code,
    resolve_client,
    success_redirect_url,
)
from ..client_auth import authenticate_client, ensure_grant_allowed, extract_credentials
from ..config import Settings
from ..constants import (
    GRANT_AUTHORIZATION_CODE,
    GRANT_DEVICE_CODE,
    GRANT_REFRESH_TOKEN,
    SCOPE_OFFLINE_ACCESS,
    SCOPE_OPENID,
    SUPPORTED_GRANT_TYPES,
)
from ..db import get_db
from ..deps import KeyStoreDep, OptionalSession, SettingsDep, client_ip
from ..device import (
    approve_device_code,
    consume_device_code,
    create_device_code,
    deny_device_code,
    describe_scopes,
    find_pending_by_user_code,
)
from ..errors import api_error, limiter
from ..keys import KeyStore
from ..models import OAuthClient, User
from ..oidc import join_scope, split_scope, validate_scope_subset
from ..security import create_access_token, create_id_token, decode_id_token_hint
from ..sessions import (
    clear_session_cookie,
    csrf_cookie_name,
    create_session,
    new_csrf_token,
    revoke_session,
    revoke_session_chains,
    set_csrf_cookie,
    set_session_cookie,
    verify_csrf,
)
from ..tokens import (
    consume_refresh_token,
    issue_refresh_token,
    new_family_id,
    resolve_auth_time,
    revoke_family,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["oidc"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# 登录页上的失败提示：与 JSON 端点一样**不区分失败原因**（防枚举）
GENERIC_LOGIN_ERROR = "用户名或密码错误"


# ------------------------------------------------------------------ 渲染


def render_error_page(
    request: Request,
    *,
    title: str,
    message: str,
    detail: str | None = None,
    hint: str | None = None,
    status_code: int = 400,
) -> HTMLResponse:
    response = templates.TemplateResponse(
        request,
        "error.html",
        {"title": title, "message": message, "detail": detail, "hint": hint},
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _login_page(
    request: Request,
    settings: Settings,
    client: OAuthClient,
    params: AuthorizeParams,
    *,
    error: str | None = None,
    username: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """渲染登录页；CSRF token 同时下发到 cookie 与表单隐藏字段（双重提交）。"""
    existing = request.cookies.get(csrf_cookie_name(settings))
    token = existing or new_csrf_token()

    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "action": settings.external_url("authorize"),
            "csrf_token": token,
            "client_id": client.client_id,
            "client_name": client.name,
            "redirect_uri": params.redirect_uri,
            "response_type": "code",
            "scope": params.scope_text,
            "state": params.state,
            "nonce": params.nonce,
            "code_challenge": params.code_challenge,
            "code_challenge_method": params.code_challenge_method,
            "prompt": params.prompt,
            "error": error,
            "username": username,
        },
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    if existing is None:
        set_csrf_cookie(response, settings, token)
    return response


def _redirect(url: str, *, settings: Settings | None = None, session_cookie: str | None = None) -> RedirectResponse:
    response = RedirectResponse(url, status_code=302)
    # 授权码不要经由 Referer 泄漏
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if settings is not None and session_cookie is not None:
        set_session_cookie(response, settings, session_cookie)
    return response


# -------------------------------------------------------------- 共用流程


def _validate(
    db: DbSession,
    *,
    client_id: str | None,
    redirect_uri: str | None,
    response_type: str | None,
    scope: str | None,
    state: str | None,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
    prompt: str | None,
) -> tuple[OAuthClient, AuthorizeParams]:
    """先验 client/redirect_uri（不可信则不重定向），再验其余参数。"""
    client = resolve_client(db, client_id, redirect_uri)
    params = build_params(
        client,
        redirect_uri=redirect_uri or "",
        response_type=response_type,
        scope=scope,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        prompt=prompt,
    )
    return client, params


def _issue_code_redirect(
    request: Request,
    db: DbSession,
    settings: Settings,
    client: OAuthClient,
    params: AuthorizeParams,
    user: User,
    session_id: str,
    auth_time_iso: str,
    *,
    session_cookie: str | None = None,
) -> RedirectResponse:
    code = issue_authorization_code(
        db,
        client=client,
        user_id=user.id,
        params=params,
        settings=settings,
        session_id=session_id,
        auth_time_iso=auth_time_iso,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    logger.info(
        "authorization code issued client=%s user=%s scope=%s",
        client.client_id,
        user.id,
        params.scope_text,
    )
    return _redirect(
        success_redirect_url(params.redirect_uri, code, params.state),
        settings=settings,
        session_cookie=session_cookie,
    )


# --------------------------------------------------------------- /authorize


@router.get("/authorize", response_class=HTMLResponse, response_model=None)
def authorize_get(
    request: Request,
    settings: SettingsDep,
    session_row: OptionalSession,
    db: DbSession = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    query = request.query_params

    try:
        client, params = _validate(
            db,
            client_id=query.get("client_id"),
            redirect_uri=query.get("redirect_uri"),
            response_type=query.get("response_type"),
            scope=query.get("scope"),
            state=query.get("state"),
            nonce=query.get("nonce"),
            code_challenge=query.get("code_challenge"),
            code_challenge_method=query.get("code_challenge_method"),
            prompt=query.get("prompt"),
        )
    except AuthorizeFatalError as exc:
        # 开放重定向防线：client_id / redirect_uri 不可信 → 只渲染错误页，绝不 302
        logger.warning("authorize fatal error=%s", exc.error)
        return render_error_page(
            request,
            title="无法完成授权",
            message=exc.description,
            detail=exc.error,
            hint="请回到发起登录的应用重新进入；若反复出现，请确认该应用已在本站注册。",
        )
    except AuthorizeRedirectError as exc:
        return _redirect(error_redirect_url(query.get("redirect_uri") or "", exc.error, exc.description, exc.state))

    user = db.get(User, session_row.user_id) if session_row is not None else None
    has_usable_session = session_row is not None and user is not None and user.status == "active"

    if params.prompt == "none" and not has_usable_session:
        return _redirect(error_redirect_url(params.redirect_uri, "login_required", "用户未登录", params.state))

    if has_usable_session and params.prompt != "login":
        # 已有有效会话 → 直接发码，不再弹登录页
        return _issue_code_redirect(
            request, db, settings, client, params, user, session_row.id, session_row.auth_time
        )

    return _login_page(request, settings, client, params)


@router.post("/authorize", response_class=HTMLResponse, response_model=None)
def authorize_post(
    request: Request,
    settings: SettingsDep,
    session_row: OptionalSession,
    db: DbSession = Depends(get_db),
    username: Annotated[str | None, Form()] = None,
    password: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    response_type: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
    state: Annotated[str | None, Form()] = None,
    nonce: Annotated[str | None, Form()] = None,
    code_challenge: Annotated[str | None, Form()] = None,
    code_challenge_method: Annotated[str | None, Form()] = None,
    prompt: Annotated[str | None, Form()] = None,
) -> HTMLResponse | RedirectResponse:
    # 表单字段是**不可信输入**：全部重新校验（隐藏字段可被篡改）
    try:
        client, params = _validate(
            db,
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            prompt=prompt,
        )
    except AuthorizeFatalError as exc:
        logger.warning("authorize(post) fatal error=%s", exc.error)
        return render_error_page(
            request,
            title="无法完成授权",
            message=exc.description,
            detail=exc.error,
            hint="请回到发起登录的应用重新进入。",
        )
    except AuthorizeRedirectError as exc:
        return _redirect(error_redirect_url(redirect_uri or "", exc.error, exc.description, exc.state))

    if not verify_csrf(request, settings, csrf_token):
        logger.warning("authorize csrf verification failed client=%s", client.client_id)
        return render_error_page(
            request,
            title="表单已失效",
            message="登录表单校验未通过：可能页面停留过久，或不是从本站登录页提交的。",
            hint="请回到发起登录的应用重新进入。",
            status_code=403,
        )

    try:
        user = authenticate(db, username=username, password=password, ip=client_ip(request), settings=settings)
    except HTTPException as exc:
        if exc.status_code == 429:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            return render_error_page(
                request,
                title="尝试过于频繁",
                message=str(detail.get("error_description") or "请稍后再试"),
                status_code=429,
            )
        # 浏览器流程用页面表达失败，而不是返回裸 JSON
        logger.info("authorize login failed client=%s", client.client_id)
        return _login_page(request, settings, client, params, error=GENERIC_LOGIN_ERROR, username=username)

    # 防会话固定：撤销请求里带的旧会话，登录成功一律**新建**会话
    revoke_session(db, session_row, reason="login_replaced")
    session, raw_cookie = create_session(
        db,
        user_id=user.id,
        settings=settings,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _issue_code_redirect(
        request,
        db,
        settings,
        client,
        params,
        user,
        session.id,
        session.auth_time,
        session_cookie=raw_cookie,
    )


# ----------------------------------------------------------------- /token


def _token_response(payload: dict[str, object], status_code: int = 200) -> JSONResponse:
    """令牌响应**一律不得被缓存**（sso-oidc.md §2.4、§7.10）。"""
    response = JSONResponse(payload, status_code=status_code)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _token_error(exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    if not isinstance(detail, dict) or "error" not in detail:
        detail = {"error": "server_error", "error_description": str(detail)}
    response = _token_response(detail, status_code=exc.status_code)
    # 别把 WWW-Authenticate 丢掉（invalid_client 时 RFC 6749 §5.2 要求带上）
    for key, value in (exc.headers or {}).items():
        response.headers[key] = value
    return response


def _grant_authorization_code(
    request: Request,
    settings: Settings,
    db: DbSession,
    keystore: KeyStore,
    client: OAuthClient,
    *,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> JSONResponse:
    exchange = consume_authorization_code(
        db,
        code=code,
        client=client,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )

    user = db.get(User, exchange.user_id)
    if user is None or user.status != "active":
        raise api_error(400, "invalid_grant", "用户不存在或已被禁用")

    scope_text = join_scope(exchange.scope)
    access_token, expires_in = create_access_token(
        settings,
        keystore,
        user,
        scope=scope_text,
        client_id=client.client_id,
    )

    payload: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": scope_text,
    }

    # scope 含 openid → 签发 id_token（aud = client_id，不能用于访问 API）
    if SCOPE_OPENID in exchange.scope:
        id_token, _ = create_id_token(
            settings,
            keystore,
            user=user,
            client_id=client.client_id,
            scopes=exchange.scope,
            auth_time_iso=exchange.auth_time,
            nonce=exchange.nonce,
        )
        payload["id_token"] = id_token

    # 只有请求了 offline_access **且**该客户端注册了 refresh_token 授权类型才发
    # refresh token（OIDC 惯例）：浏览器类客户端靠会话 cookie 静默续期即可，
    # 不必持有长期凭据。
    if SCOPE_OFFLINE_ACCESS in exchange.scope and GRANT_REFRESH_TOKEN in client.grant_type_list:
        family_id = new_family_id()
        payload["refresh_token"] = issue_refresh_token(
            db,
            user_id=user.id,
            settings=settings,
            family_id=family_id,
            client_id=client.client_id,
            scope=scope_text,
            session_id=exchange.session_id,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        # 把链挂到授权码上：该码被重放时整链撤销（§7.4）
        exchange.row.family_id = family_id

    db.commit()
    logger.info(
        "token issued grant=authorization_code client=%s user=%s scope=%s refresh=%s",
        client.client_id,
        user.id,
        scope_text,
        "yes" if "refresh_token" in payload else "no",
    )
    return _token_response(payload)


def _grant_refresh_token(
    request: Request,
    settings: Settings,
    db: DbSession,
    keystore: KeyStore,
    client: OAuthClient,
    *,
    refresh_token: str | None,
    scope: str | None,
) -> JSONResponse:
    """``grant_type=refresh_token``（docs/sso-oidc.md §2.4b）。

    与私有 ``/v1/refresh`` 的关键差别：**强制客户端绑定** ——
    令牌必须由同一个 ``client_id`` 兑换，且刷新时只能**收窄** scope、不能扩大。
    """
    row = consume_refresh_token(
        db,
        token=refresh_token,
        error_status=400,
        require_client_id=client.client_id,
        requested_scope=scope,
    )

    user = db.get(User, row.user_id)
    if user is None or user.status != "active":
        revoke_family(db, row.family_id, reason="user_unavailable")
        db.commit()
        raise api_error(400, "invalid_grant", "用户不存在或已被禁用")

    requested = split_scope(scope)
    granted_scope = join_scope(requested) if requested else (row.scope or "")

    access_token, expires_in = create_access_token(
        settings,
        keystore,
        user,
        scope=granted_scope,
        client_id=client.client_id,
    )

    new_refresh_token = issue_refresh_token(
        db,
        user_id=user.id,
        settings=settings,
        family_id=row.family_id,  # 同一条链
        client_id=client.client_id,
        scope=granted_scope,
        session_id=row.session_id,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()

    payload: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": new_refresh_token,
        "scope": granted_scope,
    }

    if SCOPE_OPENID in split_scope(granted_scope):
        id_token, _ = create_id_token(
            settings,
            keystore,
            user=user,
            client_id=client.client_id,
            scopes=split_scope(granted_scope),
            # 刷新不与原始 nonce 关联；auth_time 取会话或整链起点，取不到就省略
            auth_time_iso=resolve_auth_time(db, session_id=row.session_id, family_id=row.family_id),
            nonce=None,
        )
        payload["id_token"] = id_token

    logger.info(
        "token issued grant=refresh_token client=%s user=%s scope=%s",
        client.client_id,
        user.id,
        granted_scope,
    )
    return _token_response(payload)


@router.post("/token", response_model=None)
def token(
    request: Request,
    settings: SettingsDep,
    keystore: KeyStoreDep,
    db: DbSession = Depends(get_db),
    grant_type: Annotated[str | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    device_code: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
) -> JSONResponse:
    """令牌端点：``application/x-www-form-urlencoded``，客户端认证见 ``app/client_auth.py``。

    ``device_code`` 分支按 §10 第 7 步实现；在那之前它返回 ``unsupported_grant_type``
    （**不假装成功**）。
    """
    try:
        if not grant_type:
            raise api_error(400, "invalid_request", "缺少 grant_type")

        credentials = extract_credentials(request, form_client_id=client_id, form_client_secret=client_secret)
        client = authenticate_client(db, credentials)

        # 先判"服务端是否支持这个 grant_type"，再判"该客户端是否被允许"
        # （否则 password 之类会错报成 unauthorized_client）
        if grant_type not in SUPPORTED_GRANT_TYPES:
            raise api_error(400, "unsupported_grant_type", f"不支持的 grant_type={grant_type}")

        ensure_grant_allowed(client, grant_type)

        if grant_type == GRANT_AUTHORIZATION_CODE:
            return _grant_authorization_code(
                request,
                settings,
                db,
                keystore,
                client,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )

        if grant_type == GRANT_REFRESH_TOKEN:
            return _grant_refresh_token(
                request,
                settings,
                db,
                keystore,
                client,
                refresh_token=refresh_token,
                scope=scope,
            )

        return _grant_device_code(
            request,
            settings,
            db,
            keystore,
            client,
            device_code=device_code,
        )
    except HTTPException as exc:
        return _token_error(exc)


# ------------------------------------------------------------ 设备授权流程

# 「短码不存在」与「短码已过期」必须给出**完全相同**的提示（§7.14，防枚举）
DEVICE_CODE_ERROR = "设备码无效或已过期，请核对后重试。"

# 发起设备授权的限流（防止刷爆短码空间）
DEVICE_AUTHORIZATION_ATTEMPTS = 30
DEVICE_AUTHORIZATION_WINDOW_SECONDS = 300


def _device_token_response(payload: dict[str, object], status_code: int = 200) -> JSONResponse:
    return _token_response(payload, status_code)


def _grant_device_code(
    request: Request,
    settings: Settings,
    db: DbSession,
    keystore: KeyStore,
    client: OAuthClient,
    *,
    device_code: str | None,
) -> JSONResponse:
    """``grant_type=urn:ietf:params:oauth:grant-type:device_code``（docs/sso-oidc.md §2.4c）。"""
    row = consume_device_code(db, device_code=device_code, client=client)

    user = db.get(User, row.user_id) if row.user_id else None
    if user is None or user.status != "active":
        raise api_error(400, "invalid_grant", "用户不存在或已被禁用")

    scope_text = row.scope or ""
    scopes = split_scope(scope_text)

    access_token, expires_in = create_access_token(
        settings,
        keystore,
        user,
        scope=scope_text,
        client_id=client.client_id,
    )

    payload: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": scope_text,
    }

    if SCOPE_OPENID in scopes:
        id_token, _ = create_id_token(
            settings,
            keystore,
            user=user,
            client_id=client.client_id,
            scopes=scopes,
            auth_time_iso=row.auth_time,  # 用户在浏览器里确认授权的时间
            nonce=None,
        )
        payload["id_token"] = id_token

    if SCOPE_OFFLINE_ACCESS in scopes and GRANT_REFRESH_TOKEN in client.grant_type_list:
        payload["refresh_token"] = issue_refresh_token(
            db,
            user_id=user.id,
            settings=settings,
            family_id=new_family_id(),
            client_id=client.client_id,
            scope=scope_text,
            session_id=row.session_id,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    db.commit()
    logger.info(
        "token issued grant=device_code client=%s user=%s scope=%s",
        client.client_id,
        user.id,
        scope_text,
    )
    return _device_token_response(payload)


@router.post("/device_authorization", response_model=None)
def device_authorization(
    request: Request,
    settings: SettingsDep,
    db: DbSession = Depends(get_db),
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
) -> JSONResponse:
    """设备流程第一步：返回 device_code 与人读短码（RFC 8628 §3.1–3.2）。"""
    try:
        credentials = extract_credentials(request, form_client_id=client_id, form_client_secret=client_secret)
        client = authenticate_client(db, credentials)
        ensure_grant_allowed(client, GRANT_DEVICE_CODE)

        ip = client_ip(request)
        if not limiter.allow(
            f"device-authorization:{ip}",
            DEVICE_AUTHORIZATION_ATTEMPTS,
            DEVICE_AUTHORIZATION_WINDOW_SECONDS,
        ):
            raise api_error(
                429,
                "too_many_requests",
                "设备授权请求过于频繁，请稍后再试",
                headers={"Retry-After": str(DEVICE_AUTHORIZATION_WINDOW_SECONDS)},
            )

        requested = split_scope(scope)
        if not requested:
            raise api_error(400, "invalid_request", "缺少 scope")
        validate_scope_subset(requested, client.scope_list)
        scope_text = join_scope(requested)

        device_code, row = create_device_code(
            db,
            client=client,
            scope=scope_text,
            settings_ttl=settings.device_code_ttl,
            interval_seconds=settings.device_poll_interval,
            ip=ip,
        )

        verification_uri = settings.device_verification_uri
        return _device_token_response(
            {
                "device_code": device_code,
                "user_code": row.user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": f"{verification_uri}?{urlencode({'user_code': row.user_code})}",
                "expires_in": settings.device_code_ttl,
                "interval": row.interval_seconds,
            }
        )
    except HTTPException as exc:
        return _token_error(exc)


# ------------------------------------------------------------ /device 页面


def _html(response: HTMLResponse) -> HTMLResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _device_code_page(
    request: Request,
    settings: Settings,
    *,
    user_code: str | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    existing = request.cookies.get(csrf_cookie_name(settings))
    token = existing or new_csrf_token()
    response = _html(
        templates.TemplateResponse(
            request,
            "device_code.html",
            {
                "action": settings.external_url("device"),
                "csrf_token": token,
                "user_code": user_code,
                "error": error,
            },
            status_code=status_code,
        )
    )
    if existing is None:
        set_csrf_cookie(response, settings, token)
    return response


def _device_login_page(
    request: Request,
    settings: Settings,
    *,
    user_code: str | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """设备流程里的登录页：复用同一个模板，但表单提交到 /device。"""
    existing = request.cookies.get(csrf_cookie_name(settings))
    token = existing or new_csrf_token()
    response = _html(
        templates.TemplateResponse(
            request,
            "login.html",
            {
                "action": settings.external_url("device"),
                "csrf_token": token,
                "device_mode": True,
                "user_code": user_code,
                "error": error,
                "username": None,
            },
            status_code=status_code,
        )
    )
    if existing is None:
        set_csrf_cookie(response, settings, token)
    return response


def _device_confirm_page(
    request: Request,
    settings: Settings,
    *,
    row,
    client: OAuthClient,
    username: str,
) -> HTMLResponse:
    existing = request.cookies.get(csrf_cookie_name(settings))
    token = existing or new_csrf_token()
    response = _html(
        templates.TemplateResponse(
            request,
            "device_confirm.html",
            {
                "action": settings.external_url("device"),
                "csrf_token": token,
                "user_code": row.user_code,
                "client_name": client.name,
                "username": username,
                "scopes": describe_scopes(split_scope(row.scope)),
            },
        )
    )
    if existing is None:
        set_csrf_cookie(response, settings, token)
    return response


def _device_done_page(
    request: Request,
    settings: Settings,
    *,
    title: str,
    message: str,
    tone: str = "ok",
    hint: str | None = None,
) -> HTMLResponse:
    return _html(
        templates.TemplateResponse(
            request,
            "device_done.html",
            {"title": title, "message": message, "tone": tone, "hint": hint},
        )
    )


@router.get("/device", response_class=HTMLResponse, response_model=None)
def device_get(
    request: Request,
    settings: SettingsDep,
    session_row: OptionalSession,
    db: DbSession = Depends(get_db),
) -> HTMLResponse:
    """渲染"输入设备码"页；已带短码且已登录时直接进入确认页。"""
    user_code = request.query_params.get("user_code")

    user = db.get(User, session_row.user_id) if session_row is not None else None
    if user is None or user.status != "active":
        # 未登录（或会话对应用户不可用）→ 先登录，登录后回到本页
        return _device_login_page(request, settings, user_code=user_code)

    if not user_code:
        return _device_code_page(request, settings)

    row = find_pending_by_user_code(db, user_code)
    if row is None:
        return _device_code_page(request, settings, user_code=user_code, error=DEVICE_CODE_ERROR)

    client = db.get(OAuthClient, row.client_id)
    if client is None:
        return _device_code_page(request, settings, error=DEVICE_CODE_ERROR)
    return _device_confirm_page(request, settings, row=row, client=client, username=user.username)


@router.post("/device", response_class=HTMLResponse, response_model=None)
def device_post(
    request: Request,
    settings: SettingsDep,
    session_row: OptionalSession,
    db: DbSession = Depends(get_db),
    csrf_token: Annotated[str | None, Form()] = None,
    user_code: Annotated[str | None, Form()] = None,
    username: Annotated[str | None, Form()] = None,
    password: Annotated[str | None, Form()] = None,
    decision: Annotated[str | None, Form()] = None,
) -> HTMLResponse | RedirectResponse:
    if not verify_csrf(request, settings, csrf_token):
        return render_error_page(
            request,
            title="表单已失效",
            message="校验未通过：可能页面停留过久，或不是从本站页面提交的。",
            hint="请回到设备页面重新进入。",
            status_code=403,
        )

    user = db.get(User, session_row.user_id) if session_row is not None else None

    # 1) 未登录 → 先在本页登录（登录成功后再回到 /device 输入短码）
    if user is None or user.status != "active":
        try:
            user = authenticate(db, username=username, password=password, ip=client_ip(request), settings=settings)
        except HTTPException as exc:
            if exc.status_code == 429:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                return render_error_page(
                    request,
                    title="尝试过于频繁",
                    message=str(detail.get("error_description") or "请稍后再试"),
                    status_code=429,
                )
            return _device_login_page(request, settings, user_code=user_code, error=GENERIC_LOGIN_ERROR)

        # 防会话固定：登录成功新建会话（可能覆盖请求里那个已失效的 cookie）
        revoke_session(db, session_row, reason="login_replaced")
        session, raw_cookie = create_session(
            db,
            user_id=user.id,
            settings=settings,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        db.commit()

        target = settings.external_url("device")
        if user_code:
            target = f"{target}?{urlencode({'user_code': user_code})}"
        response = RedirectResponse(target, status_code=303)
        response.headers["Cache-Control"] = "no-store"
        set_session_cookie(response, settings, raw_cookie)
        return response

    # 2) 已登录：处理"同意/拒绝"
    if decision in {"approve", "deny"}:
        row = find_pending_by_user_code(db, user_code)
        if row is None:
            return _device_code_page(request, settings, user_code=user_code, error=DEVICE_CODE_ERROR)

        client = db.get(OAuthClient, row.client_id)
        if decision == "deny":
            deny_device_code(db, row)
            logger.info("device authorization denied client=%s user=%s", row.client_id, user.id)
            return _device_done_page(
                request,
                settings,
                title="已拒绝",
                message="你已拒绝本次设备授权，设备不会获得访问权限。",
                tone="error",
            )

        approve_device_code(
            db,
            row,
            user_id=user.id,
            session_id=session_row.id,
            auth_time_iso=session_row.auth_time,
        )
        logger.info("device authorization approved client=%s user=%s", row.client_id, user.id)
        client_name = client.name if client is not None else "该设备"
        return _device_done_page(
            request,
            settings,
            title="已授权",
            message=f"{client_name} 已获得访问权限。",
            hint="现在可以关闭本页，回到设备上继续。",
        )

    # 3) 已登录：提交短码 → 进入确认页
    if not user_code:
        return _device_code_page(request, settings, error="请输入设备上显示的短码。")

    row = find_pending_by_user_code(db, user_code)
    if row is None:
        return _device_code_page(request, settings, user_code=user_code, error=DEVICE_CODE_ERROR)

    client = db.get(OAuthClient, row.client_id)
    if client is None:
        return _device_code_page(request, settings, error=DEVICE_CODE_ERROR)
    return _device_confirm_page(request, settings, row=row, client=client, username=user.username)


# ----------------------------------------- 标准登出（RP-Initiated Logout）


LOGOUT_REDIRECT_MISMATCH = "该回跳地址未在客户端注册，出于安全考虑没有跳转。"


def _logout_page(
    request: Request,
    settings: Settings,
    *,
    notice: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    response = _html(
        templates.TemplateResponse(request, "logged_out.html", {"notice": notice}, status_code=status_code)
    )
    clear_session_cookie(response, settings)
    return response


def _resolve_logout_client(
    db: DbSession,
    settings: Settings,
    keystore: KeyStore,
    *,
    id_token_hint: str | None,
    client_id: str | None,
) -> OAuthClient | None:
    """从 ``id_token_hint``（或 ``client_id``）确定是哪个客户端。

    ``id_token_hint`` 会**校验签名与 iss**（允许过期）—— 绝不能拿未经验证的 aud
    来决定回跳地址，那等于把开放重定向交到攻击者手里。
    """
    claims = decode_id_token_hint(settings, keystore, id_token_hint) if id_token_hint else None
    aud = claims.get("aud") if claims else None
    if isinstance(aud, list):
        aud = aud[0] if aud else None

    candidate = aud or client_id
    if not candidate:
        return None
    return db.get(OAuthClient, str(candidate))


def _perform_logout(
    request: Request,
    settings: Settings,
    keystore: KeyStore,
    session_row,
    db: DbSession,
    *,
    post_logout_redirect_uri: str | None,
    id_token_hint: str | None,
    state: str | None,
    client_id: str | None,
) -> HTMLResponse | RedirectResponse:
    """结束会话 → 撤销该会话派生的 refresh 链 → 按注册值决定是否回跳。

    注意撤销范围：只杀**这个浏览器会话**产生的链，不误伤同一账号在其它设备上的登录
    （这正是当初给 refresh_tokens 加 session_id 的原因）。
    """
    if session_row is not None:
        revoked = revoke_session_chains(db, session_row.id, reason="logout")
        revoke_session(db, session_row, reason="logout")
        db.commit()
        logger.info(
            "logout user=%s session=%s revoked_tokens=%s",
            session_row.user_id,
            session_row.id,
            revoked,
        )

    if not post_logout_redirect_uri:
        return _logout_page(request, settings)

    client = _resolve_logout_client(
        db,
        settings,
        keystore,
        id_token_hint=id_token_hint,
        client_id=client_id,
    )
    if client is None or not client.allows_post_logout_redirect_uri(post_logout_redirect_uri):
        # 未注册 → 不跳转（§2.7 防开放重定向）
        logger.warning(
            "logout redirect refused client=%s uri=%s",
            client.client_id if client else "-",
            post_logout_redirect_uri,
        )
        return _logout_page(request, settings, notice=LOGOUT_REDIRECT_MISMATCH)

    target = post_logout_redirect_uri
    if state:
        separator = "&" if "?" in target else "?"
        target = f"{target}{separator}{urlencode({'state': state})}"

    response = RedirectResponse(target, status_code=302)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    clear_session_cookie(response, settings)
    return response


@router.get("/logout", response_class=HTMLResponse, response_model=None)
def logout_get(
    request: Request,
    settings: SettingsDep,
    keystore: KeyStoreDep,
    session_row: OptionalSession,
    db: DbSession = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    query = request.query_params
    return _perform_logout(
        request,
        settings,
        keystore,
        session_row,
        db,
        post_logout_redirect_uri=query.get("post_logout_redirect_uri"),
        id_token_hint=query.get("id_token_hint"),
        state=query.get("state"),
        client_id=query.get("client_id"),
    )


@router.post("/logout", response_class=HTMLResponse, response_model=None)
def logout_post(
    request: Request,
    settings: SettingsDep,
    keystore: KeyStoreDep,
    session_row: OptionalSession,
    db: DbSession = Depends(get_db),
    post_logout_redirect_uri: Annotated[str | None, Form()] = None,
    id_token_hint: Annotated[str | None, Form()] = None,
    state: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
) -> HTMLResponse | RedirectResponse:
    """表单字段优先，其次回落到 query（OIDC 两种都允许）。"""
    query = request.query_params
    return _perform_logout(
        request,
        settings,
        keystore,
        session_row,
        db,
        post_logout_redirect_uri=post_logout_redirect_uri or query.get("post_logout_redirect_uri"),
        id_token_hint=id_token_hint or query.get("id_token_hint"),
        state=state or query.get("state"),
        client_id=client_id or query.get("client_id"),
    )

"""管理员命令行：建号 / 改状态 / 改密 / 轮换密钥 / OIDC 客户端管理。

容器内用法：

    docker compose exec sso python -m app.cli create-user --username alice --password-stdin
    docker compose exec sso python -m app.cli list-users
    docker compose exec sso python -m app.cli set-status --username alice --status disabled
    docker compose exec sso python -m app.cli rotate-key --new-kid 2026-07

    # OIDC 客户端（sso-oidc.md §5.3）
    docker compose exec sso python -m app.cli create-client \\
      --client-id elipese-web --name "Elipese Web" --type public \\
      --redirect-uri https://elipese.cloud/callback \\
      --scope "openid profile email"
    docker compose exec sso python -m app.cli list-clients
    docker compose exec sso python -m app.cli show-client --client-id elipese-web
    docker compose exec sso python -m app.cli rotate-client-secret --client-id elipese-web
    docker compose exec sso python -m app.cli delete-client --client-id elipese-web
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import func, select

from .clients import (
    DEFAULT_GRANT_TYPES,
    create_client,
    delete_client,
    get_client_or_404,
    list_clients,
    rotate_client_secret,
)
from .config import get_settings
from .constants import (
    CLIENT_TYPE_PUBLIC,
    SUPPORTED_AUTH_METHODS,
    SUPPORTED_CLIENT_TYPES,
)
from .db import init_db, session_scope
from .keys import KeyStore, generate_private_key, save_private_key, save_public_key
from .models import User, to_iso, utcnow
from .oidc import split_scope
from .security import hash_password, validate_email, validate_password, validate_username


def _print_api_error(exc: HTTPException) -> int:
    """把 HTTPException 渲染成一行 CLI 错误，而不是抛栈。"""
    detail = exc.detail
    if isinstance(detail, dict):
        print(f"错误：{detail.get('error')} - {detail.get('error_description')}", file=sys.stderr)
    else:
        print(f"错误：{detail}", file=sys.stderr)
    return 1


def _read_password(args: argparse.Namespace) -> str:
    if getattr(args, "password", None):
        print("警告：--password 会出现在进程列表与 shell 历史里，建议改用 --password-stdin。", file=sys.stderr)
        return args.password
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Password: ")


def _find_user(session, username: str) -> User | None:
    return session.scalar(select(User).where(func.lower(User.username) == username.strip().lower()))


def _next_user_id(session) -> str:
    max_index = 0
    for value in session.scalars(select(User.id)).all():
        if value.startswith("user_") and value[5:].isdigit():
            max_index = max(max_index, int(value[5:]))
    return f"user_{max_index + 1:04d}"


def cmd_create_user(args: argparse.Namespace) -> int:
    username = validate_username(args.username)
    password = validate_password(_read_password(args))
    email = validate_email(args.email)

    with session_scope() as session:
        if _find_user(session, username) is not None:
            print(f"用户名已存在：{username}", file=sys.stderr)
            return 1
        if email and session.scalar(select(User).where(func.lower(User.email) == email)) is not None:
            print(f"邮箱已被占用：{email}", file=sys.stderr)
            return 1
        now_iso = to_iso(utcnow())
        user = User(
            id=_next_user_id(session),
            username=username,
            email=email,
            password_hash=hash_password(password),
            status="active",
            created_at=now_iso,
            updated_at=now_iso,
        )
        session.add(user)
        session.commit()
        print(f"已创建用户 {user.id} username={user.username} email={user.email or '-'}")
    return 0


def cmd_list_users(_args: argparse.Namespace) -> int:
    with session_scope() as session:
        users = session.scalars(select(User).order_by(User.id)).all()
        if not users:
            print("（暂无用户）")
            return 0
        print(f"{'id':<12} {'username':<20} {'email':<28} {'status':<10} created_at")
        for user in users:
            print(f"{user.id:<12} {user.username:<20} {(user.email or '-'):<28} {user.status:<10} {user.created_at}")
    return 0


def cmd_set_status(args: argparse.Namespace) -> int:
    if args.status not in {"active", "disabled"}:
        print("status 只能是 active 或 disabled", file=sys.stderr)
        return 2
    with session_scope() as session:
        user = _find_user(session, args.username)
        if user is None:
            print(f"用户不存在：{args.username}", file=sys.stderr)
            return 1
        user.status = args.status
        user.updated_at = to_iso(utcnow())
        session.commit()
        print(f"{user.id} status -> {user.status}")
    return 0


def cmd_reset_password(args: argparse.Namespace) -> int:
    password = validate_password(_read_password(args))
    with session_scope() as session:
        user = _find_user(session, args.username)
        if user is None:
            print(f"用户不存在：{args.username}", file=sys.stderr)
            return 1
        user.password_hash = hash_password(password)
        user.updated_at = to_iso(utcnow())
        session.commit()
        print(f"{user.id} 密码已重置")
    return 0


def cmd_show_config(_args: argparse.Namespace) -> int:
    settings = get_settings()
    print(f"issuer        = {settings.issuer}")
    print(f"jwks_uri      = {settings.jwks_uri}")
    print(f"public_base   = {settings.public_base_url}")
    print(f"database_url  = {settings.database_url}")
    print(f"private_key   = {settings.jwt_private_key_path}")
    print(f"keys_dir      = {settings.jwt_keys_dir}")
    print(f"jwt_kid       = {settings.jwt_kid}")
    print(f"alg           = {settings.jwt_alg}")
    print(f"access_ttl    = {settings.access_token_ttl}s")
    print(f"refresh_ttl   = {settings.refresh_token_ttl}s")
    print(f"allow_reg     = {settings.allow_registration}")
    print(f"cors_origins  = {settings.cors_origin_list}")
    store = KeyStore.load(settings)
    print(f"published_kids= {sorted(store.public_keys)}")
    return 0


def cmd_rotate_key(args: argparse.Namespace) -> int:
    """轮换签名密钥：旧公钥留在 keys_dir（继续可验签），新私钥写入挂卷。

    轮换后必须把 JWT_KID 改成 --new-kid 再重启容器。
    """
    settings = get_settings()
    new_kid = (args.new_kid or "").strip()
    if not new_kid:
        print("必须提供 --new-kid", file=sys.stderr)
        return 2
    if new_kid == settings.jwt_kid:
        print("新 kid 与当前 JWT_KID 相同，无需轮换", file=sys.stderr)
        return 2

    store = KeyStore.load(settings)

    # 1) 旧签名公钥归档到 keys_dir，使其在 JWKS 里继续发布
    old_public_path = publish_path(settings.jwt_keys_dir, settings.jwt_kid)
    save_public_key(old_public_path, store.signing_public_key)

    # 2) 生成新私钥，直接落到配置的签名私钥路径
    save_private_key(Path(settings.jwt_private_key_path), generate_private_key())

    print(f"已生成新签名密钥 kid={new_kid}")
    print(f"旧公钥已归档：{old_public_path}（JWKS 继续发布 {settings.jwt_kid} 与更早的 kid）")
    print("下一步：把环境变量 JWT_KID 改为 " + new_kid + " 并重启容器：")
    print("  docker compose up -d sso")
    print("注意：旧 access token 仍可验签（公钥并存），但新令牌一律用新 kid 签发。")
    return 0


def publish_path(keys_dir: str, kid: str) -> Path:
    """历史公钥在 keys_dir 中的归档路径，文件清单即 JWKS 的发布清单。"""
    return Path(keys_dir) / f"{kid}.public.pem"


def _print_client(client, *, with_secret: str | None = None) -> None:
    print(f"client_id                  : {client.client_id}")
    print(f"name                       : {client.name}")
    print(f"client_type                : {client.client_type}")
    print(f"token_endpoint_auth_method : {client.token_endpoint_auth_method}")
    print(f"redirect_uris              : {client.redirect_uri_list}")
    print(f"post_logout_redirect_uris  : {client.post_logout_redirect_uri_list}")
    print(f"allowed_scopes             : {client.scope_list}")
    print(f"allowed_grant_types        : {client.grant_type_list}")
    if with_secret is not None:
        print(f"client_secret              : {with_secret}")
        print("  ⚠️ 明文 secret 只显示这一次，请立刻保存；之后无法再取出（库里只有哈希）。")


def cmd_create_client(args: argparse.Namespace) -> int:
    try:
        with session_scope() as session:
            client, secret = create_client(
                session,
                client_id=args.client_id,
                name=args.name,
                client_type=args.client_type,
                redirect_uris=args.redirect_uri or [],
                post_logout_redirect_uris=args.post_logout_redirect_uri or [],
                allowed_scopes=split_scope(args.scope),
                allowed_grant_types=args.grant_type or None,
                token_endpoint_auth_method=args.auth_method,
            )
            print(f"已创建客户端 {client.client_id}")
            _print_client(client, with_secret=secret)
            if secret is None:
                print("  （public 客户端没有 client_secret，认证靠 PKCE S256）")
    except HTTPException as exc:
        return _print_api_error(exc)
    return 0


def cmd_list_clients(_args: argparse.Namespace) -> int:
    with session_scope() as session:
        rows = list_clients(session)
        if not rows:
            print("（暂无客户端）")
            print("创建示例：docker compose exec sso python -m app.cli create-client \\")
            print('  --client-id elipese-web --name "Elipese Web" --type public \\')
            print("  --redirect-uri https://elipese.cloud/callback \\")
            print('  --scope "openid profile email"')
            return 0
        print(f"{'client_id':<20} {'type':<13} {'auth':<20} {'scopes':<34} redirect_uris")
        for client in rows:
            print(
                f"{client.client_id:<20} {client.client_type:<13} {client.token_endpoint_auth_method:<20} "
                f"{' '.join(client.scope_list):<34} {client.redirect_uri_list}"
            )
    return 0


def cmd_show_client(args: argparse.Namespace) -> int:
    try:
        with session_scope() as session:
            _print_client(get_client_or_404(session, args.client_id))
    except HTTPException as exc:
        return _print_api_error(exc)
    return 0


def cmd_rotate_client_secret(args: argparse.Namespace) -> int:
    try:
        with session_scope() as session:
            client, plaintext = rotate_client_secret(session, args.client_id)
            print(f"已轮换客户端 {client.client_id} 的 secret（旧 secret 立即失效）")
            print(f"client_secret : {plaintext}")
            print("  ⚠️ 只显示这一次，请立刻更新到对应服务端。")
    except HTTPException as exc:
        return _print_api_error(exc)
    return 0


def cmd_delete_client(args: argparse.Namespace) -> int:
    try:
        with session_scope() as session:
            client = get_client_or_404(session, args.client_id)
            print(f"将删除客户端 {client.client_id}（{client.name}），并撤销其 refresh 链、清掉授权码/设备码/同意记录。")
            if not args.yes:
                answer = input("确认删除？输入 yes 继续：").strip().lower()
                if answer != "yes":
                    print("已取消。", file=sys.stderr)
                    return 1
            delete_client(session, args.client_id)
            print(f"已删除 {args.client_id}")
    except HTTPException as exc:
        return _print_api_error(exc)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="EliCloud SSO 管理命令")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-user", help="创建用户")
    create.add_argument("--username", required=True)
    create.add_argument("--password", default=None, help="明文密码（不推荐，建议 --password-stdin）")
    create.add_argument("--password-stdin", action="store_true", help="从标准输入读一行作为密码")
    create.add_argument("--email", default=None)
    create.set_defaults(func=cmd_create_user)

    listing = sub.add_parser("list-users", help="列出用户")
    listing.set_defaults(func=cmd_list_users)

    status = sub.add_parser("set-status", help="启用/禁用用户")
    status.add_argument("--username", required=True)
    status.add_argument("--status", required=True, choices=["active", "disabled"])
    status.set_defaults(func=cmd_set_status)

    reset = sub.add_parser("reset-password", help="重置密码")
    reset.add_argument("--username", required=True)
    reset.add_argument("--password", default=None)
    reset.add_argument("--password-stdin", action="store_true")
    reset.set_defaults(func=cmd_reset_password)

    config = sub.add_parser("show-config", help="打印生效配置（不含任何私钥内容）")
    config.set_defaults(func=cmd_show_config)

    rotate = sub.add_parser("rotate-key", help="轮换 RSA 签名密钥")
    rotate.add_argument("--new-kid", required=True)
    rotate.set_defaults(func=cmd_rotate_key)

    # ---------------- OIDC 客户端管理（sso-oidc.md §5.3）----------------
    create_client_parser = sub.add_parser("create-client", help="创建 OIDC 客户端")
    create_client_parser.add_argument("--client-id", required=True)
    create_client_parser.add_argument("--name", required=True)
    create_client_parser.add_argument(
        "--type", dest="client_type", choices=list(SUPPORTED_CLIENT_TYPES), default=CLIENT_TYPE_PUBLIC
    )
    create_client_parser.add_argument(
        "--redirect-uri",
        action="append",
        default=[],
        help="可重复；必须与客户端实际回跳地址逐字一致（精确匹配）",
    )
    create_client_parser.add_argument("--post-logout-redirect-uri", action="append", default=[])
    create_client_parser.add_argument("--scope", default="", help='空格分隔，如 --scope "openid profile email"')
    create_client_parser.add_argument(
        "--grant-type", action="append", default=[], help=f"可重复；不传则默认 {list(DEFAULT_GRANT_TYPES)}"
    )
    create_client_parser.add_argument(
        "--auth-method", default=None, help=f"不传则按类型推导（{' / '.join(SUPPORTED_AUTH_METHODS)}）"
    )
    create_client_parser.set_defaults(func=cmd_create_client)

    list_clients_parser = sub.add_parser("list-clients", help="列出 OIDC 客户端")
    list_clients_parser.set_defaults(func=cmd_list_clients)

    show_client_parser = sub.add_parser("show-client", help="查看单个 OIDC 客户端")
    show_client_parser.add_argument("--client-id", required=True)
    show_client_parser.set_defaults(func=cmd_show_client)

    rotate_secret_parser = sub.add_parser("rotate-client-secret", help="轮换客户端 secret")
    rotate_secret_parser.add_argument("--client-id", required=True)
    rotate_secret_parser.set_defaults(func=cmd_rotate_client_secret)

    delete_client_parser = sub.add_parser("delete-client", help="删除客户端（并撤销其 refresh 链）")
    delete_client_parser.add_argument("--client-id", required=True)
    delete_client_parser.add_argument("--yes", action="store_true", help="跳过交互确认")
    delete_client_parser.set_defaults(func=cmd_delete_client)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    init_db(get_settings())
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

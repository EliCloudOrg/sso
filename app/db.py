"""数据库连接、会话与幂等迁移。

起步用 SQLite（挂卷持久化），表结构保持可迁移；换 PostgreSQL 只需改 DATABASE_URL。

迁移策略（sso-oidc.md §6.1 的要求）：**不引入 Alembic**，用启动时的幂等迁移：
1. 旧形状的 ``oauth_clients``（缺 ``client_type``）若为空表 → 直接 DROP，随后按新结构重建；
   若非空则**拒绝启动**并提示人工迁移，绝不静默丢数据。
2. ``refresh_tokens`` 补 OIDC 新列：先查 ``PRAGMA table_info`` / inspector 再决定是否 ALTER，
   因此重启任意次都不会报错。
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .models import Base

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None

# 需要按需补到既有表上的列（表名 -> 列名集合）
_ADDED_COLUMNS: dict[str, tuple[str, ...]] = {
    "refresh_tokens": ("client_id", "scope", "session_id"),
}


def _sqlite_path(database_url: str) -> str | None:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return None
    return database_url[len(prefix) :]


def _drop_legacy_oauth_clients(engine: Engine) -> None:
    """把旧的"只建表不使用"的 oauth_clients 换成新结构。

    旧结构没有 ``client_type`` 列。为空（本项目一期从未使用）时直接重建；
    非空说明已经有人写过数据，宁可启动失败也不能丢。
    """
    inspector = inspect(engine)
    if "oauth_clients" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("oauth_clients")}
    if "client_type" in columns:
        return  # 已是新结构

    with engine.begin() as connection:
        count = connection.execute(text("SELECT COUNT(*) FROM oauth_clients")).scalar() or 0
        if count:
            raise RuntimeError(
                "oauth_clients 是旧结构且包含 "
                f"{count} 行数据，拒绝自动重建。请先人工导出/迁移（见 sso-oidc.md §6.1）。"
            )
        connection.execute(text("DROP TABLE oauth_clients"))
    logger.info("已重建 oauth_clients 表（旧结构且为空）")


def _add_missing_columns(engine: Engine) -> None:
    """给既有表补新列；SQLite/PG 的 ADD COLUMN 都是幂等安全的（先判断再执行）。"""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    for table, wanted in _ADDED_COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for column in wanted:
            if column in existing:
                continue
            with engine.begin() as connection:
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} TEXT"))
            logger.info("迁移：%s 增加列 %s", table, column)


def init_db(settings: Settings) -> Engine:
    """建引擎、跑幂等迁移、建表。可重复调用。"""
    global _engine, _session_factory

    if _engine is not None:
        return _engine

    url = settings.database_url
    is_sqlite = url.startswith("sqlite")
    connect_args: dict[str, object] = {"check_same_thread": False} if is_sqlite else {}

    sqlite_path = _sqlite_path(url)
    if sqlite_path:
        Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(url, connect_args=connect_args, future=True)

    if is_sqlite:

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):  # pragma: no cover
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    # 顺序很重要：先清掉不兼容的旧表，再 create_all 建出新表，最后给既有表补列
    # （create_all 只会创建缺失的表，不会改动已存在的表结构）
    _drop_legacy_oauth_clients(engine)
    Base.metadata.create_all(engine)
    _add_missing_columns(engine)

    _engine = engine
    _session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    return engine


def get_db() -> Iterator[Session]:
    """FastAPI 依赖：每个请求一个会话。"""
    if _session_factory is None:
        raise RuntimeError("数据库尚未初始化，请先调用 init_db()")
    session = _session_factory()
    try:
        yield session
    finally:
        session.close()


def session_scope() -> Session:
    """给 CLI / 脚本用的裸会话（调用方负责 commit/close）。"""
    if _session_factory is None:
        raise RuntimeError("数据库尚未初始化，请先调用 init_db()")
    return _session_factory()


def reset_db_state() -> None:
    """测试用：丢弃引擎与会话工厂。"""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None

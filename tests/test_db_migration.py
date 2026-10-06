"""幂等迁移测试（sso-oidc.md §6.1）。

刻意在**独立的临时引擎**上直接测迁移函数，不碰 conftest 里那个共享的全局引擎，
避免这些用例影响同一 session 内其它测试的数据库。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from app.db import _add_missing_columns, _drop_legacy_oauth_clients
from app.models import Base

LEGACY_OAUTH_CLIENTS = """
CREATE TABLE oauth_clients (
  client_id          TEXT PRIMARY KEY,
  client_secret_hash TEXT NOT NULL,
  name               TEXT NOT NULL,
  redirect_uris      TEXT,
  scopes             TEXT,
  created_at         TEXT NOT NULL
)
"""

LEGACY_REFRESH_TOKENS = """
CREATE TABLE refresh_tokens (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  family_id   TEXT NOT NULL,
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  revoked_at  TEXT,
  created_at  TEXT NOT NULL,
  user_agent  TEXT,
  ip          TEXT
)
"""


def _engine(tmp_path: Path, name: str):
    return create_engine(f"sqlite:///{(tmp_path / name).as_posix()}", future=True)


def _columns(engine, table: str) -> set[str]:
    return {column["name"] for column in inspect(engine).get_columns(table)}


def test_empty_legacy_oauth_clients_is_rebuilt(tmp_path):
    engine = _engine(tmp_path, "legacy-empty.db")
    with engine.begin() as connection:
        connection.execute(text(LEGACY_OAUTH_CLIENTS))

    _drop_legacy_oauth_clients(engine)
    assert "oauth_clients" not in inspect(engine).get_table_names()

    Base.metadata.create_all(engine)
    assert "client_type" in _columns(engine, "oauth_clients")
    assert "allowed_scopes" in _columns(engine, "oauth_clients")


def test_legacy_oauth_clients_with_data_refuses_to_rebuild(tmp_path):
    """有数据时宁可启动失败，也不静默 DROP。"""
    engine = _engine(tmp_path, "legacy-data.db")
    with engine.begin() as connection:
        connection.execute(text(LEGACY_OAUTH_CLIENTS))
        connection.execute(
            text(
                "INSERT INTO oauth_clients (client_id, client_secret_hash, name, created_at) "
                "VALUES ('legacy', 'x', 'legacy', '2026-01-01T00:00:00Z')"
            )
        )

    with pytest.raises(RuntimeError, match="拒绝自动重建"):
        _drop_legacy_oauth_clients(engine)
    # 数据仍在
    with engine.begin() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM oauth_clients")).scalar() == 1


def test_new_shape_oauth_clients_is_left_alone(tmp_path):
    engine = _engine(tmp_path, "new-shape.db")
    Base.metadata.create_all(engine)

    before = _columns(engine, "oauth_clients")
    _drop_legacy_oauth_clients(engine)
    assert _columns(engine, "oauth_clients") == before


def test_add_missing_columns_is_idempotent(tmp_path):
    engine = _engine(tmp_path, "add-columns.db")
    with engine.begin() as connection:
        connection.execute(text(LEGACY_REFRESH_TOKENS))

    _add_missing_columns(engine)
    assert {"client_id", "scope", "session_id"} <= _columns(engine, "refresh_tokens")

    # 再跑一次不能报错（重启任意次都安全）
    _add_missing_columns(engine)
    assert {"client_id", "scope", "session_id"} <= _columns(engine, "refresh_tokens")


def test_add_missing_columns_skips_absent_table(tmp_path):
    engine = _engine(tmp_path, "no-table.db")
    # refresh_tokens 不存在时不应报错，也不应凭空建表
    _add_missing_columns(engine)
    assert "refresh_tokens" not in inspect(engine).get_table_names()

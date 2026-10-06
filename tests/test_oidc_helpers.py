"""OIDC 协议层纯函数测试（PKCE / scope），含 RFC 7636 的已知向量。"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.oidc import (
    ensure_pkce_s256,
    join_scope,
    pkce_challenge_s256,
    pkce_matches,
    pkce_verifier_looks_valid,
    scope_has,
    split_scope,
    validate_scope_subset,
)

# RFC 7636 Appendix B 的官方示例
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


# ------------------------------------------------------------------ scope


def test_split_scope_dedupes_and_keeps_order():
    assert split_scope("openid profile email openid") == ["openid", "profile", "email"]
    assert split_scope(None) == []
    assert split_scope("") == []
    assert split_scope("  openid   profile  ") == ["openid", "profile"]


def test_join_and_has_scope():
    assert join_scope(["openid", "email"]) == "openid email"
    assert scope_has("openid profile", "profile") is True
    assert scope_has("openid", "email") is False
    assert scope_has(None, "openid") is False


def test_validate_scope_subset_rejects_unsupported_and_unauthorized():
    with pytest.raises(HTTPException) as unsupported:
        validate_scope_subset(["openid", "admin:all"], ["openid", "admin:all"])
    assert unsupported.value.status_code == 400
    assert unsupported.value.detail["error"] == "invalid_scope"

    with pytest.raises(HTTPException) as forbidden:
        validate_scope_subset(["openid", "pdf:write"], ["openid", "pdf:read"])
    assert forbidden.value.status_code == 400
    assert forbidden.value.detail["error"] == "invalid_scope"

    assert validate_scope_subset(["openid"], ["openid", "email"]) == ["openid"]


# ------------------------------------------------------------------- PKCE


def test_pkce_matches_rfc7636_known_vector():
    assert pkce_challenge_s256(RFC_VERIFIER) == RFC_CHALLENGE
    assert pkce_matches(RFC_VERIFIER, RFC_CHALLENGE) is True


def test_pkce_matches_rejects_wrong_or_malformed_input():
    assert pkce_matches("wrong-verifier-that-is-long-enough-000000000000", RFC_CHALLENGE) is False
    assert pkce_matches(None, RFC_CHALLENGE) is False
    assert pkce_matches(RFC_VERIFIER, None) is False
    assert pkce_matches(RFC_VERIFIER, "") is False
    # plain 方式（challenge == verifier）必须不通过 S256 校验
    assert pkce_matches(RFC_VERIFIER, RFC_VERIFIER) is False
    # 含非法字符的 verifier 不抛异常，直接判失败
    assert pkce_matches("x" * 43 + "!!!", RFC_CHALLENGE) is False


def test_pkce_verifier_length_and_charset_rules():
    assert pkce_verifier_looks_valid(RFC_VERIFIER) is True
    assert pkce_verifier_looks_valid("x" * 42) is False  # 太短（<43）
    assert pkce_verifier_looks_valid("x" * 129) is False  # 太长（>128）
    assert pkce_verifier_looks_valid("x" * 43 + "+") is False  # 非 unreserved 字符
    assert pkce_verifier_looks_valid(None) is False


def test_ensure_pkce_s256_only_accepts_s256():
    assert ensure_pkce_s256("S256") == "S256"
    for bad in ("plain", "PLAIN", "", None, "s256 "):
        with pytest.raises(HTTPException) as excinfo:
            ensure_pkce_s256(bad)
        assert excinfo.value.status_code == 400

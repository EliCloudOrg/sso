"""RSA 密钥：加载 / 首次生成 / JWKS 发布（含密钥轮换）。

设计（满足 §0.4 硬约束 5 与 §5.6「轮换时新旧公钥并存」）：

* **签名私钥**：``JWT_PRIVATE_KEY_PATH``（默认 /data/jwt_private.pem），权限 600，
  落在挂卷目录里。首次启动自动生成，之后永不重新生成——否则容器重建会让所有已签发令牌失效。
* **JWKS**：当前签名公钥（kid = ``JWT_KID``）**加上** ``JWT_KEYS_DIR`` 下所有
  ``<kid>.public.pem``。轮换时把旧公钥留在该目录，新旧公钥因此并存，
  业务服务的本地缓存不会在轮换瞬间全部验签失败（见 scripts/rotate_key.py）。
"""

from __future__ import annotations

import base64
import os
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .config import Settings

PUBLIC_KEY_SUFFIX = ".public.pem"
DEFAULT_KEY_SIZE = 2048


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _int_to_b64url(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(length, "big"))


def generate_private_key(key_size: int = DEFAULT_KEY_SIZE) -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def save_private_key(path: Path, key: RSAPrivateKey) -> None:
    """以 0600 原子写入 PKCS#8 PEM。"""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def save_public_key(path: Path, key: RSAPublicKey) -> None:
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)


def load_private_key(path: Path) -> RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, RSAPrivateKey):  # pragma: no cover - 防御性分支
        raise TypeError(f"{path} 不是 RSA 私钥")
    return key


def load_public_key(path: Path) -> RSAPublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, RSAPublicKey):  # pragma: no cover - 防御性分支
        raise TypeError(f"{path} 不是 RSA 公钥")
    return key


def public_jwk(kid: str, key: RSAPublicKey, alg: str = "RS256") -> dict[str, str]:
    numbers = key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": alg,
        "kid": kid,
        "n": _int_to_b64url(numbers.n),
        "e": _int_to_b64url(numbers.e),
    }


@dataclass(frozen=True)
class KeyStore:
    """当前签名密钥 + 对外发布的公钥集。"""

    signing_kid: str
    signing_key: RSAPrivateKey
    public_keys: dict[str, RSAPublicKey]

    @property
    def signing_public_key(self) -> RSAPublicKey:
        return self.signing_key.public_key()

    def public_key_for(self, kid: str | None) -> RSAPublicKey | None:
        if kid is None:
            return None
        return self.public_keys.get(kid)

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        keys = [public_jwk(kid, key) for kid, key in sorted(self.public_keys.items())]
        return {"keys": keys}

    @classmethod
    def load(cls, settings: Settings, *, generate_if_missing: bool = True) -> KeyStore:
        private_path = Path(settings.jwt_private_key_path)
        keys_dir = Path(settings.jwt_keys_dir)

        if not private_path.exists():
            if not generate_if_missing:
                raise FileNotFoundError(f"签名私钥不存在：{private_path}")
            save_private_key(private_path, generate_private_key())

        signing_key = load_private_key(private_path)

        public_keys: dict[str, RSAPublicKey] = {settings.jwt_kid: signing_key.public_key()}

        # 历史公钥（密钥轮换时新旧并存）
        if keys_dir.is_dir():
            for candidate in sorted(keys_dir.glob(f"*{PUBLIC_KEY_SUFFIX}")):
                kid = candidate.name[: -len(PUBLIC_KEY_SUFFIX)]
                if not kid or kid in public_keys:
                    continue
                try:
                    public_keys[kid] = load_public_key(candidate)
                except Exception:  # pragma: no cover - 坏文件不该拖垮服务
                    continue

        return cls(signing_kid=settings.jwt_kid, signing_key=signing_key, public_keys=public_keys)


_keystore_lock = threading.Lock()


@lru_cache(maxsize=4)
def _load_cached(private_key_path: str, keys_dir: str, kid: str) -> KeyStore:
    settings = Settings(
        jwt_private_key_path=private_key_path,
        jwt_keys_dir=keys_dir,
        jwt_kid=kid,
    )
    return KeyStore.load(settings)


def get_keystore(settings: Settings) -> KeyStore:
    """进程内缓存；启动时调用一次即可（并顺带在首次启动时生成密钥）。"""
    with _keystore_lock:
        return _load_cached(
            settings.jwt_private_key_path,
            settings.jwt_keys_dir,
            settings.jwt_kid,
        )


def reset_keystore_cache() -> None:
    """测试用。"""
    _load_cached.cache_clear()

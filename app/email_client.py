"""email 服务的内部客户端：只做「创建验证」与「查询验证状态」。

协议见 ``email/README.md``：内部接口要求 ``Authorization: Bearer EMAIL_INTERNAL_TOKEN``，
响应错误统一为 ``{"error": "...", "error_description": "..."}``。

这里刻意不把 email 服务的错误原文透给终端用户：注册接口只需要知道
「邮件没发出去」「服务不可用」「被限流」三类，细节留在服务端日志里。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from .config import Settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmailVerificationCreated:
    id: str
    status: str
    expires_in: int
    expires_at: str


@dataclass(frozen=True)
class EmailVerificationStatus:
    id: str
    status: str
    email: str
    expires_at: str
    decided_at: str | None = None
    decided_by: str | None = None


class EmailServiceError(RuntimeError):
    """email 服务调用失败；``kind`` 供路由层映射成稳定的 API 错误码。"""

    def __init__(
        self,
        kind: str,
        description: str,
        *,
        status_code: int | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(description)
        self.kind = kind
        self.description = description
        self.status_code = status_code
        self.retry_after = retry_after


class EmailServiceClient:
    """同步 httpx 客户端；SSO 的路由是同步函数，直接用同步客户端最省事。"""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            base_url=settings.email_service_base_url,
            timeout=settings.email_http_timeout_seconds,
            follow_redirects=False,
            # 容器内直连 email，不要被宿主机的 HTTP(S)_PROXY 影响。
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------ 内部实现

    def _headers(self) -> dict[str, str]:
        if not self._settings.email_internal_token:
            raise EmailServiceError("unavailable", "EMAIL_INTERNAL_TOKEN 未配置，注册邮箱验证不可用")
        return {
            "Authorization": f"Bearer {self._settings.email_internal_token}",
            "Accept": "application/json",
        }

    @staticmethod
    def _retry_after(response: httpx.Response) -> int | None:
        raw = response.headers.get("retry-after")
        if not raw:
            return None
        try:
            return max(0, int(raw))
        except ValueError:
            return None

    def _raise_for_response(self, response: httpx.Response) -> None:
        if response.is_success:
            return

        error = None
        description = None
        try:
            body = response.json()
            if isinstance(body, dict):
                error = body.get("error")
                description = body.get("error_description")
        except ValueError:
            pass

        logger.warning(
            "email service error status=%s error=%s path=%s",
            response.status_code,
            error or "-",
            response.request.url.path,
        )

        retry_after = self._retry_after(response)
        if response.status_code == 429:
            raise EmailServiceError(
                "rate_limited",
                str(description or "邮箱验证请求过于频繁"),
                status_code=429,
                retry_after=retry_after or 60,
            )
        if response.status_code == 502:
            raise EmailServiceError(
                "delivery_failed",
                str(description or "确认邮件发送失败"),
                status_code=502,
            )
        if response.status_code in (401, 403):
            raise EmailServiceError(
                "misconfigured",
                "EMAIL_INTERNAL_TOKEN 无效或 email 内部接口未启用",
                status_code=response.status_code,
            )
        if response.status_code == 404:
            raise EmailServiceError("not_found", "验证请求不存在", status_code=404)
        if response.status_code == 400:
            raise EmailServiceError(
                "rejected",
                str(description or "email 服务拒绝了该验证请求"),
                status_code=400,
            )
        raise EmailServiceError(
            "unavailable",
            "email 服务暂时不可用",
            status_code=response.status_code,
            retry_after=retry_after,
        )

    @staticmethod
    def _connection_error(exc: Exception) -> EmailServiceError:
        logger.warning("email service connection failed type=%s", type(exc).__name__)
        return EmailServiceError("unavailable", "连不上 email 服务")

    # ------------------------------------------------------------ 公共接口

    def create_verification(
        self,
        *,
        email: str,
        purpose: str,
        callback_url: str,
        metadata: dict[str, str],
        expires_in: int,
        app_name: str = "EliCloud",
    ) -> EmailVerificationCreated:
        payload = {
            "email": email,
            "purpose": purpose,
            "source": "sso",
            "callback_url": callback_url,
            "metadata": metadata,
            "expires_in": expires_in,
            # app_name 是 email 服务的系统变量，不能通过 variables 覆盖；
            # 模板会使用 email 服务配置里的 APP_NAME。
            "content": {"mode": "template", "template": "register"},
        }
        try:
            response = self._client.post("/v1/verify", json=payload, headers=self._headers())
        except EmailServiceError:
            raise
        except Exception as exc:  # noqa: BLE001 - 网络层一律映射成 unavailable
            raise self._connection_error(exc) from exc

        self._raise_for_response(response)
        try:
            body = response.json()
            return EmailVerificationCreated(
                id=str(body["id"]),
                status=str(body.get("status") or "pending"),
                expires_in=int(body.get("expires_in") or expires_in),
                expires_at=str(body["expires_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EmailServiceError("unavailable", "email 服务返回了无法解析的响应") from exc

    def get_verification(self, request_id: str) -> EmailVerificationStatus:
        try:
            response = self._client.get(f"/v1/verify/{request_id}", headers=self._headers())
        except EmailServiceError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise self._connection_error(exc) from exc

        self._raise_for_response(response)
        try:
            body = response.json()
            return EmailVerificationStatus(
                id=str(body["id"]),
                status=str(body["status"]),
                email=str(body.get("email") or ""),
                expires_at=str(body["expires_at"]),
                decided_at=body.get("decided_at"),
                decided_by=body.get("decided_by"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EmailServiceError("unavailable", "email 服务返回了无法解析的响应") from exc

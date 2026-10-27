"""测试用 email 服务替身。"""

from __future__ import annotations

import secrets
from datetime import timedelta

from app.email_client import (
    EmailServiceError,
    EmailVerificationCreated,
    EmailVerificationStatus,
)
from app.models import to_iso, utcnow


class FakeEmailClient:
    def __init__(self) -> None:
        self.created: list[dict[str, object]] = []
        self.statuses: dict[str, EmailVerificationStatus] = {}
        self.next_error: EmailServiceError | None = None
        self.next_status_error: EmailServiceError | None = None

    def close(self) -> None:
        pass

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
        if self.next_error is not None:
            error = self.next_error
            self.next_error = None
            raise error

        request_id = f"ev_test_{secrets.token_hex(6)}"
        created = EmailVerificationCreated(
            id=request_id,
            status="pending",
            expires_in=expires_in,
            expires_at=to_iso(utcnow() + timedelta(seconds=expires_in)),
        )
        self.created.append(
            {
                "id": request_id,
                "email": email,
                "purpose": purpose,
                "callback_url": callback_url,
                "metadata": dict(metadata),
                "expires_in": expires_in,
                "app_name": app_name,
            }
        )
        self.statuses[request_id] = EmailVerificationStatus(
            id=request_id,
            status="pending",
            email=email,
            expires_at=created.expires_at,
        )
        return created

    def get_verification(self, request_id: str) -> EmailVerificationStatus:
        if self.next_status_error is not None:
            error = self.next_status_error
            self.next_status_error = None
            raise error
        status = self.statuses.get(request_id)
        if status is None:
            raise EmailServiceError("not_found", "验证请求不存在", status_code=404)
        return status

    def approve(self, request_id: str) -> None:
        old = self.statuses[request_id]
        self.statuses[request_id] = EmailVerificationStatus(
            id=old.id,
            status="approved",
            email=old.email,
            expires_at=old.expires_at,
            decided_at=to_iso(utcnow()),
            decided_by="user",
        )

    def deny(self, request_id: str) -> None:
        old = self.statuses[request_id]
        self.statuses[request_id] = EmailVerificationStatus(
            id=old.id,
            status="denied",
            email=old.email,
            expires_at=old.expires_at,
            decided_at=to_iso(utcnow()),
            decided_by="timeout",
        )

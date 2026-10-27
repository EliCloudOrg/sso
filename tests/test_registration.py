"""注册邮箱验证：pending → 邮件确认 → 建号，以及状态/重发/取消/回调。"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from sqlalchemy import select

from app.config import get_settings
from app.db import session_scope
from app.email_client import EmailServiceError
from app.models import PendingRegistration, User, parse_iso, to_iso, utcnow

PASSWORD = "S3cret!pass1"


def unique(prefix: str = "reg") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def start(client, *, username: str | None = None, email: str | None = None):
    username = username or unique()
    email = email or f"{username}@example.com"
    response = client.post(
        "/v1/register",
        json={"username": username, "password": PASSWORD, "email": email},
    )
    return response, username, email


def callback(client, registration_id: str, *, status: str = "approved", email: str | None = None):
    stub = client.app.state.email_client
    record = next(
        item
        for item in reversed(stub.created)
        if item["metadata"].get("registration_id") == registration_id
    )
    request_id = str(record["id"])
    if status == "approved":
        stub.approve(request_id)
    else:
        stub.deny(request_id)

    payload = {
        "event": "email.verification",
        "request_id": request_id,
        "status": status,
        "reason": "user_confirm" if status == "approved" else "timeout",
        "decided_by": "user" if status == "approved" else "timeout",
        "email": email or record["email"],
        "purpose": "register",
        "source": "sso",
        "metadata": {"registration_id": registration_id},
        "verified_at": to_iso(utcnow()),
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    timestamp = int(time.time())
    signature = hmac.new(
        get_settings().email_callback_secret.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + raw,
        hashlib.sha256,
    ).hexdigest()
    return client.post(
        "/internal/email/verification",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-EliCloud-Event": "email.verification",
            "X-EliCloud-Timestamp": str(timestamp),
            "X-EliCloud-Signature": f"sha256={signature}",
            "Idempotency-Key": f"{request_id}:{status}",
        },
    )


def status(client, registration_id: str):
    return client.post("/v1/register/status", json={"registration_id": registration_id})


def pending_row(registration_id: str) -> PendingRegistration:
    with session_scope() as session:
        row = session.get(PendingRegistration, registration_id)
        assert row is not None
        session.expunge(row)
        return row


def set_sent_at_past(registration_id: str) -> None:
    with session_scope() as session:
        row = session.get(PendingRegistration, registration_id)
        assert row is not None
        row.email_sent_at = to_iso(utcnow().replace(year=2020))
        session.commit()


def set_expired(registration_id: str) -> None:
    with session_scope() as session:
        row = session.get(PendingRegistration, registration_id)
        assert row is not None
        row.expires_at = to_iso(utcnow().replace(year=2020))
        session.commit()


def test_register_returns_pending_and_calls_email(client, email_stub):
    response, username, email = start(client)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "pending"
    assert body["registration_id"].startswith("reg_")
    assert body["email_masked"].startswith(username[0]) and "@example.com" in body["email_masked"]
    assert body["resend_after"] > 0  # 刚发过信，返回剩余冷却
    assert email_stub.created[-1]["email"] == email
    assert email_stub.created[-1]["purpose"] == "register"
    assert email_stub.created[-1]["metadata"]["registration_id"] == body["registration_id"]

    row = pending_row(body["registration_id"])
    assert row.status == "pending"
    assert row.email == email
    assert row.password_hash != PASSWORD


def test_register_requires_email(client):
    response = client.post("/v1/register", json={"username": unique(), "password": PASSWORD})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_login_pending_requires_verification(client):
    response, username, _ = start(client)
    assert response.status_code == 202

    wrong = client.post("/v1/login", json={"username": username, "password": "WrongPass123"})
    assert wrong.status_code == 401
    assert wrong.json()["error"] == "invalid_grant"

    right = client.post("/v1/login", json={"username": username, "password": PASSWORD})
    assert right.status_code == 403
    assert right.json()["error"] == "email_not_verified"


def test_approved_callback_creates_user_and_status_is_verified(client):
    response, username, email = start(client)
    registration_id = response.json()["registration_id"]

    assert callback(client, registration_id).status_code == 200
    body = status(client, registration_id).json()
    assert body["status"] == "verified"
    assert body["user"]["username"] == username
    assert body["user"]["email"] == email
    assert body["user"]["email_verified"] is True

    login = client.post("/v1/login", json={"username": username, "password": PASSWORD})
    assert login.status_code == 200
    token = login.json()["access_token"]
    info = client.get("/v1/userinfo", headers={"Authorization": f"Bearer {token}"}).json()
    assert info["email"] == email
    assert info["email_verified"] is True


def test_callback_is_idempotent(client):
    response, username, _ = start(client)
    registration_id = response.json()["registration_id"]

    assert callback(client, registration_id).status_code == 200
    assert callback(client, registration_id).status_code == 200

    with session_scope() as session:
        users = session.scalars(select(User).where(User.username == username)).all()
        assert len(users) == 1


def test_callback_rejects_bad_signature(client):
    response, _, _ = start(client)
    registration_id = response.json()["registration_id"]
    response = client.post(
        "/internal/email/verification",
        content=b"{}",
        headers={
            "X-EliCloud-Event": "email.verification",
            "X-EliCloud-Timestamp": str(int(time.time())),
            "X-EliCloud-Signature": "sha256=deadbeef",
        },
    )
    assert response.status_code == 401


def test_denied_callback_expires_registration(client):
    response, username, _ = start(client)
    registration_id = response.json()["registration_id"]
    assert callback(client, registration_id, status="denied").status_code == 200

    body = status(client, registration_id).json()
    assert body["status"] == "expired"

    login = client.post("/v1/login", json={"username": username, "password": PASSWORD})
    assert login.status_code == 403


def test_status_reconciles_approved_email_without_callback(client, email_stub):
    response, username, _ = start(client)
    registration_id = response.json()["registration_id"]
    request_id = email_stub.created[-1]["id"]
    email_stub.approve(str(request_id))

    body = status(client, registration_id).json()
    assert body["status"] == "verified"
    assert body["user"]["username"] == username


def test_resend_cooldown_and_success(client):
    response, _, _ = start(client)
    registration_id = response.json()["registration_id"]

    blocked = client.post("/v1/register/resend", json={"registration_id": registration_id})
    assert blocked.status_code == 429
    assert blocked.headers.get("retry-after")

    set_sent_at_past(registration_id)
    resent = client.post("/v1/register/resend", json={"registration_id": registration_id})
    assert resent.status_code == 202, resent.text
    assert resent.json()["registration_id"] == registration_id


def test_expired_registration_can_resend(client):
    response, _, _ = start(client)
    registration_id = response.json()["registration_id"]
    set_sent_at_past(registration_id)
    set_expired(registration_id)

    assert status(client, registration_id).json()["status"] == "expired"
    resent = client.post("/v1/register/resend", json={"registration_id": registration_id})
    assert resent.status_code == 202, resent.text
    assert status(client, registration_id).json()["status"] == "pending"


def test_cancel_ignores_later_callback(client):
    response, username, _ = start(client)
    registration_id = response.json()["registration_id"]
    assert client.post("/v1/register/cancel", json={"registration_id": registration_id}).status_code == 204
    assert status(client, registration_id).status_code == 404

    # 旧邮件链接仍可能被点，但 cancelled 状态应忽略回调，不建号。
    assert callback(client, registration_id).status_code == 200
    with session_scope() as session:
        assert session.scalar(select(User).where(User.username == username)) is None


def test_email_service_failure_is_502_and_row_failed(client, email_stub):
    email_stub.next_error = EmailServiceError("delivery_failed", "smtp down", status_code=502)
    response, username, _ = start(client)
    assert response.status_code == 502
    assert response.json()["error"] == "email_delivery_failed"

    with session_scope() as session:
        row = session.scalar(
            select(PendingRegistration).where(PendingRegistration.username_lower == username.lower())
        )
        assert row is not None
        assert row.status == "failed"


def test_same_credentials_resume_pending(client, email_stub):
    response, username, email = start(client)
    first_id = response.json()["registration_id"]
    set_sent_at_past(first_id)
    resumed, _, _ = start(client, username=username, email=email)
    assert resumed.status_code == 202
    assert resumed.json()["registration_id"] == first_id
    assert len(email_stub.created) >= 2

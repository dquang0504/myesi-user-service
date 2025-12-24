import json
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import PasswordResetToken

def _pretty_json(text: str) -> str:
    try:
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except Exception:
        return text


def assert_status(r, expected: int):
    if r.status_code != expected:
        print("\n========== HTTP DEBUG ==========")
        print("URL:", str(r.request.url))
        print("METHOD:", r.request.method)
        print("REQUEST HEADERS:", dict(r.request.headers))
        # request body (nếu có)
        try:
            content = r.request.content
            if content:
                print("REQUEST BODY:", content.decode("utf-8", errors="replace"))
        except Exception:
            pass

        print("\nSTATUS:", r.status_code)
        print("RESPONSE HEADERS:", dict(r.headers))
        print("RESPONSE TEXT:\n", _pretty_json(r.text))
        print("================================\n")

    assert r.status_code == expected


@pytest.mark.asyncio
async def test_register_success(client):
    r = await client.post(
        "/api/users/register",
        json={
            "name": "Dev",
            "email": "new@example.com",
            "password": "Passw0rd!!",
            "organization_id": 1,
            "role": "developer",
            "is_active": True,
        },
    )
    assert_status(r, 201)
    assert r.json()["email"] == "new@example.com"


@pytest.mark.asyncio
async def test_login_success_sets_refresh_cookie(client, seeded_user):
    r = await client.post(
        "/api/users/login",
        json={"email": seeded_user.email, "password": "Passw0rd!!"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    # refresh_token cookie must be present
    set_cookie = r.headers.get("set-cookie", "")
    assert "refresh_token=" in set_cookie


@pytest.mark.asyncio
async def test_refresh_token_missing_cookie_401(client):
    r = await client.post("/api/users/refresh-token")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_validates_token(client, seeded_user):
    token = __import__("tests.conftest").conftest.make_access_token_for_user(
        seeded_user.id, seeded_user.email, seeded_user.role, seeded_user.organization_id
    )
    r = await client.post("/api/users/logout", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["success"] is True


@pytest.mark.asyncio
async def test_login_rejects_inactive_user(client, fake_db):
    inactive = await fake_db.seed_user(
        email="inactive@example.com",
        name="Inactive",
        password="Passw0rd!!",
        is_active=False,
    )
    r = await client.post(
        "/api/users/login",
        json={"email": inactive.email, "password": "Passw0rd!!"},
    )
    assert r.status_code == 403
    assert "inactive" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_complete_password_reset_success(client, fake_db):
    user = fake_db._users[0]
    user.is_active = False
    existing_hash = user.hashed_password
    token_plain = "invite-reset-token"
    reset = PasswordResetToken(
        user_id=user.id,
        token_hash=hashlib.sha256(token_plain.encode("utf-8")).hexdigest(),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        used=False,
    )
    fake_db._reset_tokens.append(reset)

    r = await client.post(
        "/api/users/password-reset/complete",
        json={"token": token_plain, "new_password": "NewPassw0rd!"},
    )
    assert_status(r, 200)
    assert user.hashed_password != existing_hash
    assert user.is_active is True
    assert reset.used is True
    assert reset.used_at is not None


@pytest.mark.asyncio
async def test_complete_password_reset_invalid_or_expired(client, fake_db):
    user = fake_db._users[0]
    token_plain = "expired-token-123"
    expired_token = PasswordResetToken(
        user_id=user.id,
        token_hash=hashlib.sha256(token_plain.encode("utf-8")).hexdigest(),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        used=False,
    )
    fake_db._reset_tokens.append(expired_token)

    r = await client.post(
        "/api/users/password-reset/complete",
        json={"token": token_plain, "new_password": "AnotherPass1!"},
    )
    assert r.status_code == 400

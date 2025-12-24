from datetime import datetime, timedelta, timezone

import asyncio
from types import SimpleNamespace

import pytest
from jose import jwt

from app.core.config import settings
from app.services.auth import get_current_user
from app.services.session_manager import require_active_session


class _DummyRequest:
    def __init__(self, path="/api/users/me", headers=None):
        self.headers = headers or {}
        self.url = SimpleNamespace(path=path)
        self.state = SimpleNamespace()
        self.client = SimpleNamespace(host="testclient")


def _first_non_admin(fake_db):
    return next(u for u in fake_db._users if u.role != "admin")


@pytest.mark.asyncio
async def test_interactive_request_expires_idle_session(client, fake_db):
    fake_db._org_settings[0].session_timeout = True
    user = _first_non_admin(fake_db)

    login = await client.post(
        "/api/users/login",
        json={"email": user.email, "password": "Passw0rd!!"},
    )
    assert login.status_code == 200, login.text
    body = login.json()
    access_token = body["access_token"]
    session_id = body["session_id"]
    assert session_id
    decoded = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
    assert decoded["id"] == user.id

    session = next(s for s in fake_db._sessions if str(s.id) == session_id)
    session.last_activity_at = datetime.now(timezone.utc) - timedelta(
        minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES_DEFAULT + 5
    )

    me = await client.get(
        "/api/users/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me.status_code == 401
    assert "Session expired" in me.json()["detail"]


@pytest.mark.asyncio
async def test_background_request_does_not_touch_session(client, fake_db):
    fake_db._org_settings[0].session_timeout = True
    user = _first_non_admin(fake_db)

    login = await client.post(
        "/api/users/login",
        json={"email": user.email, "password": "Passw0rd!!"},
    )
    assert login.status_code == 200, login.text
    body = login.json()
    session_id = body["session_id"]
    session = next(s for s in fake_db._sessions if str(s.id) == session_id)
    before = datetime.now(timezone.utc) - timedelta(
        minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES_DEFAULT - 1
    )
    session.last_activity_at = before

    await require_active_session(
        fake_db,
        session_id=session_id,
        principal_type="organization_user",
        principal_id=user.id,
        interactive=False,
    )
    assert session.last_activity_at == before


@pytest.mark.asyncio
async def test_session_timeout_disabled_behaves_as_legacy(client, fake_db):
    fake_db._org_settings[0].session_timeout = False
    user = _first_non_admin(fake_db)

    login = await client.post(
        "/api/users/login",
        json={"email": user.email, "password": "Passw0rd!!"},
    )
    assert login.status_code == 200, login.text
    body = login.json()
    assert body["session_id"] is None

    dummy_request = _DummyRequest()
    user_obj = await get_current_user(
        request=dummy_request, token=body["access_token"], db=fake_db
    )
    assert user_obj.id == user.id

import json
import pytest
from conftest import make_access_token_for_user

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
async def test_admin_get_all_users_forbidden_if_not_admin(client, seeded_user):
    
    token = f"Bearer {make_access_token_for_user(seeded_user)}"
    r = await client.get("/api/admin/users", headers={"Authorization": token})
    assert_status(r, 403)


@pytest.mark.asyncio
async def test_admin_get_all_users_success(client, seeded_admin, db_session):
    # create a developer user in same org
    from app.db.models import User
    from app.services.auth import get_password_hash

    u = User(
        name="Dev2",
        email="dev2@example.com",
        hashed_password=get_password_hash("Passw0rd!!"),
        role="developer",
        organization_id=seeded_admin.organization_id,
        is_active=True,
        two_factor_enabled=False,
    )
    db_session.add(u)
    await db_session.commit()

    token = f"Bearer {__import__('tests.conftest').conftest.make_access_token_for_user(seeded_admin.id, seeded_admin.email, seeded_admin.role, seeded_admin.organization_id)}"
    r = await client.get("/api/admin/users?page=1&limit=10", headers={"Authorization": token})
    assert r.status_code == 200
    body = r.json()
    assert "data" in body and "users" in body["data"]
    assert any(x["email"] == "dev2@example.com" for x in body["data"]["users"])


@pytest.mark.asyncio
async def test_admin_update_user_rejects_duplicate_email(client, seeded_admin, db_session):
    from app.db.models import User
    from app.services.auth import get_password_hash

    u1 = User(
        name="U1",
        email="u1@example.com",
        hashed_password=get_password_hash("Passw0rd!!"),
        role="developer",
        organization_id=seeded_admin.organization_id,
        is_active=True,
        two_factor_enabled=False,
    )
    u2 = User(
        name="U2",
        email="u2@example.com",
        hashed_password=get_password_hash("Passw0rd!!"),
        role="developer",
        organization_id=seeded_admin.organization_id,
        is_active=True,
        two_factor_enabled=False,
    )
    db_session.add_all([u1, u2])
    await db_session.commit()
    await db_session.refresh(u1)

    token = f"Bearer {__import__('tests.conftest').conftest.make_access_token_for_user(seeded_admin.id, seeded_admin.email, seeded_admin.role, seeded_admin.organization_id)}"
    r = await client.put(
        f"/api/admin/users/{u1.id}",
        headers={"Authorization": token},
        json={"email": "u2@example.com", "is_active": True},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "Email already exists"

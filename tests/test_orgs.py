import json
import pytest
from tests.conftest import make_access_token_for_user, make_access_token_for_owner

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
async def test_create_organization_requires_owner(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r = await client.post(
        "/api/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "NewOrg", "require_two_factor": False, "admin_email": None, "admin_name": None},
    )
    # get_current_owner should reject
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_create_organization_success_and_invite_admin(client, fake_db):
    owner = fake_db._owners[0]
    token = make_access_token_for_owner(owner)

    r = await client.post(
        "/api/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "NewOrg",
            "require_two_factor": True,
            "admin_name": "Invited Admin",
            "admin_email": "invited_admin@example.com",
        },
    )
    assert_status(r,201)
    body = r.json()
    assert body["organization"]["name"] == "NewOrg"
    assert body["invited_admin"]["email"] == "invited_admin@example.com"


@pytest.mark.asyncio
async def test_list_organizations_owner_only(client, fake_db):
    owner = fake_db._owners[0]
    token = make_access_token_for_owner(owner)

    # Seed an additional org for same owner
    await fake_db.seed_org(name="Org2", owner_id=owner.id)

    r = await client.get("/api/organizations", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert any(o["name"] == "Acme" for o in body)


@pytest.mark.asyncio
async def test_get_organization_public_endpoint(client, fake_db):
    org = fake_db._orgs[0]
    r = await client.get(f"/api/organizations/{org.id}")
    assert r.status_code == 200
    assert r.json()["name"] == org.name


@pytest.mark.asyncio
async def test_get_settings_creates_if_missing(client, fake_db):
    admin = next(u for u in fake_db._users if u.role == "admin")
    token = make_access_token_for_user(admin)
    org = fake_db._orgs[0]

    r = await client.get(f"/api/organizations/{org.id}/settings", headers={"Authorization": f"Bearer {token}"})
    assert_status(r,200)
    body = r.json()
    assert body["organization_id"] == org.id


@pytest.mark.asyncio
async def test_update_settings_requires_admin(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)
    org = fake_db._orgs[0]

    r = await client.put(
        f"/api/organizations/{org.id}/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"support_email": "support@example.com"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_update_settings_success(client, fake_db):
    admin = next(u for u in fake_db._users if u.role == "admin")
    token = make_access_token_for_user(admin)
    org = fake_db._orgs[0]

    r = await client.put(
        f"/api/organizations/{org.id}/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"support_email": "support@example.com", "require_two_factor": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["support_email"] == "support@example.com"
    assert body["require_two_factor"] is True


@pytest.mark.asyncio
async def test_toggle_notification_settings_requires_admin(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)
    org = fake_db._orgs[0]

    r = await client.patch(
        f"/api/organizations/{org.id}/settings/notifications",
        headers={"Authorization": f"Bearer {token}"},
        json={"weekly_reports": False},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_toggle_notification_settings_success(client, fake_db):
    admin = next(u for u in fake_db._users if u.role == "admin")
    token = make_access_token_for_user(admin)
    org = fake_db._orgs[0]

    r = await client.patch(
        f"/api/organizations/{org.id}/settings/notifications",
        headers={"Authorization": f"Bearer {token}"},
        json={"weekly_reports": False, "user_activity_alerts": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["weekly_reports"] is False
    assert body["user_activity_alerts"] is True


@pytest.mark.asyncio
async def test_invite_admin_to_org_owner_only_and_org_ownership_enforced(client, fake_db):
    owner = fake_db._owners[0]
    other_owner = await fake_db.seed_owner(name="Other", email="other_owner@example.com")
    other_org = await fake_db.seed_org(name="OtherOrg", owner_id=other_owner.id)

    # owner tries to invite admin to someone else's org => 403
    token = make_access_token_for_owner(owner)
    r = await client.post(
        f"/api/organizations/{other_org.id}/invite-admin",
        headers={"Authorization": f"Bearer {token}"},
        json={"admin_name": "X", "admin_email": "x@example.com"},
    )
    assert r.status_code == 403

    # correct owner => success
    token2 = make_access_token_for_owner(other_owner)
    r2 = await client.post(
        f"/api/organizations/{other_org.id}/invite-admin",
        headers={"Authorization": f"Bearer {token2}"},
        json={"admin_name": "Y", "admin_email": "y@example.com"},
    )
    assert r2.status_code == 200
    assert r2.json()["admin"]["email"] == "y@example.com"

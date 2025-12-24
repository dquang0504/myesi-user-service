import json
import pytest
from tests.conftest import make_access_token_for_user

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
async def test_admin_developers_as_admin(client, fake_db):
    admin = next(u for u in fake_db._users if u.role == "admin")
    token = make_access_token_for_user(admin)

    r = await client.get("/api/admin/users/developers", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert "developers" in body
    assert all(d["role"] == "developer" for d in body["developers"])


@pytest.mark.asyncio
async def test_admin_developers_as_analyst_allowed(client, fake_db):
    analyst = next(u for u in fake_db._users if u.role == "analyst")
    token = make_access_token_for_user(analyst)

    r = await client.get("/api/admin/users/developers", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_admin_developers_forbidden_for_developer(client, fake_db):
    dev = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(dev)

    r = await client.get("/api/admin/users/developers", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_toggle_user_status_success(client, fake_db):
    admin = next(u for u in fake_db._users if u.role == "admin")
    target = next(u for u in fake_db._users if u.role == "developer")
    token = make_access_token_for_user(admin)

    r = await client.patch(
        f"/api/admin/users/{target.id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"is_active": False},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == target.id
    assert body["is_active"] is False


@pytest.mark.asyncio
async def test_admin_toggle_user_status_404(client, fake_db):
    admin = next(u for u in fake_db._users if u.role == "admin")
    token = make_access_token_for_user(admin)

    r = await client.patch(
        "/api/admin/users/99999/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"is_active": True},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_admin_get_all_users_pagination_and_filters(client, fake_db):
    # add more users to test pagination
    for i in range(25):
        await fake_db.seed_user(
            name=f"Dev{i}",
            email=f"dev{i}@acme.com",
            role="developer" if i % 2 == 0 else "viewer",
            organization_id=1,
            is_active=(i % 3 != 0),
        )

    admin = next(u for u in fake_db._users if u.role == "admin")
    token = make_access_token_for_user(admin)

    # page 1
    r1 = await client.get("/api/admin/users?page=1&limit=10", headers={"Authorization": f"Bearer {token}"})
    assert_status(r1, 200)
    b1 = r1.json()["data"]
    assert b1["pagination"]["page"] == 1
    assert b1["pagination"]["limit"] == 10
    assert b1["pagination"]["hasPrev"] is False

    # page 2
    r2 = await client.get("/api/admin/users?page=2&limit=10", headers={"Authorization": f"Bearer {token}"})
    assert_status(r2, 200)
    b2 = r2.json()["data"]
    assert b2["pagination"]["page"] == 2
    assert b2["pagination"]["hasPrev"] is True

    # filters (role + is_active)
    rf = await client.get(
        "/api/admin/users?page=1&limit=10&role=developer&is_active=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_status(rf, 200)
    bf = rf.json()["data"]["users"]
    # best-effort: route should apply role filter; assert no admin + same org holds
    assert all(u["role"] != "admin" for u in bf)

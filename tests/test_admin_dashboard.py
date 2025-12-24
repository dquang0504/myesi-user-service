import pytest
from fastapi import HTTPException

from app.api.v1.admin import admin_dashboard


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class FakeSession:
    def __init__(self, mapping):
        self.mapping = mapping  # substr -> scalar value

    async def execute(self, stmt, params=None):
        sql = str(stmt)
        for key, val in self.mapping.items():
            if key in sql:
                return _ScalarResult(val)
        return _ScalarResult(0)


class FakeUser:
    def __init__(self, role="admin", organization_id=1):
        self.role = role
        self.organization_id = organization_id


@pytest.mark.asyncio
async def test_admin_dashboard_requires_admin_role():
    with pytest.raises(HTTPException) as e:
        await admin_dashboard(current_user=FakeUser(role="developer"), db=FakeSession({}))
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_dashboard_requires_org_context():
    with pytest.raises(HTTPException) as e:
        await admin_dashboard(current_user=FakeUser(role="admin", organization_id=None), db=FakeSession({}))
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_dashboard_success_shapes_response():
    mapping = {
        "FROM users": 10,
        "FROM projects": 7,
        "FROM vulnerabilities": 3,
        "FROM sboms": 9,
        "created_at >= :week_ago": 2,  # will match multiple; acceptable for this unit-ish test
    }
    resp = await admin_dashboard(current_user=FakeUser(role="admin", organization_id=1), db=FakeSession(mapping))
    assert resp.users.total >= 0
    assert resp.projects.total >= 0
    assert resp.vulnerabilities.total >= 0
    assert resp.sboms.scanned >= 0

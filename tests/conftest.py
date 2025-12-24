from datetime import timedelta
import uuid
import importlib
import os
import traceback
from fastapi import Request
from fastapi.exceptions import ResponseValidationError
from fastapi.responses import JSONResponse
import httpx
import pytest
import pytest_asyncio

from httpx import AsyncClient, ASGITransport
from sqlalchemy import FunctionElement, text
from sqlalchemy.sql.selectable import Select
from sqlalchemy.sql.elements import BinaryExpression, BooleanClauseList
from sqlalchemy.sql.operators import eq, ne
from sqlalchemy.sql import operators
from sqlalchemy.sql.elements import BindParameter
from sqlalchemy.sql.elements import True_, False_, Null


# ---- Ensure required env exists before importing app/settings ----
os.environ.setdefault("GITHUB_CLIENT_ID", "dummy")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "dummy")
os.environ.setdefault("GITHUB_OAUTH_REDIRECT_URI", "https://localhost:3000/github/callback")
os.environ["SECRET_KEY"] = "test-secret"
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://dummy:dummy@localhost:5432/dummy")  # not used in tests

# ---- Force reload settings module so it re-reads env vars ----
import app.core.config as cfg
importlib.reload(cfg)

# ---- Force reload auth module to ensure it uses the reloaded settings instance ----
import app.services.auth as auth_service
importlib.reload(auth_service)

from app.main import app
from app.db.session import get_db
from app.db.models import (
    PasswordResetToken,
    User,
    OwnerAccount,
    Organization,
    OrganizationSettings,
    UserTwoFactor,
    UserSession,
)

print(cfg.settings.SECRET_KEY)

@app.exception_handler(ResponseValidationError)
async def _test_response_validation_handler(request, exc: ResponseValidationError):
    # trả về chi tiết lỗi validate response (field nào thiếu / type nào sai)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "ResponseValidationError",
            "errors": exc.errors(),
        },
    )
    
@app.exception_handler(Exception)
async def _test_any_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "detail": repr(exc),
            "traceback": traceback.format_exc(),
        },
    )

# ============================================================
# Result wrappers
# ============================================================

class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _FakeScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _FakeScalars(self._rows)

    def scalar_one_or_none(self):
        if not self._rows:
            return None
        return self._rows[0]
    def scalar(self):
        if not self._rows:
            return None
        return self._rows[0]


# ============================================================
# Fake AsyncSession (in-memory)
# ============================================================

class FakeAsyncSession:
    """
    Minimal async session to satisfy app code paths (users/admin/github/orgs).
    Key: evaluate SQLAlchemy Select statements using stmt._where_criteria
    (not SQL string), so bound params work correctly.
    """

    def __init__(self):
        self._users: list[User] = []
        self._owners: list[OwnerAccount] = []
        self._orgs: list[Organization] = []
        self._org_settings: list[OrganizationSettings] = []
        self._two_factors: list[UserTwoFactor] = []
        self._reset_tokens: list[PasswordResetToken] = []
        self._sessions: list[UserSession] = []

        self._next_user_id = 1
        self._next_owner_id = 1
        self._next_org_id = 1
        self._next_reset_id = 1

        # admin dashboard counters
        self._dashboard_counters = {
            "users_total": 0,
            "users_last_week": 0,
            "projects_total": 0,
            "projects_last_week": 0,
            "vulns_total": 0,
            "vulns_last_week": 0,
            "sboms_total": 0,
            "sboms_last_week": 0,
        }

    def add_all(self, objs):
        for o in objs:
            self.add(o)
            
    async def scalar(self, stmt):
        """
        Support for SQLAlchemy AsyncSession.scalar(...)
        Many code paths use this for COUNT queries.
        """
        res = await self.execute(stmt)
        if hasattr(res, "scalar"):
            return res.scalar()
        if hasattr(res, "scalar_one_or_none"):
            return res.scalar_one_or_none()
        return None

    # ---------------- seeding helpers ----------------

    async def seed_user(
        self,
        *,
        name="Dev",
        email="dev@example.com",
        password="Passw0rd!!",
        role="developer",
        organization_id=1,
        is_active=True,
        two_factor_enabled=False,
    ) -> User:
        u = User(
            id=self._next_user_id,
            name=name,
            email=email,
            hashed_password=auth_service.get_password_hash(password),
            role=role,
            is_active=is_active,
            organization_id=organization_id,
            two_factor_enabled=two_factor_enabled,
        )
        self._next_user_id += 1
        self._users.append(u)
        return u

    async def seed_owner(
        self,
        *,
        name="Owner",
        email="owner@example.com",
        password="Passw0rd!!",
        role="owner",
        is_active=True,
        two_factor_enabled=False,
    ) -> OwnerAccount:
        o = OwnerAccount(
            id=self._next_owner_id,
            name=name,
            email=email,
            hashed_password=auth_service.get_password_hash(password),
            role=role,
            is_active=is_active,
            two_factor_enabled=two_factor_enabled,
        )
        self._next_owner_id += 1
        self._owners.append(o)
        return o

    async def seed_org(self, *, name="Acme", owner_id=1, require_two_factor=False) -> Organization:
        org = Organization(
            id=self._next_org_id,
            name=name,
            owner_id=owner_id,
            require_two_factor=require_two_factor,
            subscription_id=None,
        )
        self._next_org_id += 1
        self._orgs.append(org)
        return org

    async def seed_org_settings(
        self,
        *,
        organization_id: int,
        admin_email: str | None = None,
        require_two_factor: bool = False,
        session_timeout: bool | None = None,
    ) -> OrganizationSettings:
        s = OrganizationSettings(
            organization_id=organization_id,
            admin_email=admin_email,
            require_two_factor=require_two_factor,
            session_timeout=session_timeout if session_timeout is not None else False,
        )
        self._org_settings.append(s)
        return s

    async def seed_two_factor(self, *, user_id: int, secret="BASE32SECRET", is_enabled=False) -> UserTwoFactor:
        tf = UserTwoFactor(user_id=user_id, secret=secret, is_enabled=is_enabled)
        self._two_factors = [x for x in self._two_factors if x.user_id != user_id]
        self._two_factors.append(tf)
        return tf

    # ---------------- core session API ----------------

    async def get(self, model, pk):
        if model is User:
            return next((u for u in self._users if u.id == pk), None)
        if model is OwnerAccount:
            return next((o for o in self._owners if o.id == pk), None)
        if model is Organization:
            return next((o for o in self._orgs if o.id == pk), None)
        if model is OrganizationSettings:
            return next((s for s in self._org_settings if s.organization_id == pk), None)
        if model is UserSession:
            return next(
                (
                    s
                    for s in self._sessions
                    if str(getattr(s, "id", pk)) == str(pk)
                ),
                None,
            )
        return None

    def add(self, obj):
        if isinstance(obj, User) and obj not in self._users:
            if getattr(obj, "id", None) in (None, 0):
                obj.id = self._next_user_id
                self._next_user_id += 1
            self._users.append(obj)

        elif isinstance(obj, OwnerAccount) and obj not in self._owners:
            if getattr(obj, "id", None) in (None, 0):
                obj.id = self._next_owner_id
                self._next_owner_id += 1
            self._owners.append(obj)

        elif isinstance(obj, Organization) and obj not in self._orgs:
            if getattr(obj, "id", None) in (None, 0):
                obj.id = self._next_org_id
                self._next_org_id += 1
            self._orgs.append(obj)

        elif isinstance(obj, OrganizationSettings) and obj not in self._org_settings:
            if getattr(obj, "support_email", None) is None:
                obj.support_email = None
            if getattr(obj, "require_two_factor", None) is None:
                obj.require_two_factor = False
            if getattr(obj, "weekly_reports", None) is None:
                obj.weekly_reports = True
            if getattr(obj, "user_activity_alerts", None) is None:
                obj.user_activity_alerts = False

            self._org_settings.append(obj)

        elif isinstance(obj, UserTwoFactor):
            self._two_factors = [x for x in self._two_factors if x.user_id != obj.user_id]
            self._two_factors.append(obj)
        elif isinstance(obj, PasswordResetToken):
            if getattr(obj, "id", None) in (None, 0):
                obj.id = self._next_reset_id
                self._next_reset_id += 1
            self._reset_tokens.append(obj)
        elif isinstance(obj, UserSession):
            if getattr(obj, "id", None) in (None, 0):
                obj.id = uuid.uuid4()
            self._sessions = [s for s in self._sessions if s.id == obj.id]
            self._sessions.append(obj)

    async def flush(self):
        return

    async def commit(self):
        return

    async def refresh(self, obj):
        return

    # ---------------- SELECT evaluation helpers ----------------

    def _bind_value(self, expr):
        # BindParameter(:param)
        if isinstance(expr, BindParameter):
            return expr.value

        # SQLAlchemy boolean literals
        if isinstance(expr, True_):
            return True
        if isinstance(expr, False_):
            return False

        # NULL literal
        if isinstance(expr, Null):
            return None

        # Some SQLAlchemy literals expose .value
        if hasattr(expr, "value"):
            return expr.value

        # Fallback (raw python value or comparator)
        return expr

    def _match_user_clause(self, clause, u: User) -> bool:
        if isinstance(clause, BooleanClauseList):
            if clause.operator.__name__ == "and_":
                return all(self._match_user_clause(c, u) for c in clause.clauses)
            if clause.operator.__name__ == "or_":
                return any(self._match_user_clause(c, u) for c in clause.clauses)

        if isinstance(clause, BinaryExpression):
            key = getattr(clause.left, "key", None)
            val = self._bind_value(clause.right)
            op = clause.operator

            # --- EQ / NE core filters ---
            if key == "id":
                if op == eq:
                    return u.id == val
                if op == ne:
                    return u.id != val

            if key == "email":
                if op == eq:
                    return u.email == val
                if op == ne:
                    return u.email != val

            if key == "role":
                if op == eq:
                    return u.role == val
                if op == ne:
                    return u.role != val

            if key == "organization_id":
                if op == eq:
                    return u.organization_id == val
                if op == ne:
                    return u.organization_id != val

            if key == "is_active" and op in (eq, operators.is_):
                if isinstance(val, bool):
                    return bool(getattr(u, "is_active", False)) == val
                return getattr(u, "is_active", None) == val

            # LIKE / ILIKE used for search
            if key in ("email", "name") and "like" in op.__name__:
                needle = str(val).strip("%").lower()
                return needle in (getattr(u, key, "") or "").lower()
        

        return True
    
    def _match_org_clause(self, clause, org: Organization) -> bool:
        if isinstance(clause, BooleanClauseList):
            op_name = getattr(clause.operator, "__name__", "")
            if op_name == "and_":
                return all(self._match_org_clause(c, org) for c in clause.clauses)
            if op_name == "or_":
                return any(self._match_org_clause(c, org) for c in clause.clauses)

        if isinstance(clause, BinaryExpression):
            op = clause.operator
            op_name = getattr(op, "__name__", "")

            # ---------- CASE 1: plain column == value ----------
            left_key = getattr(clause.left, "key", None)
            if left_key:
                val = self._bind_value(clause.right)
                is_eq = (op == operators.eq) or (op_name == "eq")

                if left_key == "id" and is_eq:
                    return org.id == val
                if left_key == "owner_id" and is_eq:
                    return org.owner_id == val
                if left_key == "name" and is_eq:
                    return org.name == val

            # ---------- CASE 2: func.lower(Organization.name) == value ----------
            # left is FunctionElement: lower(<column>)
            if isinstance(clause.left, FunctionElement) and getattr(clause.left, "name", "").lower() == "lower":
                # lower() usually has 1 arg: organizations.name
                args = list(getattr(clause.left, "clauses", []))
                if args:
                    arg0 = args[0]
                    arg_key = getattr(arg0, "key", None)  # should be "name"
                    if arg_key == "name":
                        val = self._bind_value(clause.right)
                        is_eq = (op == operators.eq) or (op_name == "eq")
                        if is_eq:
                            return (org.name or "").lower() == (str(val) if val is not None else "").lower()

        return True

    def _select_users(self, stmt: Select):
        rows = list(self._users)
        for c in getattr(stmt, "_where_criteria", []):
            rows = [u for u in rows if self._match_user_clause(c, u)]

        offset = getattr(stmt, "_offset_clause", None)
        limit = getattr(stmt, "_limit_clause", None)

        if offset is not None:
            rows = rows[int(self._bind_value(offset)) :]
        if limit is not None:
            rows = rows[: int(self._bind_value(limit))]

        return rows

    def _select_owners(self, stmt: Select):
        rows = list(self._owners)
        # typically filtered by email in login for owner (if you have it)
        for c in getattr(stmt, "_where_criteria", []):
            if isinstance(c, BinaryExpression) and getattr(c.left, "key", None) == "email" and c.operator == eq:
                val = self._bind_value(c.right)
                rows = [o for o in rows if o.email == val]
        return rows

    def _select_orgs(self, stmt: Select):
        rows = list(self._orgs)
        for c in getattr(stmt, "_where_criteria", []):
            rows = [o for o in rows if self._match_org_clause(c, o)]
        return rows

    def _select_org_settings(self, stmt: Select):
        rows = list(self._org_settings)
        for c in getattr(stmt, "_where_criteria", []):
            if isinstance(c, BinaryExpression):
                key = getattr(c.left, "key", None)
                val = self._bind_value(c.right)
                if key == "organization_id" and c.operator == eq:
                    rows = [s for s in rows if s.organization_id == val]
        return rows

    def _select_two_factors(self, stmt: Select):
        rows = list(self._two_factors)
        for c in getattr(stmt, "_where_criteria", []):
            if isinstance(c, BinaryExpression):
                key = getattr(c.left, "key", None)
                val = self._bind_value(c.right)
                if key == "user_id" and c.operator == eq:
                    rows = [t for t in rows if t.user_id == val]
        return rows

    def _select_reset_tokens(self, stmt: Select):
        rows = list(self._reset_tokens)
        for c in getattr(stmt, "_where_criteria", []):
            if isinstance(c, BinaryExpression):
                key = getattr(c.left, "key", None)
                val = self._bind_value(c.right)
                if key == "token_hash" and c.operator == eq:
                    rows = [t for t in rows if t.token_hash == val]
                if key == "user_id" and c.operator == eq:
                    rows = [t for t in rows if t.user_id == val]
        return rows

    async def execute(self, stmt, params=None):
        # -------- RAW SQL for dashboard --------
        if isinstance(stmt, type(text("x"))):
            sql = str(stmt)

            if "FROM users" in sql and "created_at >=" not in sql:
                return _FakeScalarResult(self._dashboard_counters["users_total"])
            if "FROM users" in sql and "created_at >=" in sql:
                return _FakeScalarResult(self._dashboard_counters["users_last_week"])

            if "FROM projects" in sql and "created_at >=" not in sql:
                return _FakeScalarResult(self._dashboard_counters["projects_total"])
            if "FROM projects" in sql and "created_at >=" in sql:
                return _FakeScalarResult(self._dashboard_counters["projects_last_week"])

            if "FROM vulnerabilities" in sql and "created_at >=" not in sql:
                return _FakeScalarResult(self._dashboard_counters["vulns_total"])
            if "FROM vulnerabilities" in sql and "created_at >=" in sql:
                return _FakeScalarResult(self._dashboard_counters["vulns_last_week"])

            if "FROM sboms" in sql and "created_at >=" not in sql:
                return _FakeScalarResult(self._dashboard_counters["sboms_total"])
            if "FROM sboms" in sql and "created_at >=" in sql:
                return _FakeScalarResult(self._dashboard_counters["sboms_last_week"])

            return _FakeScalarResult(0)

        # -------- SELECT(...) --------
        if isinstance(stmt, Select):
            sql = str(stmt).lower()

            # COUNT(...) patterns
            if "count(" in sql:
                # Common: select(func.count()).select_from(subquery)
                froms = list(getattr(stmt, "froms", []))
                if froms and hasattr(froms[0], "element"):
                    inner = froms[0].element
                    if isinstance(inner, Select) and "from users" in str(inner).lower():
                        return _FakeScalarResult(len(self._select_users(inner)))
                # direct count from users
                if "from users" in sql:
                    return _FakeScalarResult(len(self._select_users(stmt)))
                return _FakeScalarResult(0)

            if "from users" in sql:
                return _FakeResult(self._select_users(stmt))

            if "from owner_accounts" in sql:
                return _FakeResult(self._select_owners(stmt))

            if "from organizations" in sql:
                return _FakeResult(self._select_orgs(stmt))

            if "from organization_settings" in sql:
                return _FakeResult(self._select_org_settings(stmt))

            if "from password_reset_tokens" in sql:
                return _FakeResult(self._select_reset_tokens(stmt))

            if "from user_two_factors" in sql:
                return _FakeResult(self._select_two_factors(stmt))

        return _FakeResult([])


# ============================================================
# Auth helpers (keep backward-compat with your tests)
# ============================================================

def _resolve_identity(entity, email, role, organization_id):
    if hasattr(entity, "id"):
        principal_id = entity.id
        email = email or getattr(entity, "email", None)
        role = role or getattr(entity, "role", None)
        if organization_id is None and hasattr(entity, "organization_id"):
            organization_id = getattr(entity, "organization_id", None)
    else:
        principal_id = entity

    email = email or f"user{principal_id}@example.test"
    role = role or "developer"
    return principal_id, email, role, organization_id


def make_access_token_for_user(
    user_or_id, email=None, role=None, organization_id=None, session_id=None
):
    user_id, email, role, organization_id = _resolve_identity(
        user_or_id, email, role, organization_id
    )
    return auth_service.create_access_token(
        user_id=user_id,
        sub=email,
        role=role,
        organization_id=organization_id,
        account_type="organization_user",
        expires_delta=timedelta(days=365),
        session_id=session_id,
    )


def make_access_token_for_owner(owner_or_id, email=None, role="owner"):
    owner_id, email, role, _ = _resolve_identity(owner_or_id, email, role, organization_id=None)
    return auth_service.create_access_token(
        user_id=owner_id,
        sub=email,
        role=role or "owner",
        organization_id=None,
        account_type="owner",
        expires_delta=timedelta(days=365),
        session_id=None,
    )


# ============================================================
# Fixtures
# ============================================================

@pytest_asyncio.fixture
async def fake_db():
    db = FakeAsyncSession()

    owner = await db.seed_owner(name="Owner", email="owner@example.com")
    org = await db.seed_org(name="Acme", owner_id=owner.id, require_two_factor=False)
    await db.seed_org_settings(
        organization_id=org.id,
        require_two_factor=False,
        session_timeout=False,
    )

    await db.seed_user(name="Admin", email="admin@acme.com", role="admin", organization_id=org.id)
    await db.seed_user(name="Dev", email="dev@acme.com", role="developer", organization_id=org.id)
    await db.seed_user(name="Analyst", email="analyst@acme.com", role="analyst", organization_id=org.id)

    db._dashboard_counters.update(
        users_total=3,
        users_last_week=1,
        projects_total=2,
        projects_last_week=1,
        vulns_total=5,
        vulns_last_week=2,
        sboms_total=4,
        sboms_last_week=1,
    )
    return db


@pytest.fixture
def seeded_admin(fake_db):
    return next(u for u in fake_db._users if u.role == "admin")


@pytest.fixture
def seeded_user(fake_db):
    # first non-admin
    return next(u for u in fake_db._users if u.role != "admin")


@pytest.fixture
def db_session(fake_db):
    return fake_db


@pytest_asyncio.fixture
async def client(fake_db):
    async def _override_get_db():
        yield fake_db

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app, raise_app_exceptions=False)

    try:
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            follow_redirects=True,
        ) as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()

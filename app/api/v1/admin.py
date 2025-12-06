from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from app.db.session import get_db, AsyncSession
from app.db.models import User
from app.schemas.admin import DashboardStatsResponse, DashboardFieldTrend, SBOMField
from app.schemas.user import UserUpdate
from sqlalchemy import or_, select, func, text

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ----- ADMIN DASHBOARD -----
@router.get("/dashboard", response_model=DashboardStatsResponse)
async def admin_dashboard(db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    # -------------------------
    # USERS
    # -------------------------
    total_users = (await db.execute(text("SELECT COUNT(*) FROM users"))).scalar() or 0

    users_last_week = (
        await db.execute(
            text("SELECT COUNT(*) FROM users WHERE created_at >= :week_ago"),
            {"week_ago": week_ago},
        )
    ).scalar() or 0

    users_stat = DashboardFieldTrend(
        total=total_users,
        change=users_last_week,
        trend="up" if users_last_week >= 0 else "down",
    )

    # -------------------------
    # PROJECTS
    # -------------------------
    total_projects = (
        await db.execute(text("SELECT COUNT(*) FROM projects"))
    ).scalar() or 0

    projects_last_week = (
        await db.execute(
            text("SELECT COUNT(*) FROM projects WHERE created_at >= :week_ago"),
            {"week_ago": week_ago},
        )
    ).scalar() or 0

    projects_stat = DashboardFieldTrend(
        total=total_projects,
        change=projects_last_week,
        trend="up" if projects_last_week >= 0 else "down",
    )

    # -------------------------
    # VULNERABILITIES
    # -------------------------
    total_vulns = (
        await db.execute(
            text("SELECT COUNT(*) FROM vulnerabilities WHERE is_active = TRUE")
        )
    ).scalar() or 0

    vulns_last_week = (
        await db.execute(
            text(
                "SELECT COUNT(*) FROM vulnerabilities "
                "WHERE created_at >= :week_ago AND is_active = TRUE"
            ),
            {"week_ago": week_ago},
        )
    ).scalar() or 0

    vulns_stat = DashboardFieldTrend(
        total=total_vulns,
        change=vulns_last_week,
        trend="up" if vulns_last_week >= 0 else "down",
    )

    # -------------------------
    # SBOMS
    # -------------------------
    total_sboms = (await db.execute(text("SELECT COUNT(*) FROM sboms"))).scalar() or 0

    sboms_last_week = (
        await db.execute(
            text("SELECT COUNT(*) FROM sboms " "WHERE created_at >= :week_ago"),
            {"week_ago": week_ago},
        )
    ).scalar() or 0

    sboms_stat = SBOMField(
        scanned=total_sboms,
        change=sboms_last_week,
    )

    # -------------------------
    # RETURN
    # -------------------------
    return DashboardStatsResponse(
        users=users_stat,
        projects=projects_stat,
        vulnerabilities=vulns_stat,
        sboms=sboms_stat,
    )


# ----- ADMIN GET ALL USERS -----
@router.get("/users")
async def get_all_users(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    is_active: bool = Query(None),
):
    """
    Retrieve all users with pagination + filters (excluding admins)
    """

    # Base query
    stmt = select(User).where(User.role != "admin")

    # Search by name or email
    if search:
        stmt = stmt.where(
            or_(
                User.email.ilike(f"%{search}%"),
                (
                    getattr(User, "name", User.email).ilike(f"%{search}%")
                    if hasattr(User, "name")
                    else False
                ),
            )
        )

    # Filter by role
    if role:
        stmt = stmt.where(User.role == role)

    # Filter by status
    if is_active is not None and hasattr(User, "is_active"):
        stmt = stmt.where(User.is_active == is_active)

    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    # Pagination
    stmt = stmt.offset((page - 1) * limit).limit(limit)
    result = await db.execute(stmt)
    users = result.scalars().all()

    if not users:
        return {
            "data": {
                "users": [],
                "pagination": {
                    "total": 0,
                    "page": page,
                    "limit": limit,
                    "totalPages": 0,
                    "hasNext": False,
                    "hasPrev": page > 1,
                },
            }
        }

    # Build user list
    user_list = [
        {
            "id": u.id,
            "name": getattr(u, "name", None),
            "email": u.email,
            "role": u.role,
            "is_active": getattr(u, "is_active", True),
            "createdAt": str(getattr(u, "created_at", "")),
            "lastLogin": str(getattr(u, "last_login", "")),
        }
        for u in users
    ]

    # Pagination info
    pagination = {
        "total": total,
        "page": page,
        "limit": limit,
        "totalPages": (total + limit - 1) // limit,
        "hasNext": page * limit < total,
        "hasPrev": page > 1,
    }

    return {"data": {"users": user_list, "pagination": pagination}}


# ----- ADMIN GET DEVELOPERS ONLY -----
@router.get("/users/developers")
async def get_developers(db: AsyncSession = Depends(get_db)):
    """
    Return list of users where role = 'developer'
    """
    stmt = select(User).where(User.role == "developer")

    result = await db.execute(stmt)
    users = result.scalars().all()

    devs = [
        {
            "id": u.id,
            "name": getattr(u, "name", None),
            "email": u.email,
            "role": u.role,
            "is_active": getattr(u, "is_active", True),
        }
        for u in users
    ]

    return {"developers": devs}


# ----- ADMIN UPDATE USER -----
@router.put("/users/{user_id}")
async def update_user(
    user_id: int,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update user information (name, email, role, status).
    Only accessible by admin.
    """

    # Find user (excluding admins)
    result = await db.execute(
        select(User).where(User.id == user_id, User.role != "admin")
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=404, detail="User not found or cannot update admin account"
        )

    # Update provided fields only
    update_data = payload.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    # Check email uniqueness
    if "email" in update_data:
        result = await db.execute(
            select(User)
            .where(User.email == update_data["email"])
            .where(User.id != user_id)
        )
        existing_user = result.scalar_one_or_none()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already exists")

    for field, value in update_data.items():
        setattr(user, field, value)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


# ----- ADMIN TOGGLE USER STATUS -----
@router.patch("/users/{user_id}/status")
async def toggle_user_status(
    user_id: int,
    is_active: bool = Body(..., embed=True),
    db: AsyncSession = Depends(get_db),
):
    """
    Toggle or set user status (is_active).
    Only non-admin users can be updated.
    Body: {"is_active": true/false}
    """

    # Find user (excluding admins)
    result = await db.execute(
        select(User).where(User.id == user_id, User.role != "admin")
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found or cannot update admin account",
        )

    # Update status
    if not hasattr(user, "is_active"):
        raise HTTPException(
            status_code=400,
            detail="User model does not support is_active field",
        )

    user.is_active = is_active

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {
        "id": user.id,
        "name": getattr(user, "name", None),
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "createdAt": str(getattr(user, "created_at", "")),
        "lastLogin": str(getattr(user, "last_login", "")),
    }

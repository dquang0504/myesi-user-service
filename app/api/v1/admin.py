from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from app.db.session import get_db, AsyncSession
from app.db.models import User
from app.schemas.admin import DashboardStatsResponse, DashboardFieldTrend, SBOMField
from app.schemas.user import UserUpdate
from sqlalchemy import or_, select, func, text
from app.services.auth import get_current_user

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ----- ADMIN DASHBOARD -----
@router.get("/dashboard", response_model=DashboardStatsResponse)
async def admin_dashboard(
    current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    if current_user.organization_id is None:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required for admin dashboard",
        )
    org_id = current_user.organization_id
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    # -------------------------
    # USERS
    # -------------------------
    total_users = (
        await db.execute(
            text("SELECT COUNT(*) FROM users WHERE organization_id = :org_id"),
            {"org_id": org_id},
        )
    ).scalar() or 0

    users_last_week = (
        await db.execute(
            text(
                "SELECT COUNT(*) FROM users WHERE organization_id = :org_id AND created_at >= :week_ago"
            ),
            {"org_id": org_id, "week_ago": week_ago},
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
        await db.execute(
            text(
                "SELECT COUNT(*) FROM projects WHERE organization_id = :org_id AND is_archived = false"
            ),
            {"org_id": org_id},
        )
    ).scalar() or 0

    projects_last_week = (
        await db.execute(
            text(
                "SELECT COUNT(*) FROM projects WHERE organization_id = :org_id AND created_at >= :week_ago AND is_archived = false"
            ),
            {"org_id": org_id, "week_ago": week_ago},
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
            text(
                "SELECT COUNT(*) FROM vulnerabilities v JOIN projects p ON v.project_id = p.id WHERE is_active = TRUE AND p.organization_id = :org_id"
            ),
            {"org_id": org_id},
        )
    ).scalar() or 0

    vulns_last_week = (
        await db.execute(
            text(
                "SELECT COUNT(*) FROM vulnerabilities v JOIN projects p ON v.project_id = p.id "
                "WHERE is_active = TRUE AND p.organization_id = :org_id AND v.created_at >= :week_ago"
            ),
            {"org_id": org_id, "week_ago": week_ago},
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
    total_sboms = (
        await db.execute(
            text(
                "SELECT COUNT(*) FROM sboms s JOIN projects p ON s.project_id = p.id WHERE p.organization_id = :org_id"
            ),
            {"org_id": org_id},
        )
    ).scalar() or 0

    sboms_last_week = (
        await db.execute(
            text(
                "SELECT COUNT(*) FROM sboms s JOIN projects p ON s.project_id = p.id WHERE p.organization_id = :org_id AND s.created_at >= :week_ago "
            ),
            {"org_id": org_id, "week_ago": week_ago},
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
    current_user=Depends(get_current_user),
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

    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    # Base query
    stmt = select(User).where(
        User.role != "admin",
        User.organization_id == current_user.organization_id,
    )

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


@router.get("/users/developers")
async def get_developers(
    current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """
    Return list of users where role = 'developer'
    """
    if current_user.role != "admin" and current_user.role != "analyst":
        raise HTTPException(status_code=403, detail="Admin role required")

    stmt = select(User).where(
        User.role == "developer",
        User.organization_id == current_user.organization_id,
    )

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
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update user information (name, email, role, status).
    Only accessible by admin.
    """

    # Find user (excluding admins)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.role != "admin",
            User.organization_id == current_user.organization_id,
        )
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
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Toggle or set user status (is_active).
    Only non-admin users can be updated.
    Body: {"is_active": true/false}
    """

    # Find user (excluding admins)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.role != "admin",
            User.organization_id == current_user.organization_id,
        )
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

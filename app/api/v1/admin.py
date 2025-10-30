from operator import or_
from typing import Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db import session as db_session
from app.db.models import User
from app.schemas.user import UserUpdate

router = APIRouter(prefix="/api/admin", tags=["admin"])


def get_db():
    db = db_session.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ----- ADMIN DASHBOARD -----
@router.get("/dashboard")
def admin_dashboard():
    """
    Simple admin dashboard endpoint.
    Only accessible through API Gateway (role=admin).
    """
    return {"message": "Welcome to Admin Dashboard — only admins can see this."}


# ----- ADMIN GET ALL USERS -----
@router.get("/users")
def get_all_users(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """
    Retrieve all users with pagination + filters
    """

    # Base query
    query = db.query(User).filter(User.role != "admin")

    # Search by name or email
    if search:
        query = query.filter(
            or_(
                User.email.ilike(f"%{search}%"),
                getattr(User, "name", None).ilike(f"%{search}%")
                if hasattr(User, "name")
                else False,
            )
        )

    # Filter by role
    if role:
        query = query.filter(User.role == role)

    # Filter by status (if field exists)
    if status and hasattr(User, "status"):
        query = query.filter(User.status == status)

    # Count total
    total = query.count()

    # Pagination
    users = query.offset((page - 1) * limit).limit(limit).all()

    if not users:
        raise HTTPException(status_code=404, detail="No users found")

    # Build user list
    user_list = [
        {
            "id": u.id,
            "name": getattr(u, "name", None),
            "email": u.email,
            "role": u.role,
            "status": getattr(u, "status", "active"),
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

# ----- ADMIN UPDATE USER -----
@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
):
    """
    Update user information (name, email, role, status).
    Only accessible by admin.
    """

   # Find user (excluding admins)
    user = db.query(User).filter(User.id == user_id, User.role != "admin").first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found or cannot update admin account")

    # Update provided fields only
    update_data = payload.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    if "email" in update_data:
        existing_user = db.query(User).filter(User.email == update_data["email"], User.id != user_id).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already exists")

    for field, value in update_data.items():
        setattr(user, field, value)

    db.add(user)
    db.commit()
    db.refresh(user)

    return user

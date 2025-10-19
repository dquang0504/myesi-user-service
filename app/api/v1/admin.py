from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db import session as db_session
from app.db.models import User

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
def get_all_users(db: Session = Depends(get_db)):
    """
    Retrieve all users in the database.
    """
    users = db.query(User).all()
    if not users:
        raise HTTPException(status_code=404, detail="No users found")
    return [
        {"id": u.id, "email": u.email, "role": u.role}
        for u in users
    ]
from fastapi import APIRouter, Depends, Request, Response, status, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.db import session as db_session
from app.db.models import User
from app.schemas.user import LoginResponse, UserCreate, UserLogin, UserOut, Token
from app.services.auth import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    get_current_user,
    get_password_hash,
    verify_password,
)
from app.core.config import settings

router = APIRouter(prefix="/api/users", tags=["users"])


def get_db():
    db = db_session.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user account.
    - Check if email already exists.
    - Hash password before storing.
    """
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(payload.password)

    new_user = User(
        name=payload.name,
        email=payload.email,
        hashed_password=hashed_pw,
        role=payload.role or "developer",
        status=payload.status or "active",
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=LoginResponse)
def login(payload: UserLogin, response: Response, db: Session = Depends(get_db)):
    """
    Authenticate user and return access + refresh tokens.
    """
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)

    # === Access token ===
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        sub=user.email, role=user.role, expires_delta=access_token_expires
    )

    # === Refresh token ===
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        sub=user.email, expires_delta=refresh_token_expires
    )
    
    print("This is refresh token: ",refresh_token)

    # === Set HttpOnly cookie ===
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=refresh_token_expires.total_seconds(),
        path="/",
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "status": user.status,
            "created_at": getattr(user, "created_at", None),
            "last_login": user.last_login,
        },
    }
    
@router.post("/refresh-token", response_model=Token)
def refresh_access_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Refresh access token using refresh token from cookie.
    """
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    token_data = decode_refresh_token(refresh_token)

    user = db.query(User).filter(User.email == token_data.sub).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Create new access token
    new_access_token = create_access_token(
        sub=user.email,
        role=user.role,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout")
def logout(current_user=Depends(get_current_user)):
    """
    Handle user logout.
    (Stateless JWT => client only needs to delete token.)
    """
    try:
        return{"success": True, "message": "Logout successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")

@router.get("/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    """
    Return current logged-in user info.
    """
    return current_user

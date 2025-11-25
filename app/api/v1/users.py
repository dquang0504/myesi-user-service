import logging
from fastapi import APIRouter, Depends, Request, Response, status, HTTPException
from datetime import datetime, timedelta
from app.db.session import get_db, AsyncSession
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
from sqlalchemy.future import select
from sqlalchemy.exc import DBAPIError

router = APIRouter(prefix="/api/users", tags=["users"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = get_password_hash(payload.password)

    new_user = User(
        name=payload.name,
        email=payload.email,
        hashed_password=hashed_pw,
        role=payload.role or "developer",
        organization_id=payload.organization_id,
        is_active=payload.is_active,
    )

    db.add(new_user)

    try:
        await db.commit()

    except DBAPIError as e:
        msg = str(e.orig)

        # CHUẨN NHẤT: match substring từ PostgreSQL trigger
        if "User limit exceeded" in msg:
            raise HTTPException(
                status_code=429,
                detail="User limit exceeded for your subscription plan. Please upgrade to a better plan to add more users!",
            )

        raise HTTPException(status_code=500, detail="Database error")

    await db.refresh(new_user)
    return new_user


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: UserLogin, response: Response, db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return access + refresh tokens.
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(
            status_code=403, detail="User is disabled. Please contact an admin!"
        )

    # Update last login
    user.last_login = datetime.utcnow()
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # === Access token ===
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        user_id=user.id,
        sub=user.email,
        role=user.role,
        organization_id=user.organization_id,
        expires_delta=access_token_expires,
    )

    # === Refresh token ===
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        sub=user.email, expires_delta=refresh_token_expires
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=refresh_token_expires.total_seconds(),
        path="/",
    )

    # --- DEBUG LOG ---
    logging.warning(f"[DEBUG] Set refresh_token cookie: {refresh_token}")

    # --- Optional: inspect all cookies sent in response headers ---
    for k, v in response.headers.items():
        if k.lower() == "set-cookie":
            logging.warning(f"[DEBUG] Response header set-cookie: {v}")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": getattr(user, "created_at", None),
            "last_login": user.last_login,
            "organization_id": user.organization_id,
        },
    }


@router.post("/refresh-token", response_model=Token)
async def refresh_access_token(
    request: Request, response: Response, db: AsyncSession = Depends(get_db)
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    token_data = decode_refresh_token(refresh_token)

    result = await db.execute(select(User).where(User.email == token_data.sub))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    new_access_token = create_access_token(
        user_id=user.id,
        sub=user.email,
        role=user.role,
        organization_id=user.organization_id,
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
        return {"success": True, "message": "Logout successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")


@router.get("/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    """
    Return current logged-in user info.
    """
    return current_user

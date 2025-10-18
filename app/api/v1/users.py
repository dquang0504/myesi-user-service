from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session
from datetime import timedelta
from app.db import session as db_session
from app.db.models import User
from app.schemas.user import UserCreate, UserOut, Token
from app.services.auth import (
    get_current_user,
    get_password_hash,
    verify_password,
    create_access_token,
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
    print(hashed_pw)
    new_user = User(email=payload.email, hashed_password=hashed_pw, role="developer")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.post("/login", response_model=Token)
def login(payload: UserCreate, db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT access token.
    """
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        print(payload.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.hashed_password):
        print(payload.password)
        print(user.hashed_password)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        sub=user.email, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    """
    Return current logged-in user info.
    """
    return current_user

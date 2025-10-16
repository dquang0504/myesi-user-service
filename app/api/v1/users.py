from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import session as db_session
from app.schemas.user import UserCreate, UserOut, Token
from app.services.auth import (
    get_current_user,
    # get_password_hash,
    # verify_password,
    # create_access_token,
)

router = APIRouter(prefix="/api/users", tags=["users"])


def get_db():
    db = db_session.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/register", response_model=UserOut)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    # check exists, hash pass, create user
    ...


@router.post("/login", response_model=Token)
def login():
    # validate credentials, return JWT
    ...


@router.get("/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    return current_user

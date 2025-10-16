from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db import session as db_session
from app.db.models import User
from app.schemas.user import TokenData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(sub: str, expires_delta: timedelta | None = None):
    to_encode = {"sub": sub}
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        sub: str = payload.get("sub")
        if sub is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
            )
        return TokenData(sub=sub, exp=payload.get("exp"))
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(db_session.SessionLocal)
) -> User:
    token_data = decode_access_token(token)
    user = db.query(User).filter(User.email == token_data.sub).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    return user

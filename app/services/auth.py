from datetime import datetime, timedelta, timezone
import logging
from typing import Literal
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from app.core.config import settings
from app.db.models import OwnerAccount, OrganizationSettings, User
from app.schemas.user import TokenData
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.services.session_manager import is_interactive_request, require_active_session

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")

AccountType = Literal["organization_user", "owner"]


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    user_id: int,
    sub: str,
    role: str,
    organization_id: int | None,
    account_type: AccountType,
    expires_delta: timedelta | None = None,
    session_id: str | None = None,
):
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode = {
        "id": user_id,
        "sub": sub,
        "role": role,
        "organization_id": organization_id,
        "account_type": account_type,
        "exp": int(expire.timestamp()),
    }
    if session_id:
        to_encode["sid"] = session_id

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


logger = logging.getLogger(__name__)


def decode_access_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        sub: str | None = payload.get("sub")
        account_type: str | None = payload.get("account_type")
        if not sub or account_type not in {"organization_user", "owner"}:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
        return TokenData(
            sub=sub,
            exp=payload.get("exp"),
            id=payload.get("id"),
            role=payload.get("role"),
            organization_id=payload.get("organization_id"),
            account_type=account_type,
            sid=payload.get("sid"),
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    token_data = decode_access_token(token)
    if token_data.account_type != "organization_user" or token_data.id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization account required",
        )

    user = await db.get(User, token_data.id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    enforce_idle = False
    if user.organization_id:
        org_settings = await db.get(OrganizationSettings, user.organization_id)
        enforce_idle = bool(org_settings and org_settings.session_timeout)

    if enforce_idle:
        if not token_data.sid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid session",
            )
        interactive = is_interactive_request(request)
        await require_active_session(
            db,
            session_id=token_data.sid,
            principal_type="organization_user",
            principal_id=user.id,
            interactive=interactive,
        )
        request.state.session_id = token_data.sid
    else:
        request.state.session_id = token_data.sid

    return user


async def get_current_owner(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> OwnerAccount:
    token_data = decode_access_token(token)
    if token_data.account_type != "owner" or token_data.id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Owner credentials required"
        )

    owner = await db.get(OwnerAccount, token_data.id)
    if not owner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Owner not found"
        )
    request.state.session_id = token_data.sid
    return owner


def create_refresh_token(
    *,
    sub: str,
    account_type: AccountType,
    expires_delta: timedelta | None = None,
    session_id: str | None = None,
):
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode = {
        "sub": sub,
        "account_type": account_type,
        "exp": int(expire.timestamp()),
        "type": "refresh",
    }
    if session_id:
        to_encode["sid"] = session_id
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


def decode_refresh_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token type",
            )
        sub: str | None = payload.get("sub")
        account_type: str | None = payload.get("account_type")
        if not sub or account_type not in {"organization_user", "owner"}:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
            )
        return TokenData(
            sub=sub,
            exp=payload.get("exp"),
            account_type=account_type,
            sid=payload.get("sid"),
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

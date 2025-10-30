from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


# ---------------------------
# Request model
# ---------------------------
class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=255)
    role: Optional[str] = "developer"
    status: Optional[str] = "active"


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=255)


class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    status: Optional[str] = None


# ---------------------------
# Response models
# ---------------------------
class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str
    status: str
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = 15 * 60


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: Optional[int] = 15 * 60
    user: UserOut

    class Config:
        from_attributes = True


class TokenData(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None

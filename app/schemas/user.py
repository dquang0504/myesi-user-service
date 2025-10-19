from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=255)
    role: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=255)


class UserOut(BaseModel):
    id: int
    email: EmailStr
    is_active: bool = True
    role: Optional[str] = "developer"
    created_at: Optional[datetime] = None

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = 15 * 60


class TokenData(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None

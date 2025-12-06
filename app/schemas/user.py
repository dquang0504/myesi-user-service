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
    organization_id: int
    role: Optional[str] = "developer"
    is_active: bool


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=255)
    two_factor_code: Optional[str] = None


class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: bool


class UserProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    email: Optional[EmailStr] = None
    current_password: Optional[str] = Field(None, min_length=8, max_length=255)
    current_password: Optional[str] = Field(None, min_length=8, max_length=255)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=255)
    new_password: str = Field(..., min_length=8, max_length=255)


class TwoFactorVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


class TwoFactorSetupResponse(BaseModel):
    secret: str
    otp_auth_url: str


# ---------------------------
# Response models
# ---------------------------
class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str
    is_active: bool
    organization_id: Optional[int] = None
    two_factor_enabled: bool
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = 15 * 60


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: Optional[int] = 15 * 60
    user: UserOut
    two_factor_required: Optional[bool] = False

    class Config:
        from_attributes = True


class TokenData(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None
    id: Optional[int] = None
    role: Optional[str] = None
    organization_id: Optional[int] = None
    account_type: Optional[str] = None

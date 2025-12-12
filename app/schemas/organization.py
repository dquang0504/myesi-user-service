from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class OrganizationOut(BaseModel):
    id: int
    name: str
    subscription_id: Optional[int] = None
    owner_id: int
    require_two_factor: bool = False
    created_at: Optional[datetime] = None

    class Config:
        orm_mode = True


class OrganizationSettingsOut(BaseModel):
    organization_id: int
    admin_email: Optional[EmailStr] = None
    support_email: Optional[EmailStr] = None
    require_two_factor: bool = False
    password_expiry: bool = True
    session_timeout: bool = True
    ip_whitelisting: bool = False
    email_notifications: bool = True
    vulnerability_alerts: bool = True
    weekly_reports: bool = True
    user_activity_alerts: bool = False

    class Config:
        orm_mode = True


class OrganizationSettingsUpdate(BaseModel):
    admin_email: Optional[EmailStr] = None
    support_email: Optional[EmailStr] = None
    require_two_factor: Optional[bool] = None
    password_expiry: Optional[bool] = None
    session_timeout: Optional[bool] = None
    ip_whitelisting: Optional[bool] = None
    email_notifications: Optional[bool] = None
    vulnerability_alerts: Optional[bool] = None
    weekly_reports: Optional[bool] = None
    user_activity_alerts: Optional[bool] = None
    organization_name: Optional[str] = None


class NotificationSettingsUpdate(BaseModel):
    email_notifications: Optional[bool] = None
    vulnerability_alerts: Optional[bool] = None
    weekly_reports: Optional[bool] = None
    user_activity_alerts: Optional[bool] = None


class OrganizationCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    require_two_factor: bool = False
    admin_name: Optional[str] = None
    admin_email: Optional[EmailStr] = None


class AdminInviteResult(BaseModel):
    id: int
    name: Optional[str] = None
    email: EmailStr
    temporary_password: str


class OrganizationCreateResponse(BaseModel):
    organization: OrganizationOut
    invited_admin: Optional[AdminInviteResult] = None


class OrganizationInviteAdminRequest(BaseModel):
    admin_name: Optional[str] = None
    admin_email: EmailStr


class OrganizationInviteAdminResponse(BaseModel):
    admin: AdminInviteResult

import logging
import secrets
import string
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Request, Response, status, HTTPException
from sqlalchemy import func
from app.db.session import get_db, AsyncSession
from app.db.models import (
    OwnerAccount,
    User,
    Organization,
    UserTwoFactor,
    OrganizationSettings,
)
from app.schemas.user import (
    ChangePasswordRequest,
    LoginResponse,
    Token,
    UserCreate,
    UserLogin,
    UserOut,
    UserProfileUpdate,
    TwoFactorSetupResponse,
    TwoFactorVerifyRequest,
)
from app.schemas.organization import (
    OrganizationOut,
    OrganizationSettingsOut,
    OrganizationSettingsUpdate,
    OrganizationCreateRequest,
    OrganizationCreateResponse,
    OrganizationInviteAdminRequest,
    OrganizationInviteAdminResponse,
    AdminInviteResult,
    NotificationSettingsUpdate,
)
from app.services.auth import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    get_current_owner,
    get_current_user,
    get_password_hash,
    oauth2_scheme,
    verify_password,
)
from app.core.config import settings
from sqlalchemy.future import select
from sqlalchemy.exc import DBAPIError
import pyotp
from app.services.notification_client import publish_event

router = APIRouter(prefix="/api/users", tags=["users"])
org_router = APIRouter(prefix="/api/organizations", tags=["organizations"])


def _generate_temporary_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


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
    payload: UserLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and return access + refresh tokens.
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user:
        if not verify_password(payload.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not user.is_active:
            raise HTTPException(
                status_code=403, detail="User is disabled. Please contact an admin!"
            )

        organization = await db.get(Organization, user.organization_id)
        org_settings = await db.get(OrganizationSettings, user.organization_id)
        enforce_two_factor = bool(organization and organization.require_two_factor)
        requires_two_factor = enforce_two_factor and not user.two_factor_enabled

        if enforce_two_factor and user.two_factor_enabled:
            if not payload.two_factor_code:
                raise HTTPException(
                    status_code=403, detail="Two-factor code is required."
                )
            result = await db.execute(
                select(UserTwoFactor).where(UserTwoFactor.user_id == user.id)
            )
            two_factor = result.scalar_one_or_none()
            if not two_factor:
                raise HTTPException(
                    status_code=403,
                    detail="Two-factor setup appears lost. Please re-run the setup flow.",
                )
            totp = pyotp.TOTP(two_factor.secret)
            if not totp.verify(payload.two_factor_code, valid_window=1):
                raise HTTPException(status_code=403, detail="Invalid two-factor code.")

        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        previous_ip = user.last_login_ip
        previous_login = user.last_login

        user.last_login = datetime.utcnow()
        user.last_login_ip = client_ip
        user.last_login_user_agent = user_agent
        db.add(user)
        await db.commit()
        await db.refresh(user)

        should_alert = False
        if (
            org_settings
            and org_settings.user_activity_alerts
            and previous_ip
            and client_ip
            and previous_ip != client_ip
            and previous_login
        ):
            if datetime.utcnow() - previous_login <= timedelta(hours=24):
                should_alert = True

        if should_alert:
            emails = []
            if (
                org_settings.email_notifications
                and org_settings.admin_email
                and org_settings.admin_email not in emails
            ):
                emails.append(org_settings.admin_email)
            await publish_event(
                {
                    "type": "user.activity.suspicious-login",
                    "organization_id": user.organization_id or 0,
                    "user_id": user.id,
                    "severity": "high",
                    "payload": {
                        "user": {
                            "id": user.id,
                            "name": user.name,
                            "email": user.email,
                        },
                        "current_ip": client_ip,
                        "previous_ip": previous_ip,
                        "user_agent": user_agent,
                        "target_role": "admin",
                        "action_url": "/admin/user-management",
                    },
                    "emails": emails,
                }
            )

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            user_id=user.id,
            sub=user.email,
            role=user.role,
            organization_id=user.organization_id,
            account_type="organization_user",
            expires_delta=access_token_expires,
        )

        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = create_refresh_token(
            sub=user.email,
            account_type="organization_user",
            expires_delta=refresh_token_expires,
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

        response.headers["X-Internal-User-Id"] = str(user.id)

        # IMPORTANT: never set empty string for org id
        if user.organization_id is not None:
            response.headers["X-Internal-Org-Id"] = str(user.organization_id)
        else:
            # ensure header is absent rather than empty
            response.headers.pop("X-Internal-Org-Id", None)

        logging.warning(f"[DEBUG] Set refresh_token cookie: {refresh_token}")
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                logging.warning(f"[DEBUG] Response header set-cookie: {v}")

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": int(access_token_expires.total_seconds()),
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": getattr(user, "created_at", None),
                "last_login": user.last_login,
                "organization_id": user.organization_id,
                "two_factor_enabled": user.two_factor_enabled,
            },
            "two_factor_required": requires_two_factor,
        }

    owner_result = await db.execute(
        select(OwnerAccount).where(OwnerAccount.email == payload.email)
    )
    owner = owner_result.scalar_one_or_none()
    if not owner or not verify_password(payload.password, owner.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not owner.is_active:
        raise HTTPException(status_code=403, detail="Owner account disabled")

    owner.last_login = datetime.utcnow()
    db.add(owner)
    await db.commit()
    await db.refresh(owner)

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        user_id=owner.id,
        sub=owner.email,
        role=owner.role,
        organization_id=None,
        account_type="owner",
        expires_delta=access_token_expires,
    )
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        sub=owner.email,
        account_type="owner",
        expires_delta=refresh_token_expires,
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
    response.headers["X-Internal-User-Id"] = str(owner.id)
    # IMPORTANT: do not emit empty org id
    response.headers.pop("X-Internal-Org-Id", None)

    logging.warning(f"[DEBUG] Set refresh_token cookie: {refresh_token}")
    for k, v in response.headers.items():
        if k.lower() == "set-cookie":
            logging.warning(f"[DEBUG] Response header set-cookie: {v}")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int(access_token_expires.total_seconds()),
        "user": {
            "id": owner.id,
            "name": owner.name,
            "email": owner.email,
            "role": owner.role,
            "is_active": owner.is_active,
            "created_at": getattr(owner, "created_at", None),
            "last_login": owner.last_login,
            "organization_id": None,
            "two_factor_enabled": owner.two_factor_enabled,
        },
        "two_factor_required": False,
    }


@router.post("/refresh-token", response_model=Token)
async def refresh_access_token(
    request: Request, response: Response, db: AsyncSession = Depends(get_db)
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    token_data = decode_refresh_token(refresh_token)

    principal_id: int | None = None
    principal_email: str | None = None
    principal_role: str | None = None
    organization_id: int | None = None

    if token_data.account_type == "owner":
        result = await db.execute(
            select(OwnerAccount).where(OwnerAccount.email == token_data.sub)
        )
        owner = result.scalar_one_or_none()
        if not owner or not owner.is_active:
            raise HTTPException(status_code=401, detail="Owner not found")
        principal_id = owner.id
        principal_email = owner.email
        principal_role = owner.role
    else:
        result = await db.execute(select(User).where(User.email == token_data.sub))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found")
        principal_id = user.id
        principal_email = user.email
        principal_role = user.role
        organization_id = user.organization_id

    if principal_id is None or principal_email is None or principal_role is None:
        raise HTTPException(status_code=401, detail="Invalid token subject")

    new_access_token = create_access_token(
        user_id=principal_id,
        sub=principal_email,
        role=principal_role,
        organization_id=organization_id,
        account_type=token_data.account_type or "organization_user",
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    """
    Stateless logout — validates token so the client can confidently clear it.
    """
    decode_access_token(token)
    return {"success": True, "message": "Logout successful"}


@router.get("/me/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_two_factor(
    current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    secret = pyotp.random_base32()
    otp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(
        current_user.email, issuer_name="MyESI"
    )

    result = await db.execute(
        select(UserTwoFactor).where(UserTwoFactor.user_id == current_user.id)
    )
    user_two_factor = result.scalar_one_or_none()

    if user_two_factor:
        user_two_factor.secret = secret
        user_two_factor.is_enabled = False
    else:
        user_two_factor = UserTwoFactor(
            user_id=current_user.id, secret=secret, is_enabled=False
        )
        db.add(user_two_factor)

    await db.commit()
    await db.refresh(user_two_factor)
    return TwoFactorSetupResponse(secret=secret, otp_auth_url=otp_auth_url)


@router.post("/me/2fa/verify")
async def verify_two_factor(
    payload: TwoFactorVerifyRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserTwoFactor).where(UserTwoFactor.user_id == current_user.id)
    )
    user_two_factor = result.scalar_one_or_none()

    if not user_two_factor:
        raise HTTPException(
            status_code=404, detail="Two-factor setup not found for this user."
        )

    totp = pyotp.TOTP(user_two_factor.secret)
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=403, detail="Invalid two-factor code.")

    user_two_factor.is_enabled = True
    current_user.two_factor_enabled = True
    db.add(user_two_factor)
    db.add(current_user)
    await db.commit()

    return {"message": "Two-factor authentication enabled"}


@router.get("/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    """
    Return current logged-in user info.
    """
    return current_user


@router.put("/me", response_model=UserOut)
async def update_profile(
    payload: UserProfileUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not payload.name and not payload.email:
        raise HTTPException(status_code=400, detail="No data provided")

    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.email and payload.email != user.email:
        if not payload.current_password:
            raise HTTPException(
                status_code=403,
                detail="Current password is required to change email",
            )
        if not verify_password(payload.current_password, user.hashed_password):
            raise HTTPException(status_code=403, detail="Current password is incorrect")
        email_check = await db.execute(select(User).where(User.email == payload.email))
        if email_check.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Email already in use")

    if payload.name:
        user.name = payload.name
    if payload.email:
        user.email = payload.email

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.put("/me/password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=403, detail="Current password is incorrect")

    user.hashed_password = get_password_hash(payload.new_password)
    db.add(user)
    await db.commit()
    return {"message": "Password updated successfully"}


@org_router.get("/{org_id}/settings", response_model=OrganizationSettingsOut)
async def get_organization_settings(
    org_id: int,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    result = await db.execute(
        select(OrganizationSettings).where(
            OrganizationSettings.organization_id == org_id
        )
    )
    settings = result.scalar_one_or_none()
    if not settings:
        settings = OrganizationSettings(
            organization_id=org_id,
            require_two_factor=org.require_two_factor,
        )
    db.add(settings)
    await db.commit()
    await db.refresh(settings)

    return settings


@org_router.put("/{org_id}/settings", response_model=OrganizationSettingsOut)
async def update_organization_settings(
    org_id: int,
    payload: OrganizationSettingsUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    result = await db.execute(
        select(OrganizationSettings).where(
            OrganizationSettings.organization_id == org_id
        )
    )
    settings = result.scalar_one_or_none()
    if not settings:
        settings = OrganizationSettings(organization_id=org_id)
        db.add(settings)

    for key, value in payload.dict(exclude_none=True).items():
        if key == "organization_name":
            org.name = value
        elif key == "require_two_factor":
            org.require_two_factor = value
            settings.require_two_factor = value
        else:
            setattr(settings, key, value)

    db.add(org)
    db.add(settings)
    await db.commit()
    await db.refresh(settings)
    return settings


@org_router.patch(
    "/{org_id}/settings/notifications", response_model=OrganizationSettingsOut
)
async def toggle_notification_settings(
    org_id: int,
    payload: NotificationSettingsUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    result = await db.execute(
        select(OrganizationSettings).where(
            OrganizationSettings.organization_id == org_id
        )
    )
    settings = result.scalar_one_or_none()
    if not settings:
        settings = OrganizationSettings(organization_id=org_id)
        db.add(settings)
        await db.flush()

    updates = payload.dict(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No notification flags provided")

    for key, value in updates.items():
        setattr(settings, key, value)

    db.add(settings)
    await db.commit()
    await db.refresh(settings)
    return settings


@org_router.get("/{org_id}", response_model=OrganizationOut)
async def get_organization(org_id: int, db: AsyncSession = Depends(get_db)):
    """
    Fetch organization by id.
    """
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@org_router.get("/", response_model=list[OrganizationOut])
async def list_organizations(
    current_owner=Depends(get_current_owner),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Organization)
        .where(Organization.owner_id == current_owner.id)
        .order_by(Organization.created_at.desc())
    )
    return result.scalars().all()


@org_router.post("/", response_model=OrganizationCreateResponse, status_code=201)
async def create_organization(
    payload: OrganizationCreateRequest,
    current_owner=Depends(get_current_owner),
    db: AsyncSession = Depends(get_db),
):
    normalized_name = payload.name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="Organization name is required")

    name_check = await db.execute(
        select(Organization).where(
            func.lower(Organization.name) == normalized_name.lower()
        )
    )
    if name_check.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Organization name already exists")

    new_org = Organization(
        name=normalized_name,
        require_two_factor=payload.require_two_factor,
        owner_id=current_owner.id,
    )
    db.add(new_org)
    await db.flush()

    settings = OrganizationSettings(
        organization_id=new_org.id,
        require_two_factor=payload.require_two_factor,
        admin_email=payload.admin_email,
    )
    db.add(settings)

    invited_admin = None
    if payload.admin_email:
        email = payload.admin_email.lower()
        existing_user = await db.execute(select(User).where(User.email == email))
        if existing_user.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Admin email already exists")

        temp_password = _generate_temporary_password()
        admin_user = User(
            name=payload.admin_name or payload.admin_email.split("@")[0],
            email=email,
            hashed_password=get_password_hash(temp_password),
            role="admin",
            organization_id=new_org.id,
            is_active=True,
        )
        db.add(admin_user)
        await db.flush()
        invited_admin = AdminInviteResult(
            id=admin_user.id,
            name=admin_user.name,
            email=admin_user.email,
            temporary_password=temp_password,
        )

    await db.commit()
    await db.refresh(new_org)

    return OrganizationCreateResponse(
        organization=OrganizationOut.model_validate(new_org, from_attributes=True),
        invited_admin=invited_admin,
    )


@org_router.post(
    "/{org_id}/invite-admin", response_model=OrganizationInviteAdminResponse
)
async def invite_admin_to_org(
    org_id: int,
    payload: OrganizationInviteAdminRequest,
    current_owner=Depends(get_current_owner),
    db: AsyncSession = Depends(get_db),
):
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.owner_id != current_owner.id:
        raise HTTPException(
            status_code=403, detail="Cannot modify another owner's organization"
        )

    email = payload.admin_email.lower()
    existing_user = await db.execute(select(User).where(User.email == email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Admin email already exists")

    temp_password = _generate_temporary_password()
    admin_user = User(
        name=payload.admin_name or payload.admin_email.split("@")[0],
        email=email,
        hashed_password=get_password_hash(temp_password),
        role="admin",
        organization_id=org.id,
        is_active=True,
    )
    db.add(admin_user)

    settings_result = await db.execute(
        select(OrganizationSettings).where(
            OrganizationSettings.organization_id == org.id
        )
    )
    settings = settings_result.scalar_one_or_none()
    if not settings:
        settings = OrganizationSettings(organization_id=org.id)
        db.add(settings)
    settings.admin_email = payload.admin_email

    await db.commit()
    await db.refresh(admin_user)

    return OrganizationInviteAdminResponse(
        admin=AdminInviteResult(
            id=admin_user.id,
            name=admin_user.name,
            email=admin_user.email,
            temporary_password=temp_password,
        )
    )

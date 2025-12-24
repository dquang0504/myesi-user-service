import asyncio
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, Request, Response, status, HTTPException
from sqlalchemy import func, text
from app.db.session import get_db, AsyncSession
from app.db.models import (
    OwnerAccount,
    PasswordResetToken,
    User,
    Organization,
    UserTwoFactor,
    OrganizationSettings,
)
from app.schemas.user import (
    ChangePasswordRequest,
    LoginResponse,
    PasswordResetCompleteRequest,
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
from app.services.session_manager import (
    create_user_session,
    require_active_session,
    revoke_session_by_id,
)
from app.core.config import settings
from sqlalchemy.future import select
from sqlalchemy.exc import DBAPIError
import pyotp
from app.services.notification_client import publish_event
from app.utils.mailer import send_email

router = APIRouter(prefix="/api/users", tags=["users"])
org_router = APIRouter(prefix="/api/organizations", tags=["organizations"])


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_reset_url(token: str) -> str:
    base = settings.FRONTEND_APP_URL.rstrip("/")
    return f"{base}/reset-password?token={token}"


async def _create_password_reset_token(
    db: AsyncSession, user_id: int, request: Request | None
) -> str:
    token_plain = secrets.token_urlsafe(48)
    token_hash = _hash_token(token_plain)
    expires = datetime.now(timezone.utc) + timedelta(
        hours=settings.RESET_TOKEN_VALID_HOURS
    )
    record = PasswordResetToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires,
        request_ip=request.client.host if request and request.client else None,
        request_user_agent=request.headers.get("user-agent") if request else None,
    )
    db.add(record)
    await db.flush()
    return token_plain


async def _dispatch_invite_email(
    *,
    admin_user: User,
    org_name: str,
    inviter_name: str,
    reset_url: str,
) -> None:
    subject = f"You've been invited to administer {org_name}"

    # Prepare CID inline image
    logo_path = Path(__file__).resolve().parents[3] / "images" / "myesi_logo.png"
    inline_images: dict[str, str] = {}
    logo_cid: str | None = None

    try:
        if logo_path.exists():
            logo_cid = "myesi-logo"
            inline_images[logo_cid] = str(logo_path)
    except Exception as exc:
        logging.getLogger(__name__).warning("Logo load failed: %s", exc)
        logo_cid = None

    # Keep HTML compact to reduce likelihood of Gmail clipping
    logo_html = (
        f'<img src="cid:{logo_cid}" alt="MyESI" width="140" '
        f'style="display:block;border:0;outline:none;text-decoration:none;height:auto;" />'
        if logo_cid
        else '<div style="font-size:20px;font-weight:700;color:#0f172a;line-height:1;">MyESI</div>'
    )

    recipient_name = admin_user.name or "there"
    expires_hours = settings.RESET_TOKEN_VALID_HOURS

    body = f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f8fafc;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;">
      <tr>
        <td align="center" style="padding:24px;">
          <table role="presentation" width="620" cellpadding="0" cellspacing="0" border="0"
                 style="max-width:620px;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;">
            <tr>
              <td style="padding:28px 28px 16px 28px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                    <tr>
                        <td align="center">
                            {logo_html}
                        </td>
                    </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 10px 28px;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
                <div style="font-size:18px;font-weight:700;">
                  You're invited to admin {org_name}
                </div>
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 18px 28px;font-family:Arial,Helvetica,sans-serif;color:#334155;font-size:14px;line-height:1.6;">
                Hi {recipient_name},<br/>
                <strong>{inviter_name}</strong> invited you to join the <strong>{org_name}</strong> workspace on MyESI.
                Please set your password to activate your account. This link expires in {expires_hours} hours.
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 22px 28px;">
                <a href="{reset_url}"
                   style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;
                          font-family:Arial,Helvetica,sans-serif;font-size:14px;font-weight:700;
                          padding:12px 18px;border-radius:8px;">
                  Set your password
                </a>
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 8px 28px;font-family:Arial,Helvetica,sans-serif;color:#64748b;font-size:12px;line-height:1.5;">
                If the button doesn't work, copy and paste this URL into your browser:
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 24px 28px;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.5;">
                <a href="{reset_url}" style="color:#2563eb;word-break:break-all;text-decoration:none;">{reset_url}</a>
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 28px 28px;font-family:Arial,Helvetica,sans-serif;color:#94a3b8;font-size:12px;line-height:1.5;">
                If you did not expect this invite, you can ignore this email.
              </td>
            </tr>
          </table>
          <div style="font-family:Arial,Helvetica,sans-serif;color:#94a3b8;font-size:11px;margin-top:14px;">
            © {datetime.utcnow().year} MyESI. All rights reserved.
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    text_fallback = (
        f"Hi {recipient_name},\n\n"
        f"{inviter_name} invited you to admin {org_name} on MyESI.\n"
        f"Set your password here (expires in {expires_hours} hours):\n{reset_url}\n\n"
        f"If you did not expect this invite, you can ignore this email."
    )

    async def _send():
        try:
            await send_email(
                subject=subject,
                body=body,
                recipients=[admin_user.email],
                text_body=text_fallback,
                inline_images=inline_images if logo_cid else None,
            )
        except Exception as exc:
            logging.getLogger(__name__).error(
                "Failed to send invite email to %s: %s", admin_user.email, exc
            )

    asyncio.create_task(_send())


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
        two_factor_enabled=False,
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
                status_code=403,
                detail="Account inactive. Please finish your invite or contact an admin.",
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

        user.last_login = datetime.now(timezone.utc)
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
            if datetime.now(timezone.utc) - previous_login <= timedelta(hours=24):
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

        session_id = None
        enforce_idle = bool(org_settings and org_settings.session_timeout)
        if enforce_idle:
            user_session = await create_user_session(
                db,
                principal_type="organization_user",
                principal_id=user.id,
                organization_id=user.organization_id,
                idle_timeout_minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES_DEFAULT,
                ip=client_ip,
                user_agent=user_agent,
            )
            session_id = str(user_session.id)

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            user_id=user.id,
            sub=user.email,
            role=user.role,
            organization_id=user.organization_id,
            account_type="organization_user",
            expires_delta=access_token_expires,
            session_id=session_id,
        )

        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = create_refresh_token(
            sub=user.email,
            account_type="organization_user",
            expires_delta=refresh_token_expires,
            session_id=session_id,
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
            if "X-Internal-Org-Id" in response.headers:
                del response.headers["X-Internal-Org-Id"]

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
            "session_id": session_id,
        }

    owner_result = await db.execute(
        select(OwnerAccount).where(OwnerAccount.email == payload.email)
    )
    owner = owner_result.scalar_one_or_none()
    if not owner or not verify_password(payload.password, owner.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not owner.is_active:
        raise HTTPException(status_code=403, detail="Owner account disabled")

    owner.last_login = datetime.now(timezone.utc)
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
    if "X-Internal-Org-Id" in response.headers:
        del response.headers["X-Internal-Org-Id"]

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
        "session_id": None,
    }


@router.post("/refresh-token", response_model=Token)
async def refresh_access_token(
    request: Request, response: Response, db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using HttpOnly refresh_token cookie.

    Behavior:
      - If access token expired but refresh token + session still valid => issue new access token.
      - If refresh token expired/invalid OR idle session expired/revoked => return 401
        AND clear refresh_token cookie to prevent client spam.
    """
    from fastapi import status as http_status

    try:
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

        enforce_idle = False
        session_id = token_data.sid
        if token_data.account_type == "organization_user" and organization_id:
            org_settings = await db.get(OrganizationSettings, organization_id)
            enforce_idle = bool(org_settings and org_settings.session_timeout)

        if enforce_idle:
            if not session_id:
                raise HTTPException(
                    status_code=401, detail="Session expired or invalid session"
                )
            # interactive=False because refresh is background traffic
            await require_active_session(
                db,
                session_id=session_id,
                principal_type="organization_user",
                principal_id=principal_id,
                interactive=False,
            )
        else:
            session_id = None

        new_access_token = create_access_token(
            user_id=principal_id,
            sub=principal_email,
            role=principal_role,
            organization_id=organization_id,
            account_type=token_data.account_type or "organization_user",
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            session_id=session_id,
        )

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "session_id": session_id,
        }

    except HTTPException as exc:
        # If refresh is not valid anymore, clear cookie so client stops retrying with a dead cookie
        if exc.status_code in (
            http_status.HTTP_401_UNAUTHORIZED,
            http_status.HTTP_403_FORBIDDEN,
        ):
            response.delete_cookie(
                key="refresh_token",
                path="/",
                secure=True,
                samesite="none",
            )
        raise


@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
):
    """
    Logout validates the token and revokes the backing session when idle enforcement is enabled.
    """
    token_data = decode_access_token(token)
    if token_data.sid:
        await revoke_session_by_id(db, token_data.sid)
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


@router.post("/password-reset/complete")
async def complete_password_reset(
    payload: PasswordResetCompleteRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    token_hash = _hash_token(payload.token)
    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    reset_record = result.scalar_one_or_none()
    if (
        not reset_record
        or reset_record.used
        or reset_record.expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=400, detail="Reset link invalid or expired")

    user = await db.get(User, reset_record.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="User unavailable")

    user.hashed_password = get_password_hash(payload.new_password)
    user.is_active = True
    reset_record.used = True
    reset_record.used_at = datetime.now(timezone.utc)
    reset_record.used_ip = request.client.host if request.client else None
    reset_record.used_user_agent = request.headers.get("user-agent")

    db.add_all([user, reset_record])
    await db.commit()

    if user.id:
        user_id_str = str(user.id)
        response.headers["X-Internal-User-Id"] = user_id_str
        setattr(request.state, "audit_user_id", user_id_str)
    if user.organization_id:
        org_id_str = str(user.organization_id)
        response.headers["X-Internal-Org-Id"] = org_id_str
        setattr(request.state, "audit_org_id", org_id_str)

    return {"message": "Password updated successfully. You can now sign in."}


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
            # ---- add defaults so response_model validates ----
            support_email=None,  # EmailStr -> None is ok, "" is NOT ok
            password_expiry=False,
            session_timeout=False,
            ip_whitelisting=False,
            email_notifications=False,
            vulnerability_alerts=False,
            weekly_reports=True,  # optional: pick your desired default
            user_activity_alerts=False,
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
        settings = OrganizationSettings(
            organization_id=org_id,
            # ---- defaults ----
            support_email=None,
            require_two_factor=org.require_two_factor,  # mirror org
            password_expiry=False,
            session_timeout=False,
            ip_whitelisting=False,
            email_notifications=False,
            vulnerability_alerts=False,
            weekly_reports=True,
            user_activity_alerts=False,
        )
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
        settings = OrganizationSettings(
            organization_id=org_id,
            # ---- defaults ----
            support_email=None,
            require_two_factor=org.require_two_factor,
            password_expiry=False,
            session_timeout=False,
            ip_whitelisting=False,
            email_notifications=False,
            vulnerability_alerts=False,
            weekly_reports=True,
            user_activity_alerts=False,
        )
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


@org_router.get("", response_model=list[OrganizationOut])
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


@org_router.post("", response_model=OrganizationCreateResponse, status_code=201)
async def create_organization(
    payload: OrganizationCreateRequest,
    request: Request,
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
    invite_email_payload = None
    billing_contact_id = None
    if payload.admin_email:
        email = payload.admin_email.lower()
        existing_user = await db.execute(select(User).where(User.email == email))
        if existing_user.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Admin email already exists")

        admin_user = User(
            name=payload.admin_name or payload.admin_email.split("@")[0],
            email=email,
            hashed_password=get_password_hash(secrets.token_urlsafe(32)),
            role="admin",
            organization_id=new_org.id,
            is_active=False,
        )
        db.add(admin_user)
        await db.flush()
        invited_admin = AdminInviteResult(
            id=admin_user.id,
            name=admin_user.name,
            email=admin_user.email,
        )
        billing_contact_id = admin_user.id
        token_plain = await _create_password_reset_token(db, admin_user.id, request)
        invite_email_payload = {
            "admin_user": admin_user,
            "reset_url": _build_reset_url(token_plain),
            "org_name": new_org.name,
            "inviter_name": current_owner.name or "MyESI Owner",
        }

    free_plan_id = 0
    sub_result = await db.execute(
        text(
            """
            INSERT INTO subscriptions (
                created_by, last_updated_by, billing_contact_user_id,
                plan_id, status, interval, created_at, updated_at
            )
            VALUES (:created_by, :last_updated_by, :billing_contact, :plan_id,
                    'active', 'monthly', NOW(), NOW())
            RETURNING id
            """
        ),
        {
            "created_by": billing_contact_id,
            "last_updated_by": billing_contact_id,
            "billing_contact": billing_contact_id,
            "plan_id": free_plan_id,
        },
    )
    subscription_id = sub_result.scalar_one()
    new_org.subscription_id = subscription_id

    await db.commit()
    await db.refresh(new_org)

    if invite_email_payload:
        await _dispatch_invite_email(**invite_email_payload)

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
    request: Request,
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

    admin_user = User(
        name=payload.admin_name or payload.admin_email.split("@")[0],
        email=email,
        hashed_password=get_password_hash(secrets.token_urlsafe(32)),
        role="admin",
        organization_id=org.id,
        is_active=False,
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

    await db.flush()

    token_plain = await _create_password_reset_token(db, admin_user.id, request)

    await db.commit()
    await db.refresh(admin_user)

    await _dispatch_invite_email(
        admin_user=admin_user,
        org_name=org.name,
        inviter_name=current_owner.name or "MyESI Owner",
        reset_url=_build_reset_url(token_plain),
    )

    return OrganizationInviteAdminResponse(
        admin=AdminInviteResult(
            id=admin_user.id,
            name=admin_user.name,
            email=admin_user.email,
        )
    )

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, status
from sqlalchemy import delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import UserSession
from app.db.session import AsyncSessionLocal

# Background endpoints that must never touch idle activity.
BACKGROUND_PATH_PREFIXES = ("/api/notifications/stream",)
TOUCH_THROTTLE_SECONDS = 60
_cleanup_task: asyncio.Task | None = None


async def create_user_session(
    db: AsyncSession,
    *,
    principal_type: str,
    principal_id: int,
    organization_id: Optional[int],
    idle_timeout_minutes: int,
    ip: Optional[str],
    user_agent: Optional[str],
) -> UserSession:
    session = UserSession(
        principal_type=principal_type,
        principal_id=principal_id,
        organization_id=organization_id,
        idle_timeout_minutes=idle_timeout_minutes,
        ip=ip,
        user_agent=user_agent,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session


async def revoke_session_by_id(db: AsyncSession, session_id: str) -> None:
    session = await _get_session(db, session_id)
    if not session or session.revoked_at:
        return
    session.revoked_at = datetime.now(timezone.utc)
    db.add(session)
    await db.commit()


async def require_active_session(
    db: AsyncSession,
    *,
    session_id: str,
    principal_type: str,
    principal_id: int,
    interactive: bool,
) -> UserSession:
    now = datetime.now(timezone.utc)
    session = await _get_session(db, session_id)
    if (
        not session
        or session.principal_type != principal_type
        or session.principal_id != principal_id
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid session",
        )

    if session.revoked_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
        )

    idle_minutes = (
        session.idle_timeout_minutes or settings.SESSION_IDLE_TIMEOUT_MINUTES_DEFAULT
    )
    last_activity = session.last_activity_at or session.created_at or now
    if now - last_activity > timedelta(minutes=idle_minutes):
        session.revoked_at = now
        db.add(session)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
        )

    if interactive and (now - last_activity).total_seconds() >= TOUCH_THROTTLE_SECONDS:
        session.last_activity_at = now
        db.add(session)
        await db.commit()

    return session


def is_interactive_request(request: Request) -> bool:
    """
    Determine whether a request should extend idle time.
    Frontend must send X-Client-Activity: interactive|background for clarity.
    """
    header = (request.headers.get("x-client-activity") or "").strip().lower()
    if header == "background":
        return False
    if header == "interactive":
        return True

    path = request.url.path or ""
    for prefix in BACKGROUND_PATH_PREFIXES:
        if path.startswith(prefix):
            return False

    return True


async def _get_session(db: AsyncSession, session_id: str) -> Optional[UserSession]:
    try:
        session_uuid = uuid.UUID(session_id)
    except (ValueError, TypeError):
        return None
    return await db.get(UserSession, session_uuid)


async def purge_stale_sessions() -> None:
    """Soft-delete sessions that are revoked or cold for too long."""
    async with AsyncSessionLocal() as db:
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=settings.SESSION_STALE_RETENTION_HOURS
        )
        stmt = delete(UserSession).where(
            or_(
                UserSession.revoked_at.is_not(None),
                UserSession.last_activity_at < cutoff,
            )
        )
        result = await db.execute(stmt)
        await db.commit()
        deleted = result.rowcount or 0
        if deleted:
            logging.getLogger(__name__).info(
                "[sessions] Purged %s stale session(s)", deleted
            )


async def _session_cleanup_loop():
    interval = max(settings.SESSION_CLEANUP_INTERVAL_MINUTES, 5) * 60
    while True:
        try:
            await purge_stale_sessions()
        except Exception as exc:  # pragma: no cover - defensive logging
            logging.getLogger(__name__).warning(
                "[sessions] cleanup loop failed: %s", exc, exc_info=True
            )
        await asyncio.sleep(interval)


def start_session_cleanup_task():
    global _cleanup_task
    if _cleanup_task is None or _cleanup_task.done():
        _cleanup_task = asyncio.create_task(_session_cleanup_loop())


async def stop_session_cleanup_task():
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
        _cleanup_task = None

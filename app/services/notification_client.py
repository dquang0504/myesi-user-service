import asyncio
from datetime import datetime
from typing import Any, Dict

import httpx

from app.core.config import settings


async def publish_event(event: Dict[str, Any]) -> None:
    """
    Lightweight helper to push events to the notification service over HTTP.
    Fire-and-forget; failures are logged but do not block auth flows.
    """
    base_url = settings.NOTIFICATION_SERVICE_URL.rstrip("/")
    if not base_url:
        return

    event.setdefault("occurred_at", datetime.utcnow().isoformat())

    headers = {}
    if settings.NOTIFICATION_SERVICE_TOKEN:
        headers["X-Service-Token"] = settings.NOTIFICATION_SERVICE_TOKEN

    url = f"{base_url}/api/notification/events"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json=event, headers=headers)
    except Exception as exc:
        # If running outside of request context (login), avoid raising
        # and degrading UX; log via print to keep dependencies minimal.
        print(f"[Notifications] failed to publish event: {exc}")


def publish_event_sync(event: Dict[str, Any]) -> None:
    """
    Synchronous shim for contexts where we cannot await directly (optional).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(publish_event(event))
    else:
        asyncio.create_task(publish_event(event))

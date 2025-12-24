import asyncio
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.services.auth import get_current_user

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("/stream")
async def notifications_stream(
    request: Request, current_user=Depends(get_current_user)
):
    """
    SSE endpoint used by the frontend to receive notifications without polling.
    Example client usage:
        const es = new EventSource("/api/notifications/stream");
    The request is treated as background traffic so it never bumps session activity.
    """

    async def event_generator():
        # Heartbeat only for now; backend-to-backend fan-out can be plugged in later.
        while True:
            if await request.is_disconnected():
                break
            yield ":\n\n"
            await asyncio.sleep(20)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(
        event_generator(), media_type="text/event-stream", headers=headers
    )

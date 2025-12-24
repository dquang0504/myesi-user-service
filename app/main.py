from fastapi import FastAPI
from app.api.v1 import users, admin, github
from app.api import notifications
from app.services.session_manager import (
    start_session_cleanup_task,
    stop_session_cleanup_task,
)

app = FastAPI(title="MyESI - User Service", redirect_slashes=False)
app.include_router(users.router)
app.include_router(users.org_router)
app.include_router(admin.router)
app.include_router(github.router)
app.include_router(notifications.router)


@app.on_event("startup")
async def _startup():
    start_session_cleanup_task()


@app.on_event("shutdown")
async def _shutdown():
    await stop_session_cleanup_task()

from fastapi import FastAPI
from app.api.v1 import users, admin

app = FastAPI(title="MyESI - User Service")
app.include_router(users.router)
app.include_router(admin.router)

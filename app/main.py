from fastapi import FastAPI
from app.api.v1 import users

app = FastAPI(title="MyESI - User Service")
app.include_router(users.router)

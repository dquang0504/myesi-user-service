from fastapi import FastAPI
from app.api.v1 import users, admin, github

app = FastAPI(title="MyESI - User Service")
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(github.router)

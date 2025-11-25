from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://myesi:password@postgres:5432/myesi_db"
    SECRET_KEY: str = "replace-with-secure-key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- GitHub OAuth ---
    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str
    GITHUB_OAUTH_REDIRECT_URI: str  # ví dụ: http://localhost:3000/github/callback

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

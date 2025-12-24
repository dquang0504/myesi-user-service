from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://myesi:password@postgres:5432/myesi_db"
    SECRET_KEY: str = "replace-with-secure-key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    ALGORITHM: str = "HS256"
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    NOTIFICATION_SERVICE_URL: str = "http://notification-service:8006"
    NOTIFICATION_SERVICE_TOKEN: str = ""

    # --- GitHub OAuth ---
    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str
    GITHUB_OAUTH_REDIRECT_URI: str  # ví dụ: http://localhost:3000/github/callback

    # --- Email / invites ---
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USE_TLS: bool = True
    SMTP_USERNAME: str = Field("", alias="GMAIL_USERNAME")
    SMTP_PASSWORD: str = Field("", alias="GMAIL_PASS")
    SMTP_FROM: str | None = None
    EMAIL_SENDER_NAME: str = "MyESI Security"
    FRONTEND_APP_URL: str = "https://localhost:3000"
    RESET_TOKEN_VALID_HOURS: int = 48
    SESSION_IDLE_TIMEOUT_MINUTES_DEFAULT: int = 30
    SESSION_CLEANUP_INTERVAL_MINUTES: int = 60
    SESSION_STALE_RETENTION_HOURS: int = 48

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

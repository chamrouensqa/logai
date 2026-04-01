from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "Log AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database (SQLite for dev, PostgreSQL for production)
    DATABASE_URL: str = "sqlite+aiosqlite:///./logai.db"
    DATABASE_URL_SYNC: str = "sqlite:///./logai.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://localhost:9200"

    # File Storage
    UPLOAD_DIR: str = "uploads"
    MAX_UPLOAD_SIZE_MB: int = 500

    # AI Configuration
    AI_PROVIDER: str = "openai"  # openai | anthropic | local
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-5"
    OPENAI_FALLBACK_MODEL: str = "gpt-4o"
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    LOCAL_LLM_URL: Optional[str] = None

    # Security
    SECRET_KEY: str = "change-this-in-production-use-openssl-rand-hex-32"
    # Session length (JWT). Default 7 days for dev; override with ACCESS_TOKEN_EXPIRE_MINUTES in .env
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8000"]

    # IP reputation (optional — AbuseIPDB + VirusTotal)
    ABUSEIPDB_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

    # Bootstrap admin (created only when no users exist — change password in production)
    ALPHA_ADMIN_USERNAME: str = "admin"
    ALPHA_ADMIN_PASSWORD: str = "changeme"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

"""
NYAYAI - Backend Configuration Settings (Phase 1)
Module: backend.app.config
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application Metadata
    APP_NAME: str = "NYAYAI Backend"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api"
    API_V1_PREFIX: str = "/api/v1"

    # Network Configuration
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000

    # PostgreSQL Database Configuration
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "nyayai_admin"
    POSTGRES_PASSWORD: str = "SecureProdPassword2026"
    POSTGRES_DB: str = "nyayai_db"

    # Database URL: defaults to PostgreSQL when configured, or local SQLite for development fallback
    DATABASE_URL: Optional[str] = None

    # Database Connection Pool
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30

    # Security & Cryptography
    SECRET_KEY: str = "phase1-dev-secret-key-32chars-minimum-entropy"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    HASH_ALGORITHM: str = "SHA-256"

    # Storage Configuration (Local, S3, MinIO)
    STORAGE_BACKEND: str = "local"  # "local", "s3", or "minio"
    EVIDENCE_VAULT_PATH: str = "./storage/vault"
    REPORT_OUTPUT_PATH: str = "./storage/reports"
    TEMP_PROCESSING_PATH: str = "./storage/temp"
    MAX_EVIDENCE_FILE_SIZE_MB: int = 500

    # S3 / MinIO Storage Configuration (Credentials read from environment, never hardcoded)
    S3_ENDPOINT_URL: Optional[str] = None
    S3_BUCKET_NAME: str = "nyayai-evidence-vault"
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[str] = None
    S3_REGION: str = "ap-south-1"
    S3_USE_SSL: bool = True

    # MinIO Specific Configurations
    MINIO_ENDPOINT: Optional[str] = None
    MINIO_ACCESS_KEY: Optional[str] = None
    MINIO_SECRET_KEY: Optional[str] = None
    MINIO_BUCKET_NAME: Optional[str] = None
    MINIO_SECURE: bool = False

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json" # "json" or "text"

    def get_database_url(self) -> str:
        """
        Returns DATABASE_URL from environment if explicitly provided;
        otherwise constructs PostgreSQL connection URI, falling back to SQLite in development.
        """
        if self.DATABASE_URL:
            return self.DATABASE_URL
        
        # If running in environment with explicit DB url in os.environ
        env_url = os.getenv("DATABASE_URL")
        if env_url:
            return env_url

        # Check if PostgreSQL is explicitly requested
        pg_url = f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        
        # In development without running PostgreSQL, fallback to SQLite
        if self.ENVIRONMENT == "development" and not os.getenv("FORCE_POSTGRES"):
            return "sqlite:///./nyayai.db"
            
        return pg_url

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"


settings = Settings()

# Ensure required storage directories exist upon boot
for path in [settings.EVIDENCE_VAULT_PATH, settings.REPORT_OUTPUT_PATH, settings.TEMP_PROCESSING_PATH]:
    os.makedirs(path, exist_ok=True)

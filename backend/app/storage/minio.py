"""
NYAYAI - MinIO Object Storage Driver
Module: backend.app.storage.minio
Lead: Dhananjay Sharma (Backend & System Integration Lead)

Enforces:
- Self-hosted S3-compatible MinIO object storage support
- Zero hardcoded credentials
- Path-style addressing configuration
"""

import os
from typing import Optional
from backend.app.config import settings
from backend.app.utils.logger import get_logger
from .s3 import S3StorageDriver

logger = get_logger("storage_minio")


class MinIOStorageDriver(S3StorageDriver):
    """
    MinIO object storage driver extending S3StorageDriver.
    Configured specifically for MinIO on-premise or containerized deployments.
    """

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        bucket_name: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        secure: Optional[bool] = None
    ):
        minio_endpoint = (
            endpoint_url
            or os.getenv("MINIO_ENDPOINT")
            or settings.MINIO_ENDPOINT
            or os.getenv("S3_ENDPOINT_URL")
            or settings.S3_ENDPOINT_URL
            or "http://127.0.0.1:9000"
        )
        minio_bucket = (
            bucket_name
            or os.getenv("MINIO_BUCKET_NAME")
            or settings.MINIO_BUCKET_NAME
            or os.getenv("S3_BUCKET_NAME")
            or settings.S3_BUCKET_NAME
            or "nyayai-vault"
        )
        minio_access = (
            access_key
            or os.getenv("MINIO_ACCESS_KEY")
            or settings.MINIO_ACCESS_KEY
            or os.getenv("S3_ACCESS_KEY")
            or settings.S3_ACCESS_KEY
        )
        minio_secret = (
            secret_key
            or os.getenv("MINIO_SECRET_KEY")
            or settings.MINIO_SECRET_KEY
            or os.getenv("S3_SECRET_KEY")
            or settings.S3_SECRET_KEY
        )
        minio_secure = (
            secure
            if secure is not None
            else (settings.MINIO_SECURE if hasattr(settings, "MINIO_SECURE") else False)
        )

        super().__init__(
            endpoint_url=minio_endpoint,
            bucket_name=minio_bucket,
            access_key=minio_access,
            secret_key=minio_secret,
            region="us-east-1",
            use_ssl=minio_secure
        )
        logger.info(f"MinIO storage driver configured for bucket '{minio_bucket}' at '{minio_endpoint}'")

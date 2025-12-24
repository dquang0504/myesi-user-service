import hashlib
import hmac
import os
from typing import Optional
import logging
from fastapi import HTTPException

logger = logging.getLogger(__name__)


def verify_signature(body: bytes, signature_header: Optional[str]) -> None:
    """
    Verify X-Hub-Signature-256 from GitHub using GITHUB_WEBHOOK_SECRET.
    If env var không set -> chỉ log warning, cho phép dev test local.
    """
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        logger.warning(
            "GITHUB_WEBHOOK_SECRET is not set – skipping signature verification (DEV ONLY)."
        )
        return

    if not signature_header or not signature_header.startswith("sha256="):
        raise HTTPException(status_code=400, detail="Invalid signature header")

    received_sig = signature_header.split("=", 1)[1]
    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
    expected_sig = mac.hexdigest()

    if not hmac.compare_digest(received_sig, expected_sig):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

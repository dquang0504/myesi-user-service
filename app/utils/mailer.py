import asyncio
import logging
import mimetypes
import smtplib
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path
from typing import Iterable, Optional, Dict

from app.core.config import settings

logger = logging.getLogger("mailer")


def _guess_mime(path: str) -> tuple[str, str]:
    ctype, _ = mimetypes.guess_type(path)
    if not ctype:
        return "application", "octet-stream"
    maintype, subtype = ctype.split("/", 1)
    return maintype, subtype


def _build_message(
    subject: str,
    html_body: str,
    recipients: Iterable[str],
    *,
    text_body: Optional[str] = None,
    inline_images: Optional[Dict[str, str]] = None,  # {cid: filepath}
) -> MIMEMultipart:
    """
    Build MIME email:
      - multipart/alternative (text/plain + text/html)
      - when inline_images is provided: wrap html part in multipart/related and attach images with Content-ID
    """
    sender = settings.SMTP_FROM or settings.SMTP_USERNAME

    # Root message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = formataddr((settings.EMAIL_SENDER_NAME, sender))
    msg["To"] = ", ".join(recipients)

    # Plain text fallback (keep short)
    if not text_body:
        text_body = "You have an invitation from MyESI. Please open this email in an HTML-capable client to view the action button."

    part_text = MIMEText(text_body, "plain", "utf-8")

    # If no inline images, attach html directly as an alternative
    if not inline_images:
        part_html = MIMEText(html_body, "html", "utf-8")
        msg.attach(part_text)
        msg.attach(part_html)
        return msg

    # With inline images: html must be a multipart/related container
    related = MIMEMultipart("related")
    related.attach(MIMEText(html_body, "html", "utf-8"))

    for cid, file_path in inline_images.items():
        try:
            p = Path(file_path)
            if not p.exists() or not p.is_file():
                logger.warning("Inline image not found: %s", file_path)
                continue

            maintype, subtype = _guess_mime(str(p))
            data = p.read_bytes()

            if maintype == "image":
                img = MIMEImage(data, _subtype=subtype)
            else:
                # Fallback: attach as application/*
                img = MIMEApplication(data, _subtype=subtype)

            # IMPORTANT: cid must be wrapped with <>
            img.add_header("Content-ID", f"<{cid}>")
            img.add_header("Content-Disposition", "inline", filename=p.name)

            related.attach(img)

        except Exception as exc:
            logger.error(
                "Failed to attach inline image %s: %s", file_path, exc, exc_info=True
            )

    msg.attach(part_text)
    msg.attach(related)
    return msg


async def send_email(
    subject: str,
    body: str,
    recipients: list[str],
    *,
    text_body: Optional[str] = None,
    inline_images: Optional[Dict[str, str]] = None,
) -> None:
    """
    Send an email asynchronously using the configured SMTP credentials.

    - body: HTML body
    - text_body: optional plain text fallback
    - inline_images: optional dict {cid: filepath} for CID inline images
      Example HTML: <img src="cid:myesi-logo" />
      Example inline_images: {"myesi-logo": "/app/images/myesi_logo.png"}
    """
    if not recipients:
        return

    if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        logger.warning(
            "SMTP credentials missing; skipping email to %s", ",".join(recipients)
        )
        return

    message = _build_message(
        subject,
        body,
        recipients,
        text_body=text_body,
        inline_images=inline_images,
    )

    def _send_sync() -> None:
        try:
            with smtplib.SMTP(
                settings.SMTP_HOST, settings.SMTP_PORT, timeout=30
            ) as smtp:
                if settings.SMTP_USE_TLS:
                    smtp.starttls()
                smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                smtp.send_message(message)
        except Exception as exc:
            logger.error("Failed to send email: %s", exc, exc_info=True)

    await asyncio.to_thread(_send_sync)

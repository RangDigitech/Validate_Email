import os
import ssl
import smtplib
from email.message import EmailMessage
from typing import Any, Iterable, Mapping, Sequence
from dotenv import load_dotenv

load_dotenv()


MAIL_USERNAME = os.getenv("MAIL_USERNAME")      # Gmail address
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")      # 16-char App Password
MAIL_FROM = os.getenv("MAIL_FROM") or MAIL_USERNAME
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME") or "AI Email Verifier"
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "465"))  # 465 = SSL, 587 = TLS


def _make_msg(
    to: str,
    subject: str,
    html_body: str,
    text_body: str = None,
    reply_to: str = None,
    attachments: Sequence[Mapping[str, Any]] | None = None,
) -> EmailMessage:
    """Builds an email message with HTML + fallback text (and optional attachments)."""
    msg = EmailMessage()
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM}>"
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to

    # Prepare a text fallback so email clients without HTML support still see content.
    fallback_text = text_body or "HTML email - no text version provided"

    if attachments:
        # When attachments exist we must ensure the top-level part is multipart/mixed
        # and the text/HTML pair lives inside a nested multipart/alternative part.
        msg.make_mixed()
        alternative = EmailMessage()
        alternative.set_content(fallback_text)
        alternative.add_alternative(html_body, subtype="html")
        msg.attach(alternative)
    else:
        msg.set_content(fallback_text)
        msg.add_alternative(html_body, subtype="html")

    if attachments:
        for attachment in attachments:
            if not attachment:
                continue
            data = attachment.get("data") or attachment.get("content")
            if not data:
                continue
            filename = attachment.get("filename") or "attachment"
            content_type = attachment.get("content_type") or "application/octet-stream"
            if "/" in content_type:
                maintype, subtype = content_type.split("/", 1)
            else:
                maintype, subtype = "application", "octet-stream"
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    return msg


def send_email_smtp(msg: EmailMessage):
    """Send email using Gmail SMTP."""
    if MAIL_PORT == 465:  # SSL
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, context=context) as server:
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
    else:  # STARTTLS (587)
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=30) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
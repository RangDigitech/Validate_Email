import os
import ssl
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()


MAIL_USERNAME = os.getenv("MAIL_USERNAME")      # Gmail address
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")      # 16-char App Password
MAIL_FROM = os.getenv("MAIL_FROM") or MAIL_USERNAME
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME") or "AI Email Verifier"
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "465"))  # 465 = SSL, 587 = TLS


def _make_msg(to: str, subject: str, html_body: str, text_body: str = None, reply_to: str = None) -> EmailMessage:
    """Builds an email message with HTML + fallback text."""
    msg = EmailMessage()
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM}>"
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to

    # Plain text fallback
    if text_body:
        msg.set_content(text_body)
    else:
        msg.set_content("HTML email - no text version provided")

    msg.add_alternative(html_body, subtype="html")
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
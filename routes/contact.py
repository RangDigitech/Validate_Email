# routes/contact.py
from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, EmailStr, constr
import os
from utils.emailer import _make_msg, send_email_smtp, MAIL_FROM

router = APIRouter()


class ContactForm(BaseModel):
    name: constr(min_length=1, max_length=120)
    email: EmailStr
    phone: str | None = None
    subject: constr(min_length=1, max_length=200)
    message: constr(min_length=1, max_length=5000)


ADMIN_EMAIL = os.getenv("ADMIN_EMAIL") or MAIL_FROM
SITE_NAME = os.getenv("SITE_NAME", "AI Email Verifier")
SITE_URL = os.getenv("SITE_URL", "https://yourwebsite.com")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", ADMIN_EMAIL)


# small helper to build footer HTML
def _email_footer_html():
    return f"""
    <hr style="border:none;border-top:1px solid #e6e6e6;margin:20px 0;" />
    <p style="font-size:12px;color:#777;margin:0;">
      Sent by <strong>{SITE_NAME}</strong> — <a href="{SITE_URL}" style="color:#5d1590;text-decoration:none">{SITE_URL}</a><br/>
      For support, email <a href="mailto:{SUPPORT_EMAIL}" style="color:#5d1590">{SUPPORT_EMAIL}</a>
    </p>
    <p style="font-size:11px;color:#999;margin-top:8px;">
      If you didn't contact us, you can safely ignore this message. Do not reply to this auto-message unless necessary.
    </p>
    """

def _email_footer_text():
    return f"\n---\nSent by {SITE_NAME} - {SITE_URL}\nSupport: {SUPPORT_EMAIL}\nIf you didn't contact us, you can ignore this message.\n"


@router.post("/contact")
async def submit_contact_form(data: ContactForm, background_tasks: BackgroundTasks):
    admin_subject = f"📩 New message from {data.name}"

    admin_html = f"""
    <div style="font-family: Arial, sans-serif; padding: 10px;">
      <h2 style="color:#5d1590; margin-top:0;">New Contact Form Submission</h2>
      <p><strong>Name:</strong> {data.name}</p>
      <p><strong>Email:</strong> {data.email}</p>
      <p><strong>Phone:</strong> {data.phone or "Not provided"}</p>
      <p><strong>Subject:</strong> {data.subject}</p>
      <hr/>
      <p><strong>Message:</strong></p>
      <p style="white-space: pre-line;">{data.message}</p>
      { _email_footer_html() }
    </div>
    """

    admin_text = f"""New Contact Form Submission

Name: {data.name}
Email: {data.email}
Phone: {data.phone or 'Not provided'}
Subject: {data.subject}

Message:
{data.message}

{_email_footer_text()}
"""

    user_subject = "✅ We received your message"
    user_html = f"""
    <div style="font-family: Arial, sans-serif; padding: 10px;">
      <h2 style="color:#5d1590; margin-top:0;">Thanks for contacting us, {data.name}!</h2>
      <p>We've received your message and will reply within <strong>24 hours</strong>.</p>

      <p><strong>Your message:</strong></p>
      <div style="background:#f5f5f5; padding:12px; border-left:4px solid #5d1590; border-radius:4px; white-space:pre-line;">
        <p><strong>Subject:</strong> {data.subject}</p>
        <p><strong>Message:</strong><br/>{data.message}</p>
      </div>

      <p style="margin-top:12px;">If you need immediate help, reply to this email or contact support at <a href="mailto:{SUPPORT_EMAIL}" style="color:#5d1590">{SUPPORT_EMAIL}</a>.</p>

      { _email_footer_html() }
    </div>
    """

    user_text = f"""Hi {data.name},

Thanks for contacting us. We received your message and will reply within 24 hours.

Your message:
Subject: {data.subject}
Message: {data.message}

{_email_footer_text()}
"""

    def send_emails():
        # send to admin
        msg_admin = _make_msg(
            to=ADMIN_EMAIL,
            subject=admin_subject,
            html_body=admin_html,
            text_body=admin_text,
            reply_to=data.email
        )
        send_email_smtp(msg_admin)

        # send auto-reply to user
        msg_user = _make_msg(
            to=data.email,
            subject=user_subject,
            html_body=user_html,
            text_body=user_text,
            reply_to=ADMIN_EMAIL
        )
        send_email_smtp(msg_user)

    background_tasks.add_task(send_emails)

    return {"success": True, "message": "Message received. Check your email!"}

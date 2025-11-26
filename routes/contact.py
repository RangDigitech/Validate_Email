# routes/contact.py
from fastapi import APIRouter, BackgroundTasks, UploadFile, File, Form, HTTPException
from pydantic import BaseModel, EmailStr, constr, ValidationError
import os
import mimetypes
import logging
from utils.emailer import _make_msg, send_email_smtp, MAIL_FROM

router = APIRouter()
logger = logging.getLogger(__name__)


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


MAX_ATTACHMENT_SIZE = int(os.getenv("CONTACT_ATTACHMENT_MAX_BYTES", 5 * 1024 * 1024))  # 5 MB
ALLOWED_ATTACHMENT_MIME_PREFIXES = os.getenv(
    "CONTACT_ATTACHMENT_MIME_PREFIXES",
    "image/,application/pdf,application/msword,application/vnd,application/,text/",
).split(",")


def _human_filesize(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


async def _prepare_attachment(file: UploadFile | None) -> dict | None:
    if not file:
        return None
    contents = await file.read()
    if not contents:
        return None
    if len(contents) > MAX_ATTACHMENT_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Attachment too large. Max allowed is {_human_filesize(MAX_ATTACHMENT_SIZE)}.",
        )
    content_type = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    if content_type:
        allowed = any(
            content_type.startswith(prefix.strip())
            for prefix in ALLOWED_ATTACHMENT_MIME_PREFIXES
            if prefix.strip()
        )
        if not allowed:
            raise HTTPException(status_code=400, detail="Unsupported attachment type.")
    filename = os.path.basename(file.filename or "attachment")
    logger.info("Contact attachment accepted: %s (%s, %d bytes)", filename, content_type, len(contents))
    return {
        "filename": filename,
        "data": contents,
        "content_type": content_type,
        "size": len(contents),
    }


@router.post("/contact")
async def submit_contact_form(
    background_tasks: BackgroundTasks,
    name: str | None = Form(None),
    email: str | None = Form(None),
    phone: str | None = Form(None),
    subject: str | None = Form(None),
    message: str | None = Form(None),
    attachments: list[UploadFile] = File(default=[]),  
) -> dict:
    try:
        data = ContactForm(name=name, email=email, phone=phone, subject=subject, message=message)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.errors())

    # Debug logging
    logger.info(f"Contact form received - attachments count: {len(attachments)}")
    for f in attachments:
        logger.info(f"Incoming attachment: {f.filename}, content_type: {f.content_type}")

    prepared_attachments: list[dict] = []
    for f in attachments:
        prepared = await _prepare_attachment(f)
        if prepared:
            prepared_attachments.append(prepared)

    if prepared_attachments:
        logger.info(
            "Prepared %d attachment(s): %s",
            len(prepared_attachments),
            ", ".join(a["filename"] for a in prepared_attachments),
        )
    else:
        logger.info("No attachments prepared")

    attachment_payload = (
        [
            {
                "filename": a["filename"],
                "data": a["data"],
                "content_type": a["content_type"],
            }
            for a in prepared_attachments
        ]
        if prepared_attachments
        else None
    )
    
    # Debug logging
    logger.info(f"Attachment payload created: {attachment_payload is not None}")
    attachment_html_block = ""
    attachment_text_block = ""
    if prepared_attachments:
        # Text version
        lines = [
            f"- {a['filename']} ({_human_filesize(a['size'])})"
            for a in prepared_attachments
        ]
        attachment_text_block = "Attachments:\n" + "\n".join(lines) + "\n"

        # HTML version
        items = [
            f"<li>{a['filename']} ({_human_filesize(a['size'])})</li>"
            for a in prepared_attachments
        ]
        attachment_html_block = "<p><strong>Attachments:</strong></p><ul>" + "".join(items) + "</ul>"

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
      {attachment_html_block}
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

    {attachment_text_block}
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

    def send_emails(attachments_payload: list | None):
        # Debug logging
        logger.info(f"send_emails called with attachments: {attachments_payload is not None}")
        if attachments_payload:
            logger.info(f"Attachments count: {len(attachments_payload)}, first file: {attachments_payload[0].get('filename')}")
        
        # send to admin
        msg_admin = _make_msg(
            to=ADMIN_EMAIL,
            subject=admin_subject,
            html_body=admin_html,
            text_body=admin_text,
            reply_to=data.email,
            attachments=attachments_payload,
        )
        logger.info(f"Admin email message created, is_multipart: {msg_admin.is_multipart()}")
        send_email_smtp(msg_admin)
        logger.info("Admin email sent successfully")

        # send auto-reply to user
        msg_user = _make_msg(
            to=data.email,
            subject=user_subject,
            html_body=user_html,
            text_body=user_text,
            reply_to=ADMIN_EMAIL,
        )
        send_email_smtp(msg_user)

    background_tasks.add_task(send_emails, attachment_payload)

    return {
        "success": True,
        "message": "Message received. Check your email!",
        "attachments_received": len(prepared_attachments),
        "attachment_filenames": [a["filename"] for a in prepared_attachments],
    }

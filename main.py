import os
import json
import uuid
import tempfile
import asyncio
from datetime import datetime
# main.py (extra imports)
from typing import List
from sqlalchemy import select, desc, exists
from sqlalchemy.orm import Session
from security import get_current_user               # <-- use auth

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, status, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from json import loads as _json_loads
import unicodedata

# Local module imports
import models
import schemas
import security
from database import SessionLocal, engine, get_db
from app import validate_single_async, load_emails_from_csv, validate_many_async, write_outputs
import os, secrets
from urllib.parse import urlencode
import httpx
from fastapi import Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import dns.resolver
import re
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, and_, desc
from fastapi import Depends
from sqlalchemy import extract
from pydantic import BaseModel ,EmailStr
from sqlalchemy import func
from routes.contact import router as contact_router
from blog_routes import router as blog_router
import os, uuid
from pathlib import Path
from redis import Redis
from rq import Queue
from queue_utils import split_csv, init_job, job_status
from tasks_rq import verify_chunk
from fastapi import Path


REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
rconn = Redis.from_url(REDIS_URL)
rq_bulk = Queue("bulk", connection=rconn)
CHUNK_SIZE_DEFAULT = 5000

class _UserStatusIn(BaseModel):
    is_active: bool

def admin_required(current_user: models.User = Depends(security.get_current_user)):
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin only")
    return current_user

def has_mx(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return any(answers)
    except Exception:
        return False

load_dotenv() 

FRONTEND_ORIGIN = os.getenv("OAUTH_FRONTEND_ORIGIN", "https://rangdigitech.net").rstrip("/")
# FRONTEND_ORIGIN = os.getenv("OAUTH_FRONTEND_ORIGIN", "http://localhost:5173").rstrip("/")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET", "")
RECAPTCHA_DISABLED = os.getenv("RECAPTCHA_DISABLED", "0") == "1"


# This creates the 'users' table in your database if it doesn't exist
models.Base.metadata.create_all(bind=engine)


app = FastAPI(title="Email Verifier API", version="3.0")
app.include_router(contact_router,prefix="/api")

app.include_router(blog_router)

# In-memory job store (for a real app, use a database or Redis)
JOBS = {}

# Fix the origins list - add comma and include both http and https variants
origins = [
    "http://localhost:5173",
    "https://localhost:5173",
    "http://127.0.0.1:5173",
    "https://127.0.0.1:5173",
    "http://127.0.0.1:8000",
    "https://127.0.0.1:8000",
    "https://rangdigitech.net"
]

# --- CORRECT AND FINAL CORS CONFIGURATION ---
# There should only be ONE of these blocks.
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,         # The origin of your React app
    allow_credentials=True,        # This MUST be True for login systems
    allow_methods=["*"],
    allow_headers=["*"],           # allows Authorization header too
)

class ContactIn(BaseModel):
    name: str | None = None
    email: EmailStr
    phone: str | None = None
    subject: str | None = None
    message: str | None = None
    recaptcha_token: str

@app.post("/contact/submit")
async def contact_submit(payload: ContactIn, request: Request, db: Session = Depends(get_db)):
    # Verify captcha
    await verify_recaptcha_or_400(payload.recaptcha_token, request.client.host if request.client else None)

    # TODO: save to DB or send email/Slack—up to you
    # Example (optional):
    # db.add(models.ContactMessage(...)); db.commit()

    return {"ok": True, "received": {
        "name": payload.name,
        "email": payload.email,
        "phone": payload.phone,
        "subject": payload.subject,
        "message": payload.message,
    }}

async def verify_recaptcha_or_400(token: str, remote_ip: str | None = None):
    """
    Verify Google reCAPTCHA token. Raise 400 if invalid.
    Set RECAPTCHA_DISABLED=1 in .env to bypass in local dev.
    """
    if RECAPTCHA_DISABLED:
        return True
    if not RECAPTCHA_SECRET:
        raise HTTPException(status_code=500, detail="Server captcha is not configured")
    if not token:
        raise HTTPException(status_code=400, detail="Missing captcha token")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            data = {
                "secret": RECAPTCHA_SECRET,
                "response": token
            }
            if remote_ip:
                data["remoteip"] = remote_ip
            r = await client.post("https://www.google.com/recaptcha/api/siteverify", data=data)
            j = r.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Captcha verification failed")

    if not j.get("success"):
        # Optional: log j.get("error-codes")
        raise HTTPException(status_code=400, detail="Invalid captcha")
    return True

# --- LIGHTWEIGHT public email check (no auth, no credits)
@app.get("/utils/check-email")
async def utils_check_email(email: str):
    """
    Quick email check for signup:
    - validates syntax
    - runs domain-level disposable detection (fast path: no SMTP)
    - returns minimal flags for UI
    """
    try:
        res = await validate_single_async(
            email=email,
            smtp_from="noreply@example.com",
            db_path=None,
            smtp_probe_flag=False,   # FAST: no SMTP handshake
        )
        return {
            "ok": True,
            "email": res.get("email"),
            "syntax_ok": bool(res.get("syntax_ok")),
            "domain": res.get("domain"),
            "disposable": bool(res.get("disposable")),
            "reason": res.get("reason") or (", ".join(res.get("notes") or []) or None),
        }
    except Exception as ex:
        return JSONResponse(
            status_code=200,
            content={"ok": False, "error": str(ex), "disposable": None, "syntax_ok": None},
        )

# --- HELPERS ---

import re

# --- DUPLICATE / NORMALIZATION HELPERS ---

def normalize_email_addr(raw: str) -> str:
    """Trim and lower-case the address for de-dupe checks."""
    return (raw or "").strip().lower()

def has_user_checked_email(db: Session, user_id: int, email: str) -> bool:
    """True if this user has ever verified this exact email before."""
    norm = normalize_email_addr(email)
    return db.query(models.EmailsChecked.id).filter(
        models.EmailsChecked.user_id == user_id,
        models.EmailsChecked.email == norm
    ).first() is not None

def get_existing_emails_set(db: Session, user_id: int, emails: list[str]) -> set[str]:
    """Fetch all already-seen emails for this user from a provided list."""
    if not emails:
        return set()
    normalized = [normalize_email_addr(e) for e in emails if e]
    rows = (
        db.query(models.EmailsChecked.email)
        .filter(models.EmailsChecked.user_id == user_id)
        .filter(models.EmailsChecked.email.in_(normalized))
        .all()
    )
    return {r[0] for r in rows}

def compute_char_stats(local_part: str):
    nums = sum(c.isdigit() for c in local_part)
    alphas = sum(c.isalpha() for c in local_part)
    # "Unicode symbols" = characters that are not alnum and not ASCII punctuation/underscore
    # This is a pragmatic definition; adjust if you track a different meaning.
    unicode_syms = 0
    for c in local_part:
        if c.isalnum() or c in "._-+":
            continue
        # count anything else that isn't a space as a symbol
        if not c.isspace():
            unicode_syms += 1
    return nums, alphas, unicode_syms



def validate_password_strength(password: str):
    """
    Ensures password meets minimum security requirements:
    - At least 8 characters
    - Contains uppercase, lowercase, number, and special character
    """
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one number.")
    if not re.search(r"[@$!%*?&]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character (@, $, !, %, *, ?, &).")


def ensure_user_credits(db: Session, user_id: int) -> "models.UserCredits":
    uc = db.query(models.UserCredits).filter(models.UserCredits.user_id == user_id).first()
    if not uc:
        uc = models.UserCredits(user_id=user_id, remaining_credits=0, used_credits=0)
        db.add(uc); db.commit(); db.refresh(uc)
    return uc

def _ledger_add(db: Session, user_id: int, kind: str, units: int, source: str = None, ref: str = None):
    """Internal: write one ledger row (positive or negative)."""
    row = models.CreditLedger(user_id=user_id, kind=kind, units=units, source=source, ref=ref)
    db.add(row)
    db.commit()

def add_credits(db: Session, user_id: int, units: int, source: str = "system/topup"):
    """Increase balance and write a +ledger row."""
    uc = ensure_user_credits(db, user_id)
    uc.remaining_credits += units
    db.add(uc); db.commit()
    _ledger_add(db, user_id, kind="topup", units=units, source=source)

def charge_credits(db: Session, user_id: int, units: int, kind: str, source: str = None, ref: str = None):
    """
    Spend credits atomically; units is the number of credits to deduct (positive int).
    Writes a -ledger row with the provided kind ('single'|'bulk'|'api'|'other').
    """
    uc = ensure_user_credits(db, user_id)
    if uc.remaining_credits < units:
        raise HTTPException(status_code=402, detail="Insufficient credits")
    uc.remaining_credits -= units
    uc.used_credits += units
    db.add(uc); db.commit()
    _ledger_add(db, user_id, kind=kind, units=-units, source=source, ref=ref)


def record_result(db: Session, user_id: int, res: dict) -> int:
    """Insert into email_verifications + upsert emails_checked. Returns verification id."""
    from json import dumps
    email = (res.get("email") or "").strip()
    domain = res.get("domain")
    ev = models.EmailVerification(
        user_id=user_id,
        email=email,
        status=res.get("final_status"),
        state=res.get("state"),
        reason=res.get("reason"),
        score=res.get("score"),
        domain=domain,
        local_part=res.get("local_part"),
        free=bool(res.get("free")),
        role=bool(res.get("role")),
        disposable=bool(res.get("disposable")),
        accept_all=bool(res.get("accept_all")),
        smtp_provider=res.get("smtp_provider"),
        mx_record=res.get("mx_record"),
        catch_all=res.get("catch_all"),
        smtp_ok=bool(res.get("smtp_ok")),
        result_json=dumps(res, ensure_ascii=False),
    )
    db.add(ev)

    # upsert into EmailsChecked
    ec = (
        db.query(models.EmailsChecked)
        .filter(models.EmailsChecked.user_id == user_id, models.EmailsChecked.email == email)
        .first()
    )
    if not ec:
        ec = models.EmailsChecked(
            user_id=user_id,
            email=email,
            total_checks=1,
            last_status=res.get("final_status"),
            last_score=res.get("score"),
        )
        db.add(ec)
    else:
        from sqlalchemy.sql import func as _func
        ec.total_checks = (ec.total_checks or 0) + 1
        ec.last_status = res.get("final_status")
        ec.last_score = res.get("score")
        ec.last_checked_at = _func.now()
        db.add(ec)

    db.commit(); db.refresh(ev)
    return ev.id

@app.get("/")
async def root():
    return {"status": "ok", "message": "Welcome to the Email Verifier API"}

# ---------- GOOGLE ----------
@app.get("/oauth/google/start")
async def oauth_google_start(request: Request):
    redirect_uri = str(request.url_for("oauth_google_callback"))
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return RedirectResponse(auth_url)

@app.get("/oauth/google/callback", name="oauth_google_callback")
async def oauth_google_callback(request: Request, db: Session = Depends(get_db)):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(400, "Missing code")

    redirect_uri = str(request.url_for("oauth_google_callback"))

    async with httpx.AsyncClient(timeout=15) as client:
        token_data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        tok = (await client.post("https://oauth2.googleapis.com/token", data=token_data)).json()
        userinfo = (await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {tok.get('access_token')}"},
        )).json()

    email = (userinfo.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(400, "Google did not return an email")

    first_name = userinfo.get("given_name") or ""
    last_name  = userinfo.get("family_name") or ""

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        random_pw = secrets.token_urlsafe(24)
        hashed = security.get_password_hash(random_pw)
        user = models.User(email=email, hashed_password=hashed, first_name=first_name, last_name=last_name)
        db.add(user); db.commit(); db.refresh(user)
        # seed credits if your register endpoint does this
        if not db.query(models.UserCredits).filter(models.UserCredits.user_id == user.id).first():
            db.add(models.UserCredits(user_id=user.id, remaining_credits=250, used_credits=0)); db.commit()

    jwt_token = security.create_access_token(data={"sub": user.email})
    return RedirectResponse(f"{FRONTEND_ORIGIN}/oauth/callback#token={jwt_token}")

# ---------- GITHUB ----------
@app.get("/oauth/github/start")
async def oauth_github_start(request: Request):
    redirect_uri = str(request.url_for("oauth_github_callback"))
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "user:email",
        "allow_signup": "true",
    }
    auth_url = "https://github.com/login/oauth/authorize?" + urlencode(params)
    return RedirectResponse(auth_url)

@app.get("/oauth/github/callback", name="oauth_github_callback")
async def oauth_github_callback(request: Request, db: Session = Depends(get_db)):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(400, "Missing code")

    redirect_uri = str(request.url_for("oauth_github_callback"))

    async with httpx.AsyncClient(timeout=15) as client:
        # Exchange code -> token
        headers = {"Accept": "application/json"}
        data = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        tok = (await client.post("https://github.com/login/oauth/access_token", data=data, headers=headers)).json()

        # Get user profile + emails
        me = (await client.get("https://api.github.com/user",
                               headers={"Authorization": f"Bearer {tok.get('access_token')}",
                                        "Accept": "application/vnd.github+json"})).json()
        em = (await client.get("https://api.github.com/user/emails",
                               headers={"Authorization": f"Bearer {tok.get('access_token')}",
                                        "Accept": "application/vnd.github+json"})).json()

    # pick primary email (fallback to first)
    email_obj = next((x for x in em if x.get("primary")), (em[0] if isinstance(em, list) and em else {}))
    email = (email_obj.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(400, "GitHub did not return an email")

    name = (me.get("name") or "").strip()
    if name and " " in name:
        first_name, last_name = name.split(" ", 1)
    else:
        first_name = name or (email.split("@")[0] if email else "User")
        last_name = ""

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        random_pw = secrets.token_urlsafe(24)
        hashed = security.get_password_hash(random_pw)
        user = models.User(email=email, hashed_password=hashed, first_name=first_name, last_name=last_name)
        db.add(user); db.commit(); db.refresh(user)
        if not db.query(models.UserCredits).filter(models.UserCredits.user_id == user.id).first():
            db.add(models.UserCredits(user_id=user.id, remaining_credits=250, used_credits=0)); db.commit()

    jwt_token = security.create_access_token(data={"sub": user.email})
    return RedirectResponse(f"{FRONTEND_ORIGIN}/oauth/callback#token={jwt_token}")


# --- AUTHENTICATION ENDPOINTS ---

@app.post("/register", response_model=schemas.User)
async def create_user(
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),  
    db: Session = Depends(get_db)
):
    try:
        # Debug logging
        print(f"Received registration data: first_name={first_name}, last_name={last_name}, email={email}")

        # Validate input data
        if not all([email, password, first_name, last_name]):
            missing_fields = []
            if not first_name: missing_fields.append('first_name')
            if not last_name: missing_fields.append('last_name')
            if not email: missing_fields.append('email')
            if not password: missing_fields.append('password')
            raise HTTPException(
                status_code=400,
                detail=f"Missing required fields: {', '.join(missing_fields)}"
            )

        # Check existing user
        try:
            db_user = db.query(models.User).filter(models.User.email == email).first()
            if db_user:
                raise HTTPException(status_code=400, detail="Email already registered")
        except Exception as e:
            print(f"Database query error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}")
        
        # Validate password strength
        validate_password_strength(password)

        # Create new user
        try:
            hashed_password = security.get_password_hash(password)
            db_user = models.User(
                email=email,
                hashed_password=hashed_password,
                first_name=first_name,
                last_name=last_name
            )
            print("Attempting to add user to database...")
            db.add(db_user)
            print("Committing transaction...")
            db.commit()
            print("Refreshing user object...")
            db.refresh(db_user)
            FREE_SIGNUP_CREDITS = 250
            add_credits(db, db_user.id, FREE_SIGNUP_CREDITS, source="signup_bonus")

            print("User successfully created")
            return db_user
        except Exception as db_error:
            db.rollback()
            print(f"Detailed database error: {str(db_error)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(db_error)}")

    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Unexpected registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
# --- AUTHENTICATION ENDPOINTS ---

@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(request: Request, db: Session = Depends(get_db)):
    try:
        form = await request.form()
        email = (form.get("email") or form.get("username") or "").strip()
        password = (form.get("password") or "").strip()

        # NEW: verify captcha before any DB work
        recaptcha_token = form.get("recaptcha_token") or ""
        await verify_recaptcha_or_400(recaptcha_token, request.client.host if request.client else None)

        if not email or not password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and password required")

        user = db.query(models.User).filter(models.User.email == email).first()
        if not user or not security.verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

        # IMPORTANT: also block deactivated users at login (your earlier ask)
        if getattr(user, "is_active", True) is False:
            raise HTTPException(status_code=403, detail="This account is deactivated")

        access_token = security.create_access_token(data={"sub": user.email})
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Login failed")

# --- EMAIL VERIFICATION ENDPOINTS ---

@app.post("/validate-email")
async def single_email_validation(
    email: str = Form(...),
    smtp: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user)
):
    norm_email = normalize_email_addr(email)

    # Charge only if this user hasn't verified this exact email before
    already_checked = has_user_checked_email(db, current_user.id, norm_email)
    credits_charged = 0
    if not already_checked:
        charge_credits(db, current_user.id, 1, kind="single", source=f"single:{norm_email}")
        credits_charged = 1

    # Run verification (you can later add a cache shortcut if you want)
    res = await validate_single_async(norm_email, "noreply@example.com", None, smtp)
    res["deliverable"] = (res.get("final_status") == "valid")
    res["state"] = res.get("state")

    lp = (res.get("local_part") or "").strip()
    if lp:
        nums, alphas, unic = compute_char_stats(lp)
        res["numerical_characters"] = nums
        res["alphabetical_characters"] = alphas
        res["unicode_symbols"] = unic

    ver_id = record_result(db, current_user.id, res)
    return {
        "result": res,
        "verification_id": ver_id,
        "credits_charged": credits_charged,
        "duplicate": already_checked
    }
# --- REPLACE current /validate-file with an enqueueing version ---
@app.post("/validate-file")
async def file_validation_enqueued(
    file: UploadFile = File(...),
    smtp: bool = Form(False),
    workers: int = Form(12),
    name: str = Form(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user)
):
    jobid = uuid.uuid4().hex

    tmp_input_path = os.path.join(tempfile.gettempdir(), f"{jobid}_{file.filename}")
    outdir = os.path.join(tempfile.gettempdir(), f"results_{jobid}")
    os.makedirs(outdir, exist_ok=True)

    with open(tmp_input_path, "wb") as f:
        content = await file.read()
        f.write(content)

    raw_emails = load_emails_from_csv(tmp_input_path)
    emails = [normalize_email_addr(e) for e in raw_emails if e]
    if not emails:
        raise HTTPException(status_code=400, detail="No emails found")

    # Credits (keep your logic)
    existing = get_existing_emails_set(db, current_user.id, emails)
    to_charge = [e for e in set(emails) if e not in existing]
    credits_to_charge = len(to_charge)
    if credits_to_charge > 0:
        charge_credits(db, current_user.id, credits_to_charge,
                       kind="bulk", source="POST /validate-file", ref=jobid)

    # Make bulk job record
    job_name = (name or os.path.splitext(file.filename or "")[0] or f"Upload {datetime.utcnow().date()}")[:120]
    bulk_job = models.BulkJob(
        id=jobid,
        user_id=current_user.id,
        name=job_name,
        total_emails=len(emails),
    )
    db.add(bulk_job)
    db.commit(); db.refresh(bulk_job)

    # Chunk & enqueue
    chunk_size = int(os.getenv("BULK_CHUNK_SIZE", CHUNK_SIZE_DEFAULT))
    chunks = [emails[i:i+chunk_size] for i in range(0, len(emails), chunk_size)]

    # store a small progress JSON in Redis
    rconn.hset(f"bulk:{jobid}", mapping={
        "total": len(emails),
        "done": 0,
        "chunks": len(chunks),
        "status": "queued",
        "outdir": outdir,
        "smtp": "1" if smtp else "0",
        "uid": str(current_user.id),
    })

    # for idx, chunk in enumerate(chunks):
    #     rq_bulk.enqueue(
    #         verify_chunk,
    #         jobid,
    #         idx,
    #         chunk,
    #         smtp,
    #         current_user.id,
    #         outdir,
    #         job_timeout=3600,      # per-chunk timeout
    #         result_ttl=86400,      # keep results for 1 day
    #         failure_ttl=86400
    #     )

    # return {"jobid": jobid, "chunks": len(chunks), "status": "queued"}

    for idx, chunk in enumerate(chunks):
        try:
            job = rq_bulk.enqueue(
            verify_chunk,
            jobid,
            idx,
            chunk,
            smtp,
            current_user.id,
            outdir,
            job_timeout=3600,      # per-chunk timeout
            result_ttl=86400,
            failure_ttl=86400
            )
        # ↓↓↓ add a strong trace so we know the API actually queued work
            print(f"[BULK][ENQ] jobid={jobid} idx={idx} size={len(chunk)} rq_id={job.id}")
        except Exception as e:
        # fail visible: UI won’t hang at 0 with unknown cause
            rconn.hset(f"bulk:{jobid}", mapping={"status": "error"})
            print(f"[BULK][ENQ-FAIL] jobid={jobid} idx={idx} err={e}")
            raise
        return {"jobid": jobid, "chunks": len(chunks), "status": "queued"}


@app.get("/download/{jobid}/{name}")
async def download_file(jobid: str, name: str):
    key = f"bulk:{jobid}"
    meta = rconn.hgetall(key)
    if not meta:
        raise HTTPException(status_code=404, detail="Job not found")

    outdir = (meta.get(b"outdir") or b"").decode()
    if not outdir:
        outdir = os.path.join(tempfile.gettempdir(), f"results_{jobid}")

    if name not in ("results.csv", "results.json"):
        raise HTTPException(status_code=400, detail="Invalid filename.")

    path = os.path.join(outdir, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found.")

    media_type = "text/csv" if name.endswith(".csv") else "application/json"
    return FileResponse(path, media_type=media_type, filename=name)

# --- NEW: CREDITS & RECENT EMAILS ENDPOINTS ---

@app.get("/me/credits")
def get_credits(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    uc = ensure_user_credits(db, current_user.id)
    return {"remaining_credits": uc.remaining_credits, "used_credits": uc.used_credits}

@app.get("/me/recent-emails")
def get_recent_emails(
    limit: int = 12,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    # order by id desc and EXCLUDE bulk-linked records (NOT EXISTS is most portable)
    bulk_exists = (
        db.query(models.BulkItem.id)
        .filter(models.BulkItem.verification_id == models.EmailVerification.id)
        .exists()
    )

    q = (
        db.query(models.EmailVerification)
        .filter(models.EmailVerification.user_id == current_user.id)
        .filter(~bulk_exists)
        .order_by(desc(models.EmailVerification.id))
        .limit(max(1, min(limit, 200)))
    )
    rows = q.all()
    return [
        {
            "id": r.id,
            "email": r.email,
            "state": r.state,
            "score": r.score,
            "created_at": getattr(r, "created_at", None),
        }
        for r in rows
    ]

# --- Bulk job listing endpoints ---

@app.get("/bulk/jobs")
def list_bulk_jobs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    rows = (
        db.query(models.BulkJob)
        .filter(models.BulkJob.user_id == current_user.id)
        .order_by(desc(models.BulkJob.created_at))
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "total_emails": r.total_emails,
            "created_at": r.created_at,
        }
        for r in rows
    ]

@app.get("/bulk/jobs/{jobid}")
def get_bulk_job(
    jobid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    job = (
        db.query(models.BulkJob)
        .filter(models.BulkJob.id == jobid, models.BulkJob.user_id == current_user.id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Bulk job not found")

    # fetch linked verifications
    ver_rows = (
        db.query(models.EmailVerification)
        .join(models.BulkItem, models.BulkItem.verification_id == models.EmailVerification.id)
        .filter(models.BulkItem.job_id == jobid)
        .order_by(desc(models.EmailVerification.id))
        .all()
    )

    # simple aggregates for UI
    totals = {"valid": 0, "risky": 0, "invalid": 0}
    for v in ver_rows:
        s = (v.status or "").lower()
        if s in totals:
            totals[s] += 1

    return {
        "id": job.id,
        "name": job.name,
        "total_emails": job.total_emails,
        "created_at": job.created_at,
        "counts": totals,
        "rows": [
            {
                "id": v.id,
                "email": v.email,
                "state": v.state,
                "score": v.score,
                "reason": v.reason,
                "status": v.status,
                "created_at": v.created_at,
            }
            for v in ver_rows
        ],
    }

@app.get("/verifications/{ver_id}")
def get_verification(
    ver_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    v = (
        db.query(models.EmailVerification)
        .filter(models.EmailVerification.id == ver_id,
                models.EmailVerification.user_id == current_user.id)
        .first()
    )
    if not v:
        raise HTTPException(status_code=404, detail="Verification not found")

    # Parse the raw result we stored at verify time
    raw = {}
    try:
        raw = _json_loads(v.result_json or "{}")
    except Exception:
        raw = {}

    # Return a merged object: indexed summary + raw fields frontends expect
    return {
        "id": v.id,
        "email": v.email,
        "domain": v.domain,
        "local_part": v.local_part,
        "final_status": v.status,          # "valid"/"risky"/"invalid"
        "state": v.state,                  # "Deliverable"/"Risky"/"Undeliverable"
        "reason": v.reason,
        "score": v.score,
        "free": v.free,
        "role": v.role,
        "disposable": v.disposable,
        "accept_all": v.accept_all,
        "smtp_provider": v.smtp_provider,
        "mx_record": v.mx_record,
        "catch_all": v.catch_all,
        "smtp_ok": v.smtp_ok,
        "created_at": v.created_at,
        # Pass through any detailed attributes your UI renders:
        "numerical_characters": raw.get("numerical_characters"),
        "alphabetical_characters": raw.get("alphabetical_characters"),
        "unicode_symbols": raw.get("unicode_symbols"),
        "mailbox_full": raw.get("mailbox_full"),
        "no_reply": raw.get("no_reply"),
        "secure_email_gateway": raw.get("secure_email_gateway"),
        "implicit_mx_record": raw.get("implicit_mx_record"),
        # keep entire raw object in case UI needs more:
        "raw": raw,
    }

@app.get("/me")
def get_me(current_user: models.User = Depends(security.get_current_user)):
    return {
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "is_admin": bool(getattr(current_user, "is_admin", False)),
        "is_active": bool(getattr(current_user, "is_active", True)),
    }

# --- Local-only OAuth start (dev shim) ---
# The frontend calls /oauth/{provider}/start?next=<frontend>/oauth/callback
# We ensure `next` points to localhost/127.0.0.1 and then redirect to
# <next>#token=<jwt>, so OAuthCallback.jsx can complete sign-in locally.

@app.get("/oauth/{provider}/start")
def oauth_start(provider: str, next: str = "", db: Session = Depends(get_db)):
    from urllib.parse import urlparse

    target = next or f"{FRONTEND_ORIGIN}/oauth/callback"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("localhost", "127.0.0.1"):
        return JSONResponse(status_code=400, content={"error": "Local OAuth allowed only for localhost/127.0.0.1"})

    try:
        # Create or fetch a local dev user so the dashboard can load profile/name/credits
        email = f"dev_{provider}@example.com"
        first, last = (provider.capitalize(), "User")
        # Upsert user for dev auth
        user = (
            db.query(models.User).filter(models.User.email == email).first()
        )
        if not user:
            pw = security.get_password_hash(secrets.token_urlsafe(16))
            user = models.User(email=email, hashed_password=pw, first_name=first, last_name=last)
            db.add(user); db.commit(); db.refresh(user)
            # ensure credits row exists
            ensure_user_credits(db, user.id)
        else:
            changed = False
            if not getattr(user, 'first_name', None):
                user.first_name = first; changed = True
            if not getattr(user, 'last_name', None):
                user.last_name = last; changed = True
            if changed:
                db.add(user); db.commit(); db.refresh(user)

        token = security.create_access_token(data={"sub": email})
    except Exception:
        token = "dev-token"

    return RedirectResponse(url=f"{target}#token={token}", status_code=302)
        
@app.get("/billing/summary")
def billing_summary(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    uc = ensure_user_credits(db, current_user.id)

    last_add = (
        db.query(models.CreditLedger)
        .filter(models.CreditLedger.user_id == current_user.id,
                models.CreditLedger.units > 0)
        .order_by(desc(models.CreditLedger.created_at))
        .first()
    )
    last_added_date = last_add.created_at.isoformat() if last_add else None

    # naive depletion estimate: last 30d avg/day
    since = datetime.utcnow() - timedelta(days=30)
    q = (
        db.query(func.sum(models.CreditLedger.units))
        .filter(models.CreditLedger.user_id == current_user.id,
                models.CreditLedger.created_at >= since)
    ).scalar() or 0
    spent30 = -min(0, q)  # units are negative for spend
    avg_per_day = spent30 / 30.0 if spent30 else 0.0
    months_left = (uc.remaining_credits / (avg_per_day * 30.0)) if avg_per_day else None

    return {
        "creditBalance": uc.remaining_credits,
        "lastAdded": last_added_date,           # ISO string; format on the client
        "timeUntilDepletionMonths": months_left # may be null
    }

@app.get("/billing/usage")
def billing_usage(
    start: str,  # ISO date
    end: str,    # ISO date (exclusive end ok)
    interval: str = "daily",  # 'hourly'|'daily'|'weekly'|'monthly'
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user),
):
    # pull negative rows (spend) in the window
    def _parse_iso8601(s: str) -> datetime:
        if not s:
            raise HTTPException(status_code=400, detail="Missing start/end time")
        s = s.strip()
        # Accept trailing 'Z' (UTC) and timezone offsets
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid datetime format: {s}")
        # Normalize to naive UTC to match DB naive timestamps
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    start_dt = _parse_iso8601(start)
    end_dt   = _parse_iso8601(end)

    rows = (
        db.query(models.CreditLedger)
        .filter(models.CreditLedger.user_id == current_user.id,
                models.CreditLedger.created_at >= start_dt,
                models.CreditLedger.created_at <  end_dt,
                models.CreditLedger.units < 0)   # only spend for usage
        .order_by(models.CreditLedger.created_at.asc())
        .all()
    )

    # bucket in Python for SQLite portability
    def bucket_key(dt):
        if interval == "hourly":
            return dt.strftime("%Y-%m-%d %H:00")
        if interval == "weekly":
            # ISO week label
            return f"{dt.isocalendar().year}-W{dt.isocalendar().week:02d}"
        if interval == "monthly":
            return dt.strftime("%Y-%m")
        return dt.strftime("%Y-%m-%d")  # daily default

    series = {}
    totals = {"bulk": 0, "single": 0, "api": 0, "other": 0}
    for r in rows:
        key = bucket_key(r.created_at)
        s = series.setdefault(key, {"date": key, "bulk": 0, "single": 0, "api": 0, "other": 0})
        k = r.kind if r.kind in s else "other"
        s[k] += -r.units
        totals[k] += -r.units

    # Ensure empty buckets are present (better chart continuity)
    cur = start_dt
    def step(dt):
        if interval == "hourly":  return dt + timedelta(hours=1)
        if interval == "weekly":  return dt + timedelta(days=7)
        if interval == "monthly": return (dt.replace(day=1) + timedelta(days=32)).replace(day=1)
        return dt + timedelta(days=1)

    out = []
    seen = set(series.keys())
    while cur < end_dt:
        key = bucket_key(cur)
        out.append(series.get(key, {"date": key, "bulk": 0, "single": 0, "api": 0, "other": 0}))
        cur = step(cur)

    return {"totals": totals, "series": out}

# --- ADMIN: Users list
@app.get("/admin/users")
def admin_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    rows = db.query(models.User).order_by(models.User.id.asc()).all()
    out = []
    for u in rows:
        out.append({
            "id": u.id,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "is_active": bool(getattr(u, "is_active", True)),
            "created_at": getattr(u, "created_at", None),
        })
    return out

# --- ADMIN: Users w/ credits
@app.get("/admin/users/credits")
def admin_users_credits(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    q = (
        db.query(models.User, models.UserCredits)
        .join(models.UserCredits, models.User.id == models.UserCredits.user_id, isouter=True)
        .order_by(models.User.id.asc())
        .all()
    )
    out = []
    for u, c in q:
        used = (c.used_credits if c else 0) or 0
        remaining = (c.remaining_credits if c else 0) or 0
        out.append({
            "user_id": u.id,
            "email": u.email,
            "name": f"{u.first_name or ''} {u.last_name or ''}".strip() or u.email.split("@")[0],
            "used_credits": used,
            "total_credits": used + remaining,
            "remaining_credits": remaining,
        })
    return out

# --- ADMIN: Deactivated users
@app.get("/admin/users/deactivated")
def admin_users_deactivated(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    rows = db.query(models.User).filter(models.User.is_active == False).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "is_active": False,
            "created_at": getattr(u, "created_at", None),
        } for u in rows
    ]

# --- ADMIN: Single user details
@app.get("/admin/users/{user_id}")
def admin_user_detail(
    user_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    uc = db.query(models.UserCredits).filter(models.UserCredits.user_id == u.id).first()
    used = (uc.used_credits if uc else 0) or 0
    remaining = (uc.remaining_credits if uc else 0) or 0
    return {
        "id": u.id,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "is_active": bool(getattr(u, "is_active", True)),
        "created_at": getattr(u, "created_at", None),
        "used_credits": used,
        "remaining_credits": remaining,
        "total_credits": used + remaining,
    }

# --- ADMIN: Toggle user active
class ToggleBody(schemas.BaseModel):
    active: bool

@app.post("/admin/users/{user_id}/toggle")
def admin_toggle_user(
    user_id: int,
    body: ToggleBody,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    u.is_active = bool(body.active)
    db.add(u); db.commit(); db.refresh(u)
    return {"ok": True, "id": u.id, "is_active": u.is_active}

# --- ADMIN: High-level stats

@app.get("/admin/stats")
def admin_stats(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    # High-level counts
    total_users = db.query(func.count(models.User.id)).scalar() or 0
    active_users = db.query(func.count(models.User.id)).filter(models.User.is_active == True).scalar() or 0
    deactivated_users = total_users - active_users

    # Credits totals
    q = db.query(models.UserCredits.used_credits, models.UserCredits.remaining_credits).all()
    total_used = sum((r[0] or 0) for r in q)
    total_remaining = sum((r[1] or 0) for r in q)

    # Users by month (this year)
    from datetime import datetime
    cur_year = datetime.utcnow().year

    month_col = extract('month', models.User.created_at).label('m')
    rows_month = (
        db.query(month_col, func.count(models.User.id))
        .filter(extract('year', models.User.created_at) == cur_year)
        .group_by(month_col)
        .order_by(month_col.asc())
        .all()
    )
    # rows_month: [(1.0, count), (2.0, count), ...] — extract returns numeric
    month_map = {int(m): int(c) for m, c in rows_month}

    months_labels = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    users_by_month = [{"month": lbl, "users": month_map.get(i, 0)} for i, lbl in enumerate(months_labels, start=1)]
    max_month = max(users_by_month, key=lambda x: x["users"]) if users_by_month else {"month": "—", "users": 0}

    # Users by year (last 5 years: optional filter; here we return all years present)
    year_col = extract('year', models.User.created_at).label('y')
    rows_year = (
        db.query(year_col, func.count(models.User.id))
        .group_by(year_col)
        .order_by(year_col.asc())
        .all()
    )
    users_by_year = [{"year": int(y), "users": int(c)} for y, c in rows_year]

    return {
        "total_users": int(total_users),
        "active_users": int(active_users),
        "deactivated_users": int(deactivated_users),
        "total_credits_used": int(total_used),
        "total_credits_remaining": int(total_remaining),
        "users_by_month": users_by_month,
        "max_users_month": max_month,
        "users_by_year": users_by_year,
        "year": cur_year,
    }
@app.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    rows = (
        db.query(models.User)
        .order_by(models.User.created_at.desc())
        .all()
    )
    return [
        {
            "id": u.id,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "is_admin": bool(u.is_admin),
            "is_active": bool(u.is_active),
            "created_at": u.created_at,
        }
        for u in rows
    ]
@app.get("/admin/users/{user_id}")
def admin_get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    credits = db.query(models.UserCredits).filter(models.UserCredits.user_id == user_id).first()
    return {
        "id": u.id,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "is_admin": bool(u.is_admin),
        "is_active": bool(u.is_active),
        "created_at": u.created_at,
        "credits": {
            "remaining": getattr(credits, "remaining_credits", 0),
            "used": getattr(credits, "used_credits", 0),
        },
    }

@app.put("/admin/users/{user_id}/status")
def admin_update_user_status(
    user_id: int,
    body: _UserStatusIn,
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    u.is_active = bool(body.is_active)
    db.add(u); db.commit(); db.refresh(u)
    return {"ok": True, "id": u.id, "is_active": u.is_active}

@app.get("/admin/users/credits")
def admin_users_with_credits(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    rows = (
        db.query(models.User, models.UserCredits)
        .outerjoin(models.UserCredits, models.User.id == models.UserCredits.user_id)
        .all()
    )
    out = []
    for u, c in rows:
        out.append({
            "id": u.id,
            "email": u.email,
            "is_active": bool(u.is_active),
            "is_admin": bool(u.is_admin),
            "remaining": getattr(c, "remaining_credits", 0),
            "used": getattr(c, "used_credits", 0),
        })
    return out

@app.get("/admin/users/deactivated")
def admin_deactivated_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(admin_required),
):
    rows = db.query(models.User).where(models.User.is_active == False).all()
    return [{"id": u.id, "email": u.email} for u in rows]
@app.post("/bulk/enqueue")
async def bulk_enqueue(
    file: UploadFile = File(...),
    smtp: bool = Form(False),
    workers: int = Form(12)
):
    jobs_dir = Path("./jobs")
    jobs_dir.mkdir(parents=True, exist_ok=True)

    jobid = str(uuid.uuid4())
    upload_path = jobs_dir / f"{jobid}_{file.filename}"
    with upload_path.open("wb") as f:
        f.write(await file.read())

    # Split into chunks and initialize progress
    chunks = split_csv(str(upload_path))
    # Quick count (header-aware)
    total_rows = max(0, sum(1 for _ in upload_path.open(encoding="utf-8")) - 1)
    init_job(jobid, total_rows=total_rows, chunk_count=len(chunks))

    # Enqueue each chunk to RQ
    for c in chunks:
        rq_q.enqueue(
            verify_chunk,
            jobid,
            c,
            smtp,
            workers,
            job_timeout="8h",
            result_ttl=86400,
            failure_ttl=86400
        )

    return {"jobid": jobid, "chunks": len(chunks), "status": "queued"}

# --- NEW: polling endpoint ---
@app.get("/bulk/jobs/{jobid}")
def bulk_job_status(jobid: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(security.get_current_user)):

    meta = rconn.hgetall(f"bulk:{jobid}")  # returns dict of bytes->bytes
    if not meta:
        # Optionally fall back to DB BulkJob presence
        bj = db.query(models.BulkJob).filter(models.BulkJob.id==jobid,
                    models.BulkJob.user_id==current_user.id).first()
        if not bj:
            raise HTTPException(404, "Bulk job not found")
        return {"jobid": jobid, "status": "unknown"}  # or check DB only

    meta = {k.decode(): v.decode() for k, v in meta.items()}
    total = int(meta.get("total", "0"))
    done = int(meta.get("done", "0"))
    chunks = int(meta.get("chunks", "0"))
    status = meta.get("status", "queued")
    outdir = meta.get("outdir")

    payload = {
        "jobid": jobid,
        "total": total,
        "done": done,
        "progress": (done / total) if total else 0.0,
        "chunks": chunks,
        "status": status,
    }

    # When done, expose download URLs (reuse your /download endpoint if you like)
    if status == "finished":
        payload["files"] = {
            "results_json": f"/download/{jobid}/results.json",
            "results_csv":  f"/download/{jobid}/results.csv",
        }

    return payload
# main.py (add this endpoint)
@app.get("/bulk/status/{jobid}")
def bulk_status(jobid: str):
    """
    Returns progress for a bulk job from Redis:
    {
      jobid, status, total, done, progress, chunks,
      files: { results_json, results_csv }  # when finished
    }
    """
    key = f"bulk:{jobid}"
    data = rconn.hgetall(key)
    if not data:
        raise HTTPException(status_code=404, detail="Job not found")

    def _s(b): return b.decode() if isinstance(b, (bytes, bytearray)) else b
    m = { _s(k): _s(v) for k, v in data.items() }

    total  = int(m.get("total", "0") or 0)
    done   = int(m.get("done", "0") or 0)
    chunks = int(m.get("chunks", "0") or 0)
    status = m.get("status", "queued")

    resp = {
        "jobid": jobid,
        "status": status,
        "total": total,
        "done": done,
        "progress": (done / total) if total else 0.0,
        "chunks": chunks,
    }

    # files are stored as a JSON string in Redis; parse if present
    if "files" in m and m["files"]:
        try:
            resp["files"] = json.loads(m["files"])
        except Exception:
            # if not JSON, still surface raw string
            resp["files"] = m["files"]

    return resp
# add near your other bulk routes

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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

# Local module imports
import models
import schemas
import security
from database import SessionLocal, engine, get_db
from app import validate_single_async, load_emails_from_csv, validate_many_async, write_outputs

# This creates the 'users' table in your database if it doesn't exist
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Email Verifier API", version="3.0")

# In-memory job store (for a real app, use a database or Redis)
JOBS = {}

# Fix the origins list - add comma and include both http and https variants
origins = [
    "http://localhost:5173",
    "https://localhost:5173",
    "http://127.0.0.1:5173",
    "https://127.0.0.1:5173",
    "http://127.0.0.1:8000",
    "https://127.0.0.1:8000"
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

# --- HELPERS ---

def ensure_user_credits(db: Session, user_id: int) -> "models.UserCredits":
    uc = db.query(models.UserCredits).filter(models.UserCredits.user_id == user_id).first()
    if not uc:
        uc = models.UserCredits(user_id=user_id, remaining_credits=0, used_credits=0)
        db.add(uc)
        db.commit(); db.refresh(uc)
    return uc

def charge_credits(db: Session, user_id: int, units: int) -> None:
    """Subtract credits atomically; raise 402 if not enough."""
    uc = ensure_user_credits(db, user_id)
    if uc.remaining_credits < units:
        raise HTTPException(status_code=402, detail="Insufficient credits")
    uc.remaining_credits -= units
    uc.used_credits += units
    db.add(uc); db.commit()

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
            existing_credits = db.query(models.UserCredits).filter(models.UserCredits.user_id == db_user.id).first()
            if not existing_credits:
                db.add(models.UserCredits(
                    user_id=db_user.id,
                    remaining_credits=FREE_SIGNUP_CREDITS,
                    used_credits=0
                ))
                db.commit()
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

@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(request: Request, db: Session = Depends(get_db)):
    """
    Accept both frontend form (email/password) and OAuth2 (username/password).
    Works with application/x-www-form-urlencoded and multipart/form-data.
    """
    try:
        form = await request.form()
        email = (form.get("email") or form.get("username") or "").strip()
        password = (form.get("password") or "").strip()

        if not email or not password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and password required")

        user = db.query(models.User).filter(models.User.email == email).first()
        if not user or not security.verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
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
    # 1 credit per single check
    charge_credits(db, current_user.id, 1)

    res = await validate_single_async(email, "noreply@example.com", None, smtp)
    res["deliverable"] = (res.get("final_status") == "valid")
    res["state"] = res.get("state")

    ver_id = record_result(db, current_user.id, res)
    return {"result": res, "verification_id": ver_id}

@app.post("/validate-file")
async def file_validation(
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

    try:
        with open(tmp_input_path, "wb") as f:
            content = await file.read()
            f.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")

    emails = load_emails_from_csv(tmp_input_path)
    if not emails:
        raise HTTPException(status_code=400, detail="No emails found in the uploaded CSV file.")

    # Charge N credits for N emails
    charge_credits(db, current_user.id, len(emails))

    # Create a BulkJob row so we can group and hide these from recent singles
    job_name = (name or os.path.splitext(file.filename or "")[0] or f"Upload {datetime.utcnow().date()}")[:120]
    bulk_job = models.BulkJob(
        id=jobid,
        user_id=current_user.id,
        name=job_name,
        total_emails=len(emails),
    )
    db.add(bulk_job)
    db.commit(); db.refresh(bulk_job)

    try:
        results = await validate_many_async(emails, "noreply@example.com", smtp, workers)
        for r in results:
            try:
                r["deliverable"] = bool(r.get("final_status") == "valid")
            except Exception:
                r["deliverable"] = False
            # Persist each row
            ver_id = record_result(db, current_user.id, r)
            # Link to bulk job
            db.add(models.BulkItem(job_id=jobid, verification_id=ver_id))
        db.commit()

        write_outputs(results, outdir)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Processing failed: {e}")

    JOBS[jobid] = outdir
    return {
        "jobid": jobid,
        "name": job_name,
        "count": len(results),
        "results": results,
        "files": {
            "results_json": f"/download/{jobid}/results.json",
            "results_csv": f"/download/{jobid}/results.csv",
        }
    }

@app.get("/download/{jobid}/{name}")
async def download_file(jobid: str, name: str):
    outdir = JOBS.get(jobid)
    if not outdir:
        raise HTTPException(status_code=404, detail="Job not found or has expired.")
    
    path = os.path.join(outdir, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found.")
        
    if name not in ["results.csv", "results.json"]:
        raise HTTPException(status_code=400, detail="Invalid filename.")

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
@app.get("/me")
def get_me(current_user: models.User = Depends(security.get_current_user)):
    return {
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
    }

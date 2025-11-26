#!/usr/bin/env python3
"""
tasks_redis.py

Redis-backed bulk job enqueuer for the email verifier.

- Enqueues per-chunk jobs into an RQ queue
- Writes per-chunk JSON files into jobs_data/<jobid>/
- Enqueues a final merge job that produces results.csv / results.json

This file intentionally mirrors the behavior of your existing
`tasks_simple.py` but uses Redis + RQ so a separate worker process
(can run on a 2-core Hostinger VPS) will do the heavy work.

IMPORTANT: This module is *imported* by `main.py` (FastAPI). The
functions that are executed by workers must be top-level callables
(so RQ can import them).

Keep the validation logic unchanged — this file calls your
`validate_many_async` and `write_outputs` functions from your
existing verifier module (import below). Adjust the import if your
module name differs (app_optimized vs app).
"""

import os
import json
import uuid
import time
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import asyncio
import glob
import re

# Redis / RQ
from redis import Redis
from rq import Queue

# Set up logging
logger = logging.getLogger(__name__)

# Database + ORM models (for persisting verified emails)
from database import SessionLocal
import models
from sqlalchemy.sql import func

# Import your validation functions (match what main.py uses)
# If your project imports validate_many_async / write_outputs from
# `app_optimized` in main.py, import from the same place here.
try:
    from app_optimized import validate_many_async, write_outputs
except Exception:
    # fallback to app if you named it differently
    from app import validate_many_async, write_outputs

# job storage (local JSON metadata + chunk files)
JOBS_DIR = Path("./jobs_data")
JOBS_DIR.mkdir(exist_ok=True)

# Redis connection (use REDIS_URL env on VPS, fallback to localhost)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_conn = Redis.from_url(REDIS_URL)

# RQ queue for bulk jobs
QUEUE_NAME = os.getenv("BULK_QUEUE_NAME", "bulk_queue")
# Default timeout: 4 hours, but can be overridden per job
DEFAULT_TIMEOUT = int(os.getenv("BULK_DEFAULT_TIMEOUT", 60 * 60 * 4))  # 4 hours in seconds
q = Queue(name=QUEUE_NAME, connection=redis_conn, default_timeout=DEFAULT_TIMEOUT)

# chunk size: smaller for 2-core VPS; override via BULK_CHUNK_SIZE
CHUNK_SIZE = int(os.getenv("BULK_CHUNK_SIZE", "3000"))

# Worker concurrency used by validate_many_async per chunk (keeps child-level parallelism moderate)
WORKERS_PER_CHUNK = max(1, int(os.getenv("WORKERS_PER_CHUNK", "8")))


# ----------------------- JobManager (JSON) -----------------------
class JobManager:
    """Simple JSON-based job metadata store (keeps parity with tasks_simple.py)."""

    @staticmethod
    def _path(jobid: str) -> Path:
        return JOBS_DIR / f"{jobid}.json"

    @staticmethod
    def create_job(jobid: str, total: int, chunks: int):
        data = {
            "jobid": jobid,
            "total": int(total),
            "done": 0,
            "chunks": int(chunks),
            "chunks_completed": 0,
            "status": "queued",
            "created_at": datetime.utcnow().isoformat(),
        }
        with open(JobManager._path(jobid), "w", encoding="utf-8") as f:
            json.dump(data, f)

    @staticmethod
    def update_progress(jobid: str, processed: int = 0, chunk_completed: bool = False):
        p = JobManager._path(jobid)
        if not p.exists():
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"jobid": jobid, "done": 0}

        data["done"] = int(data.get("done", 0)) + int(processed)
        if chunk_completed:
            data["chunks_completed"] = int(data.get("chunks_completed", 0)) + 1
        data["status"] = "processing" if data.get("chunks_completed", 0) < data.get("chunks", 0) else data.get("status", "processing")

        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f)

    @staticmethod
    def set_status(jobid: str, status: str, files: dict = None, error: str = None, **kwargs):
        """
        Update job status. Additional kwargs are stored as metadata.
        Common kwargs: duplicates, new_emails, total_processed, refunded_credits, refund_success
        """
        p = JobManager._path(jobid)
        if not p.exists():
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"jobid": jobid}

        data["status"] = status
        if files:
            data["files"] = files
        if error:
            data["error"] = error
            # Track timeout errors specifically
            if "timeout" in error.lower() or "TIMEOUT" in error:
                data["timeout_error"] = True
                data["last_error_time"] = datetime.utcnow().isoformat()
        
        # Store any additional metadata (duplicates, refunds, etc.)
        for key, value in kwargs.items():
            if value is not None:
                data[key] = value

        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f)

    @staticmethod
    def get_job(jobid: str) -> Dict[str, Any] | None:
        p = JobManager._path(jobid)
        if not p.exists():
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None


# ----------------------- Worker-callable functions -----------------------
# These must be top-level functions (RQ imports module and calls them)

def _write_chunk_results(outdir: str, chunk_idx: int, results: List[Dict[str, Any]]):
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)
    path = outdir_p / f"chunk_{chunk_idx}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False)


def process_chunk(jobid: str, chunk_idx: int, emails: List[str], smtp_flag: bool, outdir: str):
    """
    This function is executed inside a worker process by RQ.
    It runs the same validation logic you already have via validate_many_async.

    - jobid: job identifier
    - chunk_idx: index of this chunk (used for filenames)
    - emails: list of email addresses for this chunk
    - smtp_flag: whether to do SMTP probing
    - outdir: directory where chunk files will be written (jobs_data/<jobid>)
    """
    start_time = time.time()
    logger.info(f"[CHUNK] Starting chunk {chunk_idx} for job {jobid} with {len(emails)} emails")
    
    # Mark processing
    JobManager.set_status(jobid, "processing")

    smtp_from = os.getenv("SMTP_FROM", "noreply@example.com")

    try:
        # call your async batch validator from synchronous context
        logger.info(f"[CHUNK] Processing chunk {chunk_idx} for job {jobid}...")
        results = asyncio.run(
            validate_many_async(
                emails=emails,
                smtp_from=smtp_from,
                smtp_flag=bool(smtp_flag),
                workers=WORKERS_PER_CHUNK,
            )
        )
        elapsed = time.time() - start_time
        logger.info(f"[CHUNK] Completed chunk {chunk_idx} for job {jobid} in {elapsed:.2f}s ({len(results)} results)")
    except asyncio.TimeoutError as e:
        # Handle asyncio timeout errors
        elapsed = time.time() - start_time
        logger.error(f"[CHUNK] Timeout error in chunk {chunk_idx} for job {jobid} after {elapsed:.2f}s: {e}")
        reason = f"chunk_timeout: Chunk processing exceeded time limit after {elapsed:.1f}s"
        results = []
        for em in emails:
            results.append({
                "email": em,
                "final_status": "invalid",
                "state": "Undeliverable",
                "reason": reason,
                "score": 0,
            })
    except Exception as e:
        # On fatal errors, create invalid results for each email (keeps UI robust)
        elapsed = time.time() - start_time
        error_msg = str(e)
        logger.error(f"[CHUNK] Error in chunk {chunk_idx} for job {jobid} after {elapsed:.2f}s: {error_msg}")
        
        # Check if it's a timeout-related error from RQ
        if "timeout" in error_msg.lower() or "TIMEOUT" in error_msg:
            reason = f"rq_timeout: Job exceeded timeout limit ({elapsed:.1f}s)"
        else:
            reason = f"processing_error:{error_msg[:200]}"
        
        results = []
        for em in emails:
            results.append({
                "email": em,
                "final_status": "invalid",
                "state": "Undeliverable",
                "reason": reason,
                "score": 0,
            })

    # persist chunk
    try:
        _write_chunk_results(outdir, chunk_idx, results)
    except Exception as e:
        logger.error(f"[CHUNK] Failed to write chunk {chunk_idx} results for job {jobid}: {e}")
        raise

    # update job progress
    JobManager.update_progress(jobid, processed=len(results), chunk_completed=True)

    total_elapsed = time.time() - start_time
    logger.info(f"[CHUNK] Finished chunk {chunk_idx} for job {jobid} in {total_elapsed:.2f}s total")
    
    return {"ok": True, "jobid": jobid, "chunk_idx": chunk_idx, "processed": len(results)}


def merge_and_finalize(jobid: str, outdir: str):
    """
    This function runs after all chunk jobs are enqueued (and will be
    executed by RQ as a separate job). It merges all chunk_*.json files
    and writes the final CSV + JSON using your existing `write_outputs()`
    helper.
    """
    start_time = time.time()
    logger.info(f"[MERGE] Starting merge for job {jobid}")
    
    # Small delay to ensure filesystem has synced
    time.sleep(2)
    
    outdir_p = Path(outdir)
    pattern = str(outdir_p / "chunk_*.json")
    chunk_files = sorted([p for p in glob.glob(pattern) if re.search(r"chunk_\d+\.json$", p)])

    # Get job info to check expected chunks
    job_info = JobManager.get_job(jobid)
    expected_chunks = job_info.get("chunks", 0) if job_info else 0
    
    # Wait up to 30 seconds for all chunk files to appear
    max_wait = 30
    waited = 0
    while len(chunk_files) < expected_chunks and waited < max_wait:
        time.sleep(2)
        waited += 2
        chunk_files = sorted([p for p in glob.glob(pattern) if re.search(r"chunk_\d+\.json$", p)])
    
    if not chunk_files:
        error_msg = f"No chunk files produced for job {jobid} (expected {expected_chunks} chunks)"
        logger.error(f"[MERGE] {error_msg}")
        JobManager.set_status(jobid, "error", error=error_msg)
        return {"ok": False, "error": "No chunk files"}

    all_results: List[Dict[str, Any]] = []
    for cf in chunk_files:
        try:
            with open(cf, "r", encoding="utf-8") as fh:
                arr = json.load(fh)
                if isinstance(arr, list):
                    all_results.extend(arr)
        except Exception as e:
            # ignore single-file read problems (we'll report later if nothing)
            print(f"merge read error {cf}: {e}")

    if not all_results:
        JobManager.set_status(jobid, "error", error="No results to merge")
        return {"ok": False, "error": "No results to merge"}

    # write outputs using your existing function (writes results.csv + results.json)
    try:
        write_outputs(all_results, str(outdir_p))
    except Exception as e:
        logger.error(f"[MERGE] Failed to write outputs for job {jobid}: {e}")
        JobManager.set_status(jobid, "error", error=f"write_outputs failed: {e}")
        return {"ok": False, "error": f"write_outputs failed: {e}"}

    # Persist results so UI/history & credit de-dupe have full data
    persist_stats = {"total": 0, "duplicates": 0, "new": 0}
    try:
        persist_stats = _persist_bulk_results(jobid, all_results)
        logger.info(f"[MERGE] Persisted results for job {jobid}: {persist_stats}")
    except Exception as e:
        logger.error(f"[MERGE] Failed to persist DB results for job {jobid}: {e}", exc_info=True)
        # Don't fail the entire job if persistence fails, but log it

    # Refund credits for duplicates found during processing
    duplicate_count = persist_stats.get("duplicates", 0)
    refund_success = False
    if duplicate_count > 0:
        refund_success = _refund_duplicate_credits(jobid, duplicate_count)
        if refund_success:
            logger.info(f"[MERGE] Refunded {duplicate_count} credits for duplicates in job {jobid}")
        else:
            logger.warning(f"[MERGE] Failed to refund {duplicate_count} credits for job {jobid}")

    files_info = {
        "results_csv": f"/download/{jobid}/results.csv",
        "results_json": f"/download/{jobid}/results.json",
    }
    
    # Update job status with duplicate and refund information
    status_data = {
        "files": files_info,
        "duplicates": duplicate_count,
        "new_emails": persist_stats.get("new", 0),
        "total_processed": persist_stats.get("total", len(all_results)),
        "refunded_credits": duplicate_count if refund_success else 0,
        "refund_success": refund_success
    }
    JobManager.set_status(jobid, "finished", **status_data)

    # optional: cleanup chunk files
    try:
        for cf in chunk_files:
            os.remove(cf)
    except Exception as e:
        logger.warning(f"[MERGE] Failed to cleanup chunk files for job {jobid}: {e}")

    elapsed = time.time() - start_time
    logger.info(f"[MERGE] Completed merge for job {jobid} in {elapsed:.2f}s ({len(all_results)} total results)")
    
    return {"ok": True, "jobid": jobid, "count": len(all_results)}


# ----------------------- API-facing enqueuer -----------------------
def start_bulk_job(emails: List[str], smtp_flag: bool, jobid: str = None) -> str:
    """
    Called from main.py when a user uploads a file. Splits the full
    email list into chunks, creates job metadata, enqueues chunk jobs
    and enqueues the final merge job.

    Args:
        emails: List of email addresses to validate
        smtp_flag: Whether to perform SMTP checking
        jobid: Optional job ID. If not provided, a new UUID will be generated.

    Returns the jobid string.
    """
    if jobid is None:
        jobid = uuid.uuid4().hex
    outdir = str(JOBS_DIR / jobid)
    Path(outdir).mkdir(parents=True, exist_ok=True)

    # split into chunks
    chunks = [emails[i:i + CHUNK_SIZE] for i in range(0, len(emails), CHUNK_SIZE)]
    JobManager.create_job(jobid, total=len(emails), chunks=len(chunks))

    # Calculate timeout per chunk: base timeout + (emails_per_chunk * estimated_time_per_email)
    # Estimate: ~2-5 seconds per email (conservative), with minimum of 1 hour per chunk
    ESTIMATED_SECONDS_PER_EMAIL = float(os.getenv("ESTIMATED_SECONDS_PER_EMAIL", "3.0"))
    BASE_CHUNK_TIMEOUT = int(os.getenv("BASE_CHUNK_TIMEOUT", 3600))  # 1 hour base
    
    logger.info(f"[ENQUEUE] Starting bulk job {jobid} with {len(chunks)} chunks, {len(emails)} total emails")

    # enqueue each chunk job and collect job objects
    chunk_jobs = []
    for idx, chunk in enumerate(chunks):
        # Calculate timeout: base + (chunk_size * estimated_time_per_email)
        chunk_timeout = max(
            BASE_CHUNK_TIMEOUT,
            int(len(chunk) * ESTIMATED_SECONDS_PER_EMAIL) + BASE_CHUNK_TIMEOUT
        )
        # Cap at maximum timeout (default 4 hours, but allow override)
        max_timeout = int(os.getenv("MAX_CHUNK_TIMEOUT", str(DEFAULT_TIMEOUT)))
        chunk_timeout = min(chunk_timeout, max_timeout)
        
        logger.info(f"[ENQUEUE] Enqueuing chunk {idx} for job {jobid}: {len(chunk)} emails, timeout={chunk_timeout}s")
        
        job = q.enqueue(
            process_chunk, 
            jobid, 
            idx, 
            chunk, 
            bool(smtp_flag), 
            outdir,
            job_timeout=chunk_timeout  # Set explicit timeout per chunk
        )
        chunk_jobs.append(job)

    # enqueue the merge job to run AFTER all chunk jobs complete
    # Use depends_on to ensure merge only runs when all chunks are done
    # Merge job timeout: 30 minutes should be enough for merging files
    merge_timeout = int(os.getenv("MERGE_JOB_TIMEOUT", 1800))  # 30 minutes
    logger.info(f"[ENQUEUE] Enqueuing merge job for {jobid} with timeout={merge_timeout}s")
    
    q.enqueue(
        merge_and_finalize, 
        jobid, 
        outdir,
        depends_on=chunk_jobs,  # Wait for all chunk jobs to finish
        job_timeout=merge_timeout
    )

    return jobid


def get_job_status(jobid: str) -> Dict[str, Any] | None:
    return JobManager.get_job(jobid)


# ----------------------- DB persistence helpers -----------------------
def _normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def _refund_duplicate_credits(jobid: str, duplicate_count: int) -> bool:
    """
    Refund credits for duplicate emails found during bulk processing.
    Returns True if refund was successful, False otherwise.
    """
    if duplicate_count <= 0:
        return True
    
    session = SessionLocal()
    try:
        job = session.query(models.BulkJob).filter(models.BulkJob.id == jobid).first()
        if not job:
            logger.warning(f"[REFUND] BulkJob {jobid} not found for refund")
            return False
        
        user_id = job.user_id
        
        # Get user credits
        uc = session.query(models.UserCredits).filter(models.UserCredits.user_id == user_id).first()
        if not uc:
            logger.warning(f"[REFUND] UserCredits not found for user {user_id}")
            return False
        
        # Refund credits
        uc.remaining_credits += duplicate_count
        uc.used_credits = max(0, uc.used_credits - duplicate_count)
        session.add(uc)
        
        # Add ledger entry for refund (positive units)
        ledger_entry = models.CreditLedger(
            user_id=user_id,
            kind="bulk",
            units=duplicate_count,  # Positive for refund
            source="bulk_duplicate_refund",
            ref=jobid
        )
        session.add(ledger_entry)
        
        session.commit()
        logger.info(f"[REFUND] Refunded {duplicate_count} credits to user {user_id} for job {jobid}")
        return True
        
    except Exception as e:
        session.rollback()
        logger.error(f"[REFUND] Failed to refund credits for job {jobid}: {e}", exc_info=True)
        return False
    finally:
        session.close()


def _persist_bulk_results(jobid: str, results: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Persist bulk verification results to database.
    Returns dict with counts: {'total': int, 'duplicates': int, 'new': int}
    """
    if not results:
        return {"total": 0, "duplicates": 0, "new": 0}

    session = SessionLocal()
    duplicates_count = 0
    new_count = 0
    
    try:
        job = session.query(models.BulkJob).filter(models.BulkJob.id == jobid).first()
        if not job:
            logger.warning(f"[PERSIST] BulkJob {jobid} not found in database")
            return {"total": 0, "duplicates": 0, "new": 0}
        
        user_id = job.user_id
        logger.info(f"[PERSIST] Persisting {len(results)} results for job {jobid}, user {user_id}")

        for res in results:
            email_raw = (res.get("email") or "").strip()
            email_norm = _normalize_email(email_raw)
            if not email_norm:
                continue

            # Check if this email was already checked by this user (duplicate detection)
            ec_existing = (
                session.query(models.EmailsChecked)
                .filter(
                    models.EmailsChecked.user_id == user_id,
                    models.EmailsChecked.email == email_norm,
                )
                .first()
            )
            
            is_duplicate = ec_existing is not None

            # Always create EmailVerification record (for history/audit)
            ev = models.EmailVerification(
                user_id=user_id,
                email=email_raw,
                status=res.get("final_status"),
                state=res.get("state"),
                reason=res.get("reason"),
                score=res.get("score"),
                domain=res.get("domain"),
                local_part=res.get("local_part"),
                free=bool(res.get("free")),
                role=bool(res.get("role")),
                disposable=bool(res.get("disposable")),
                accept_all=bool(res.get("accept_all")),
                smtp_provider=res.get("smtp_provider"),
                mx_record=res.get("mx_record"),
                catch_all=res.get("catch_all"),
                smtp_ok=res.get("smtp_ok"),
                result_json=json.dumps(res, ensure_ascii=False),
            )
            session.add(ev)
            session.flush()

            # Link to bulk job
            session.add(models.BulkItem(job_id=jobid, verification_id=ev.id))

            # Update or create EmailsChecked record
            if not ec_existing:
                ec = models.EmailsChecked(
                    user_id=user_id,
                    email=email_norm,
                    total_checks=1,
                    last_status=res.get("final_status"),
                    last_score=res.get("score"),
                )
                new_count += 1
            else:
                ec = ec_existing
                ec.total_checks = (ec.total_checks or 0) + 1
                ec.last_status = res.get("final_status")
                ec.last_score = res.get("score")
                ec.last_checked_at = func.now()
                duplicates_count += 1
            session.add(ec)

        session.commit()
        logger.info(f"[PERSIST] Successfully persisted {len(results)} results: {new_count} new, {duplicates_count} duplicates")
        
        return {
            "total": len(results),
            "duplicates": duplicates_count,
            "new": new_count
        }
    except Exception as e:
        session.rollback()
        logger.error(f"[PERSIST] Failed to persist results for job {jobid}: {e}", exc_info=True)
        raise
    finally:
        session.close()


# If executed directly, provide a simple test harness (optional)
if __name__ == "__main__":
    print("tasks_redis loaded. REDIS_URL=", REDIS_URL)
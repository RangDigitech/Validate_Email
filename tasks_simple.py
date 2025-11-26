#!/usr/bin/env python3
"""
tasks_simple.py - Pure Python background tasks (NO REDIS)

Uses multiprocessing for parallel chunk processing.
All job tracking done via JSON files.
"""

import os
import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
import logging
import re
from app_optimized import validate_many_async, write_outputs, DNSTimeoutError
import dns.exception
import time 
import glob

# Setup
JOBS_DIR = Path("./jobs_data")
JOBS_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("tasks_simple")
logger.setLevel(logging.INFO)

# Process pool executor (uses all CPU cores)
CPU_CORES = os.cpu_count() or 4
executor = ProcessPoolExecutor(max_workers=CPU_CORES)

class JobManager:
    """Simple job manager without Redis - uses JSON files"""
    
    @staticmethod
    def create_job(jobid: str, total_emails: int, chunk_count: int):
        """Initialize job metadata"""
        job_file = JOBS_DIR / f"{jobid}.json"
        data = {
            "jobid": jobid,
            "total": total_emails,
            "done": 0,
            "chunks": chunk_count,
            "chunks_completed": 0,
            "status": "processing",
            "created_at": datetime.utcnow().isoformat(),
        }
        with open(job_file, 'w') as f:
            json.dump(data, f)
    
    @staticmethod
    def update_progress(jobid: str, processed: int = 0, chunk_completed: bool = False):
        job_file = JOBS_DIR / f"{jobid}.json"
        if job_file.exists():
            with open(job_file, 'r') as f:
                data = json.load(f)

            data["done"] = data.get("done", 0) + int(processed)
            if chunk_completed:
                data["chunks_completed"] = data.get("chunks_completed", 0) + 1

            with open(job_file, 'w') as f:
                json.dump(data, f)

    
    @staticmethod
    def set_status(jobid: str, status: str, files: dict = None, error: str = None):
        """Update job status"""
        job_file = JOBS_DIR / f"{jobid}.json"
        if job_file.exists():
            with open(job_file, 'r') as f:
                data = json.load(f)
            
            data["status"] = status
            if files:
                data["files"] = files
            if error:
                data["error"] = error
            
            with open(job_file, 'w') as f:
                json.dump(data, f)
    
    @staticmethod
    def get_job(jobid: str) -> dict:
        """Get job status"""
        job_file = JOBS_DIR / f"{jobid}.json"
        if job_file.exists():
            with open(job_file, 'r') as f:
                return json.load(f)
        return None
    
    @staticmethod
    def set_job_metadata(jobid: str, metadata: dict):
        """Store additional metadata"""
        job_file = JOBS_DIR / f"{jobid}.json"
        if job_file.exists():
            with open(job_file, 'r') as f:
                data = json.load(f)
            data.update(metadata)
            with open(job_file, 'w') as f:
                json.dump(data, f)


def create_invalid_result(email: str, reason: str) -> dict:
    """Create an invalid result for emails that failed validation"""
    return {
        "email": email,
        "local_part": email.split("@")[0] if "@" in email else "",
        "domain": email.split("@")[1] if "@" in email else "",
        "syntax_ok": True if "@" in email else False,
        "disposable": False,
        "role_based": False,
        "free_provider": False,
        "mx_hosts": [],
        "mx_ok": False,
        "implicit_mx_record": False,
        "spf": False,
        "dkim": False,
        "dmarc": False,
        "smtp_tested": False,
        "smtp_ok": None,
        "catch_all": None,
        "smtp_reason": reason,
        "score": 0,
        "final_status": "invalid",
        "notes": [reason],
        "probe_details": None,
        "state": "Undeliverable",
        "reason": reason,
        "smtp_provider": None,
        "mx_record": None,
        "free": False,
        "role": False,
        "accept_all": False,
        "tag": False,
        "numerical_characters": 0,
        "alphabetical_characters": 0,
        "unicode_symbols": 0,
        "mailbox_full": False,
        "no_reply": False,
        "secure_email_gateway": False,
        "disposable_signals": {"mx_keyword": False, "asn_match": False, "http_marker": False}
    }


def process_chunk_worker(chunk_data: dict):
    """
    Worker function that runs in separate process.
    Processes a chunk by iterating smaller subchunks so progress can be reported.
    """
    import math
    jobid = chunk_data["jobid"]
    chunk_idx = chunk_data["chunk_idx"]
    emails = chunk_data["emails"]
    smtp_flag = chunk_data["smtp_flag"]
    outdir = chunk_data["outdir"]

    pid = os.getpid()
    logger.info(f"[WORKER-{pid}] Starting chunk {chunk_idx} with {len(emails)} emails")

    try:
        # Respect global envs (don't force-overwrite SMTP_MODE)
        smtp_mode = os.getenv("SMTP_MODE", os.getenv("BULK_SMTP_MODE", "balanced"))
        os.environ["SMTP_MODE"] = smtp_mode

        smtp_from_env = os.getenv("SMTP_FROM") or os.getenv("BULK_SMTP_FROM") or "noreply@example.com"

        # Force DNS servers in child process
        os.environ["DNS_1"] = os.getenv("DNS_1", "1.1.1.1")
        os.environ["DNS_2"] = os.getenv("DNS_2", "8.8.8.8")

        # subchunking: process small groups and update progress after each group
        SUBCHUNK_SIZE = int(os.getenv("WORKER_SUBCHUNK_SIZE", "100"))
        total = len(emails)
        subcount = math.ceil(total / SUBCHUNK_SIZE)

        all_results = []
        for sidx in range(subcount):
            start = sidx * SUBCHUNK_SIZE
            end = min(total, (sidx + 1) * SUBCHUNK_SIZE)
            sub_emails = emails[start:end]
            if not sub_emails:
                continue

            # Single attempt - no retries
            results = []
            try:
                results = asyncio.run(
                    validate_many_async(
                        emails=sub_emails,
                        smtp_from=smtp_from_env,
                        smtp_flag=smtp_flag,
                        workers=max(1, min(64, int(os.getenv("WORKERS_PER_SUBCHUNK", "32"))))
                    )
                )
            except (DNSTimeoutError,) as e:
                # Hard DNS timeout raised by app_optimized.lookup_mx_async -> mark subchunk invalid (per requirements)
                logger.warning(f"[WORKER-{pid}] DNSTimeoutError on chunk {chunk_idx} sub {sidx}: {e}")
                reason = f"DNS timeout: {str(e)[:200]}"
                results = [create_invalid_result(email, reason) for email in sub_emails]
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers, asyncio.TimeoutError) as e:
                # Other resolver-level/asyncio timeout errors: treat as DNS-related but keep reason clear
                logger.warning(f"[WORKER-{pid}] DNS/timeout error on chunk {chunk_idx} sub {sidx}: {e}")
                reason = f"DNS error or lookup timeout: {str(e)[:200]}"
                results = [create_invalid_result(email, reason) for email in sub_emails]
            except Exception as e:
                # Other errors: mark all emails in this subchunk as invalid with generic error
                logger.error(f"[WORKER-{pid}] Processing error on chunk {chunk_idx} sub {sidx}: {e}")
                reason = f"Processing error: {str(e)[:200]}"
                results = [create_invalid_result(email, reason) for email in sub_emails]

            # Ensure we have results for all emails (should never be empty now)
            if len(results) != len(sub_emails):
                logger.warning(f"[WORKER-{pid}] Result count mismatch in chunk {chunk_idx} sub {sidx}: expected {len(sub_emails)}, got {len(results)}")
                # Create invalid results for any missing emails
                processed_emails = {r.get("email") for r in results if r.get("email")}
                for email in sub_emails:
                    if email not in processed_emails:
                        results.append(create_invalid_result(email, "Missing result"))

            # Write subchunk results to disk
            chunk_file = os.path.join(outdir, f"chunk_{chunk_idx}_part_{sidx}.json")
            with open(chunk_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False)

            all_results.extend(results)

            # Update job progress (incremental)
            JobManager.update_progress(jobid, len(results))
            logger.info(f"[WORKER-{pid}] Chunk {chunk_idx} part {sidx} processed {len(results)} emails")

        # After all subchunks, write the merged chunk file for this chunk
        merged_chunk_file = os.path.join(outdir, f"chunk_{chunk_idx}.json")
        with open(merged_chunk_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, ensure_ascii=False)

        logger.info(f"[WORKER-{pid}] Chunk {chunk_idx} complete: {len(all_results)} results")
        return {"ok": True, "processed": len(all_results), "chunk_idx": chunk_idx}

    except Exception as e:
        logger.error(f"[WORKER-{pid}] Fatal error in chunk {chunk_idx}: {e}")
        # Even on fatal error, try to create invalid results for all emails
        try:
            reason = f"Fatal chunk error: {str(e)[:100]}"
            invalid_results = [create_invalid_result(email, reason) for email in emails]
            merged_chunk_file = os.path.join(outdir, f"chunk_{chunk_idx}.json")
            with open(merged_chunk_file, 'w', encoding='utf-8') as f:
                json.dump(invalid_results, f, ensure_ascii=False)
            logger.info(f"[WORKER-{pid}] Saved {len(invalid_results)} invalid results for failed chunk {chunk_idx}")
            return {"ok": True, "processed": len(invalid_results), "chunk_idx": chunk_idx}
        except Exception as save_error:
            logger.error(f"[WORKER-{pid}] Could not save invalid results: {save_error}")
            # Create failure marker as last resort
            failure_file = os.path.join(outdir, f"chunk_{chunk_idx}.failed")
            try:
                with open(failure_file, "w", encoding="utf-8") as fh:
                    fh.write(str(e))
            except Exception:
                pass
            raise


def merge_and_finalize(jobid: str, outdir: str):
    """Merge all chunk results into final CSV and JSON files"""
    import glob
    
    logger.info(f"[MERGE] Starting merge for job {jobid}")
    
    all_results = []
    chunk_files = sorted([p for p in glob.glob(os.path.join(outdir, "chunk_*.json")) if re.search(r"chunk_\d+\.json$", p)])
    
    if not chunk_files:
        logger.warning(f"[MERGE] No chunk files found for job {jobid}")
        JobManager.set_status(jobid, "error", error="No results produced")
        return
    
    for cf in chunk_files:
        try:
            with open(cf, 'r', encoding='utf-8') as f:
                chunk_data = json.load(f)
                all_results.extend(chunk_data)
            logger.info(f"[MERGE] Loaded {len(chunk_data)} results from {os.path.basename(cf)}")
        except Exception as e:
            logger.error(f"[MERGE] Error reading {cf}: {e}")
    
    if not all_results:
        logger.warning(f"[MERGE] No results to merge for job {jobid}")
        JobManager.set_status(jobid, "error", error="No results produced")
        return
    
    # Write final outputs
    try:
        write_outputs(all_results, outdir)
        logger.info(f"[MERGE] Wrote final results: {len(all_results)} emails")
    except Exception as e:
        logger.error(f"[MERGE] Error writing outputs: {e}")
        JobManager.set_status(jobid, "error", error=f"Failed to write results: {e}")
        return
    
    # Update job status
    files_info = {
        "results_json": f"/download/{jobid}/results.json",
        "results_csv": f"/download/{jobid}/results.csv"
    }
    JobManager.set_status(jobid, "finished", files=files_info)
    
    logger.info(f"[MERGE] Job {jobid} complete: {len(all_results)} results")
    
    # Clean up chunk files
    for cf in chunk_files:
        try:
            os.remove(cf)
        except Exception as e:
            logger.warning(f"[MERGE] Failed to delete {cf}: {e}")


async def process_bulk_async(
    jobid: str,
    emails: List[str],
    smtp_flag: bool,
    outdir: str,
    chunk_size: int = 10000
):
    """
    Process bulk emails asynchronously without Redis.
    Uses multiprocessing for parallel chunk processing.
    """
    
    logger.info(f"[BULK] Starting job {jobid} with {len(emails)} emails")
    
    # Split into chunks
    chunks = [emails[i:i+chunk_size] for i in range(0, len(emails), chunk_size)]
    
    logger.info(f"[BULK] Split into {len(chunks)} chunks of ~{chunk_size} emails")
    
    # Initialize job
    JobManager.create_job(jobid, len(emails), len(chunks))
    
    # Submit all chunks to process pool
    futures = []
    for idx, chunk in enumerate(chunks):
        chunk_data = {
            "jobid": jobid,
            "chunk_idx": idx,
            "emails": chunk,
            "smtp_flag": smtp_flag,
            "outdir": outdir,
        }
        future = executor.submit(process_chunk_worker, chunk_data)
        futures.append((idx, future))
    
    logger.info(f"[BULK] Submitted {len(chunks)} chunks to process pool")
    
    # Background thread to wait for completion and merge
    def wait_and_finalize():
        try:
            # Wait for all chunks
            failed_chunks = []
            for idx, future in futures:
                try:
                    result = future.result(timeout=3600)
                    logger.info(f"[BULK] Chunk {idx} finished: {result}")
                except Exception as e:
                    logger.error(f"[BULK] Chunk {idx} failed: {e}")
                    failed_chunks.append((idx, str(e)))
                    # Continue waiting for others - don't break

            # Check if we have any chunk files at all
            import glob
            chunk_files = sorted([p for p in glob.glob(os.path.join(outdir, "chunk_*.json")) if re.search(r"chunk_\d+\.json$", p)])
            
            if not chunk_files:
                # No chunks succeeded - this is truly fatal
                err_msg = f"All {len(chunks)} chunks failed to produce results"
                JobManager.set_status(jobid, "error", error=err_msg)
                logger.error(f"[BULK] Job {jobid} has no successful chunk outputs; failing job")
                return

            # We have some results - merge them
            merge_and_finalize(jobid, outdir)

            # If there were failed chunks, add that metadata to the job results
            if failed_chunks:
                JobManager.set_job_metadata(jobid, {
                    "failed_chunks": failed_chunks,
                    "successful_chunks": len(chunk_files),
                    "total_chunks": len(chunks)
                })
                logger.warning(f"[BULK] Job {jobid} completed with {len(failed_chunks)} failed chunks out of {len(chunks)}")
            
        except Exception as e:
            logger.error(f"[BULK] Error in wait_and_finalize: {e}")
            JobManager.set_status(jobid, "error", error=str(e))
    
    # Start background finalization
    import threading
    thread = threading.Thread(target=wait_and_finalize, daemon=True)
    thread.start()
    
    return {
        "jobid": jobid, 
        "chunks": len(chunks), 
        "status": "processing"
    }
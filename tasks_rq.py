import os, csv, json
from pathlib import Path
from typing import List, Dict
from rq import get_current_job
from redis import Redis

from queue_utils import incr_done, set_status, push_file
# Import your existing async pipeline & writer from app.py
from app import validate_many_async, write_outputs  # uses your current logic

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
r = Redis.from_url(REDIS_URL)

async def _verify_emails(emails: List[str], smtp: bool, workers: int) -> List[Dict]:
    # Reuse your async bulk verifier
    return await validate_many_async(emails, smtp_from="noreply@example.com", smtp=smtp, workers=workers)

def verify_chunk(jobid: str, chunk_path: str, smtp: bool, workers: int):
    """
    RQ task (sync entry) that runs your async verifier via anyio,
    writes output files, and updates progress in Redis.
    """
    import anyio
    set_status(jobid, "running")

    # read emails from the chunk
    with open(chunk_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    emails = [r["email"].strip() for r in rows if r.get("email")]

    # run your async pipeline
    results = anyio.run(_verify_emails, emails, smtp, workers)

    # write outputs to a per-job folder
    outdir = Path(f"./jobs/{jobid}")
    outdir.mkdir(parents=True, exist_ok=True)

    # Use your helper if it composes combined results; if not, write per-chunk files:
    try:
        write_outputs(results, outdir)   # your helper (already in app.py)
    except Exception:
        # minimal fallback writer
        csv_path = outdir / f"{Path(chunk_path).stem}_results.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            keys = ["email","deliverable","score","reason"]
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for row in results:
                w.writerow({k: row.get(k) for k in keys})
        push_file(jobid, str(csv_path))

    # progress
    incr_done(jobid, len(emails))

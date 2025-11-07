import os, csv, json
from pathlib import Path
from typing import List, Dict
from rq import get_current_job
from redis import Redis
import inspect
from queue_utils import push_file

# from queue_utils import incr_done, set_status, push_file
# Import your existing async pipeline & writer from app.py
from app import validate_many_async, write_outputs  # uses your current logic

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
r = Redis.from_url(REDIS_URL)

# async def _verify_emails(emails: List[str], smtp: bool, workers: int) -> List[Dict]:
#     # Reuse your async bulk verifier
#     return await validate_many_async(emails, smtp_from="noreply@example.com", smtp=smtp, workers=workers)
async def _verify_emails(emails: List[str], smtp: bool, workers: int) -> List[Dict]:
    """
    Call validate_many_async with the correct SMTP flag name by inspecting its signature.
    Works whether the param is named 'smtp', 'do_smtp', 'smtp_check', etc.
    """
    # Build base kwargs
    kwargs = {"smtp_from": "noreply@example.com", "workers": workers}

    # Detect the correct SMTP-flag parameter name
    param_names = set(inspect.signature(validate_many_async).parameters.keys())
    for candidate in ("smtp", "do_smtp", "smtp_check", "perform_smtp", "enable_smtp"):
        if candidate in param_names:
            kwargs[candidate] = smtp
            break  # use the first matching name

    return await validate_many_async(emails, **kwargs)

def verify_chunk(jobid: str, idx: int, chunk: list, smtp: bool, user_id: int, outdir: str):
    """
    Enqueued by /validate-file with params:
      jobid, idx, chunk(list-of-emails), smtp(bool), user_id(int), outdir(str)
    Updates Redis hash bulk:{jobid} so /bulk/status/{jobid} can see progress.
    On the last chunk, merges parts into results.csv / results.json and marks finished.
    """
    import anyio
    from datetime import datetime

    # Mark running (match your status route which reads bulk:{jobid})
    r.hset(f"bulk:{jobid}", "status", "running")

    # Normalize emails
    emails = [e.strip() for e in (chunk or []) if isinstance(e, str) and e.strip()]
    if not emails:
        # still count as done for this chunk
        r.hincrby(f"bulk:{jobid}", "done", 0)
        return

    # Run your async verifier (reusing your existing pipeline)
    async def _run():
        return await _verify_emails(
            emails,
            smtp=smtp,
            workers=int(os.getenv("BULK_WORKERS", "12")),
        )
    results = anyio.run(_run)

    # Write a per-chunk CSV (so we can merge later)
    part_dir = Path(outdir)
    part_dir.mkdir(parents=True, exist_ok=True)
    part_csv = part_dir / f"part_{idx:04d}.csv"

    # Prefer your existing writer if it can append into outdir; otherwise write a simple CSV
    try:
        # if your write_outputs can handle per-chunk writes to outdir, keep it:
        write_outputs(results, part_dir)
        # if write_outputs produces a single file per run, also drop a part_* for merging fallback:
        if not part_csv.exists():
            with part_csv.open("w", newline="", encoding="utf-8") as f:
                keys = ["email","deliverable","score","reason"]
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                for row in results:
                    w.writerow({k: row.get(k) for k in keys})
    except Exception:
        # Minimal fallback writer
        with part_csv.open("w", newline="", encoding="utf-8") as f:
            keys = ["email","deliverable","score","reason"]
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for row in results:
                w.writerow({k: row.get(k) for k in keys})

    # Increment progress on the SAME KEY your status route reads
    done = r.hincrby(f"bulk:{jobid}", "done", len(emails))
    total = int((r.hget(f"bulk:{jobid}", "total") or b"0").decode())

    # If this was the final chunk, merge parts and flip status
    if total and done >= total:
        # Merge all part_*.csv into results.csv
        parts = sorted(Path(outdir).glob("part_*.csv"))
        results_csv = Path(outdir) / "results.csv"
        with results_csv.open("w", newline="", encoding="utf-8") as out:
            writer = None
            for p in parts:
                with p.open("r", newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    if writer is None:
                        writer = csv.DictWriter(out, fieldnames=reader.fieldnames)
                        writer.writeheader()
                    for row in reader:
                        writer.writerow(row)

        # (Optional) build a JSON too if your UI uses it
        results_json = Path(outdir) / "results.json"
        try:
            # Very small JSON: just list emails + summary fields. Adjust as you like.
            import json
            rows = []
            with results_csv.open("r", newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    rows.append(row)
            results_json.write_text(json.dumps(rows, ensure_ascii=False))
        except Exception:
            pass

        # Let the UI discover downloadable files (your status route looks at this list)
        r.rpush(f"job:{jobid}:files", "results.csv", "results.json")
        r.hset(f"bulk:{jobid}", "status", "finished")

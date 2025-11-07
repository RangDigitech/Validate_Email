import os, csv, json
from pathlib import Path
from typing import List, Dict
import inspect
from redis import Redis
from rq import get_current_job

# Import your existing async pipeline & file writer
from app import validate_many_async, write_outputs  # keeps your current logic

# DB imports for persisting results so /bulk/jobs/{jobid} works
from database import SessionLocal
import models

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
r = Redis.from_url(REDIS_URL)


async def _verify_emails(emails: List[str], smtp: bool, workers: int) -> List[Dict]:
    """
    Calls validate_many_async with the correct SMTP flag name by inspecting its signature.
    Works whether the param is named 'smtp_flag', 'smtp', 'do_smtp', etc.
    """
    kwargs = {"smtp_from": "noreply@example.com", "workers": workers}
    param_names = set(inspect.signature(validate_many_async).parameters.keys())
    for candidate in ("smtp_flag", "smtp", "do_smtp", "smtp_check", "perform_smtp", "enable_smtp"):
        if candidate in param_names:
            kwargs[candidate] = smtp
            break
    return await validate_many_async(emails, **kwargs)


def _record_bulk_results(jobid: str, user_id: int, results: List[Dict]) -> None:
    """
    Persist each result into EmailVerification and link with BulkItem.
    This feeds the existing /bulk/jobs/{jobid} endpoint (DB-based UI).
    """
    from json import dumps as _dumps

    db = SessionLocal()
    try:
        for res in results or []:
            email = (res.get("email") or "").strip().lower()
            ev = models.EmailVerification(
                user_id=user_id,
                email=email,
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
                smtp_ok=bool(res.get("smtp_ok")),
                result_json=_dumps(res, ensure_ascii=False),
            )
            db.add(ev)
            db.flush()  # so ev.id is available

            db.add(models.BulkItem(job_id=jobid, verification_id=ev.id, email=email))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[BULK][DB-WRITE-FAIL] jobid={jobid} err={e}")
    finally:
        db.close()


def verify_chunk(jobid: str, idx: int, chunk: list, smtp: bool, user_id: int, outdir: str):
    """
    Enqueued by /validate-file with params:
      jobid, idx, chunk(list-of-emails), smtp(bool), user_id(int), outdir(str)
    Updates Redis hash bulk:{jobid} so /bulk/status/{jobid} can see progress.
    On the final chunk, merges parts into results.csv/json, sets files list, and marks finished.
    """
    import anyio

    # Mark job as running
    r.hset(f"bulk:{jobid}", "status", "running")

    # Normalize emails
    emails = [e.strip() for e in (chunk or []) if isinstance(e, str) and e.strip()]
    if not emails:
        r.hincrby(f"bulk:{jobid}", "done", 0)
        return

    # Run async verification
    async def _run():
        return await _verify_emails(
            emails,
            smtp=smtp,
            workers=int(os.getenv("BULK_WORKERS", "12")),
        )

    try:
        results = anyio.run(_run)
    except Exception as e:
        # advance progress so UI doesn't stall; mark error
        r.hincrby(f"bulk:{jobid}", "done", len(emails))
        r.hset(f"bulk:{jobid}", "status", "error")
        print(f"[BULK][CHUNK-FAIL] jobid={jobid} idx={idx} err={e}")
        return

    # === NEW: write results to DB so /bulk/jobs/{jobid} returns rows ===
    try:
        _record_bulk_results(jobid, user_id, results)
    except Exception as e:
        print(f"[BULK][DB-LINK-FAIL] jobid={jobid} idx={idx} err={e}")

    # Write per-chunk CSV (so we can merge later)
    part_dir = Path(outdir)
    part_dir.mkdir(parents=True, exist_ok=True)
    part_csv = part_dir / f"part_{idx:04d}.csv"

    try:
        # Use your existing writer if it handles outdir correctly
        write_outputs(results, part_dir)
        # Ensure we still have a part_* file to merge
        if not part_csv.exists():
            with part_csv.open("w", newline="", encoding="utf-8") as f:
                keys = ["email", "deliverable", "score", "reason"]
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                for row in results:
                    w.writerow({k: row.get(k) for k in keys})
    except Exception:
        # Minimal fallback writer
        with part_csv.open("w", newline="", encoding="utf-8") as f:
            keys = ["email", "deliverable", "score", "reason"]
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for row in results:
                w.writerow({k: row.get(k) for k in keys})

    # Increment progress
    done = r.hincrby(f"bulk:{jobid}", "done", len(emails))
    total_bytes = r.hget(f"bulk:{jobid}", "total") or b"0"
    try:
        total = int(total_bytes.decode() if isinstance(total_bytes, (bytes, bytearray)) else total_bytes)
    except Exception:
        total = 0

    # If last chunk, merge and finalize
    if total and done >= total:
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

        # Optional JSON for easy UI preview/download
        results_json = Path(outdir) / "results.json"
        try:
            rows = []
            with results_csv.open("r", newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    rows.append(row)
            results_json.write_text(json.dumps(rows, ensure_ascii=False))
        except Exception:
            pass

        # Expose downloadable files in Redis for /bulk/status/{jobid}
        try:
            r.hset(
                f"bulk:{jobid}",
                "files",
                json.dumps(
                    {
                        "results_json": f"/download/{jobid}/results.json",
                        "results_csv": f"/download/{jobid}/results.csv",
                    }
                ),
            )
        except Exception:
            # best effort — also push list keys
            r.rpush(f"job:{jobid}:files", "results.csv", "results.json")

        r.hset(f"bulk:{jobid}", "status", "finished")

import os, csv, json, inspect
from pathlib import Path
from typing import List, Dict

from redis import Redis
from rq import get_current_job

# DB / models
from database import SessionLocal
import models

# your async verifier + writer
from app import validate_many_async, write_outputs

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
r = Redis.from_url(REDIS_URL)

# ------------ helpers ------------

async def _verify_emails(emails: List[str], smtp: bool, workers: int) -> List[Dict]:
    """
    Call validate_many_async with whatever SMTP flag name it uses.
    """
    kwargs = {"smtp_from": "noreply@example.com", "workers": workers}
    param_names = set(inspect.signature(validate_many_async).parameters.keys())
    for candidate in ("smtp_flag", "smtp", "do_smtp", "smtp_check", "perform_smtp", "enable_smtp"):
        if candidate in param_names:
            kwargs[candidate] = smtp
            break
    return await validate_many_async(emails, **kwargs)

def _persist_results_to_db(jobid: str, user_id: int, results: List[Dict]) -> None:
    """
    Store each result into EmailVerification, link to BulkItem, upsert EmailsChecked.
    This is what your /bulk/jobs/{jobid} endpoint expects.
    """
    db = SessionLocal()
    try:
        from sqlalchemy.sql import func as _func

        for res in results:
            email = (res.get("email") or "").strip()

            # EmailVerification row
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
                result_json=json.dumps(res, ensure_ascii=False),
            )
            db.add(ev)
            db.flush()  # get ev.id

            # Link to the bulk job
            try:
                db.add(models.BulkItem(job_id=jobid, verification_id=ev.id))
            except Exception:
                # If BulkItem has extra fields in your model, add/fill them here.
                pass

            # Upsert EmailsChecked
            ec = (
                db.query(models.EmailsChecked)
                .filter(models.EmailsChecked.user_id == user_id,
                        models.EmailsChecked.email == email)
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
                ec.total_checks = (ec.total_checks or 0) + 1
                ec.last_status = res.get("final_status")
                ec.last_score = res.get("score")
                ec.last_checked_at = _func.now()
                db.add(ec)

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[BULK][DB-FAIL] jobid={jobid} err={e}")
        # Do not raise; we still want the job to finish and files to be downloadable.
    finally:
        db.close()

# ------------ RQ job ------------

def verify_chunk(jobid: str, idx: int, chunk: list, smtp: bool, user_id: int, outdir: str):
    """
    Enqueued by /validate-file:
      jobid, idx, chunk(list-of-emails), smtp(bool), user_id(int), outdir(str)
    Updates Redis hash bulk:{jobid}. On last chunk, merges parts and marks finished.
    """
    import anyio

    r.hset(f"bulk:{jobid}", "status", "running")

    emails = [e.strip() for e in (chunk or []) if isinstance(e, str) and e.strip()]
    if not emails:
        r.hincrby(f"bulk:{jobid}", "done", 0)
        return

    async def _run():
        return await _verify_emails(
            emails,
            smtp=smtp,
            workers=int(os.getenv("BULK_WORKERS", "12")),
        )

    try:
        results = anyio.run(_run)
    except Exception as e:
        # advance progress so the UI doesn't stall forever
        r.hincrby(f"bulk:{jobid}", "done", len(emails))
        r.hset(f"bulk:{jobid}", "status", "error")
        print(f"[BULK][CHUNK-FAIL] jobid={jobid} idx={idx} err={e}")
        return

    # ---- persist results to DB for the UI "View Results" page ----
    try:
        _persist_results_to_db(jobid, user_id, results)
    except Exception as e:
        print(f"[BULK][WARN] DB persist failed jobid={jobid} idx={idx} err={e}")

    # ---- write per-chunk outputs (and a fallback CSV) ----
    part_dir = Path(outdir)
    part_dir.mkdir(parents=True, exist_ok=True)
    part_csv = part_dir / f"part_{idx:04d}.csv"

    try:
        # If your writer writes into part_dir, keep it:
        write_outputs(results, part_dir)
        # Ensure there is a part CSV we can merge later:
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

    # ---- progress ----
    done = r.hincrby(f"bulk:{jobid}", "done", len(emails))
    total = int((r.hget(f"bulk:{jobid}", "total") or b"0").decode())

    # ---- finalization (merge files and set 'finished') ----
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

        results_json = Path(outdir) / "results.json"
        try:
            rows = []
            with results_csv.open("r", newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    rows.append(row)
            results_json.write_text(json.dumps(rows, ensure_ascii=False))
        except Exception:
            pass

        # Expose links on the SAME hash polled by /bulk/status/{jobid}
        files_payload = {
            "results_json": f"/download/{jobid}/results.json",
            "results_csv":  f"/download/{jobid}/results.csv",
        }
        r.hset(
            f"bulk:{jobid}",
            mapping={
                "status": "finished",
                "files": json.dumps(files_payload),
            },
        )
        # Optional: legacy list for other consumers
        r.rpush(f"job:{jobid}:files", "results.csv", "results.json")

# queue_utils.py
import os
import redis
from rq import Queue
from typing import Any, Dict, List

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
PROGRESS_KEY = "job:{jobid}:progress"
RESULTS_KEY  = "job:{jobid}:files"
import csv
from pathlib import Path
from typing import List

CHUNK_SIZE = 1000  # adjust if you want bigger/smaller chunks

def split_csv(csv_path: str | Path, chunk_size: int = CHUNK_SIZE) -> List[str]:
    """
    Split a CSV file into smaller chunk files with the same header.

    Returns a list of chunk file paths (as strings).
    Assumes there is an 'email' column in the header.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    # Create a per-upload chunk directory next to the original file
    outdir = csv_path.parent / f"chunks_{csv_path.stem}"
    outdir.mkdir(parents=True, exist_ok=True)

    chunks: list[str] = []

    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []

        if "email" not in fieldnames:
            raise ValueError("CSV must contain an 'email' column in the header.")

        buffer: list[dict] = []
        chunk_index = 0

        def flush_buffer():
            nonlocal chunk_index, buffer
            if not buffer:
                return
            chunk_file = outdir / f"{csv_path.stem}_part{chunk_index}.csv"
            with chunk_file.open("w", newline="", encoding="utf-8") as cf:
                writer = csv.DictWriter(cf, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(buffer)
            chunks.append(str(chunk_file))
            buffer = []
            chunk_index += 1

        for row in reader:
            # Skip rows without an email
            email = (row.get("email") or "").strip()
            if not email:
                continue
            buffer.append(row)
            if len(buffer) >= chunk_size:
                flush_buffer()

        # Last chunk
        flush_buffer()

    return chunks


def _get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)

def enqueue_job(queue_name: str, jobid: str, func_name: str, args: List[Any]):
    r = _get_redis()
    # Reset progress
    r.hset(PROGRESS_KEY.format(jobid=jobid), mapping={
        "total": 0,
        "done": 0,
        "chunks": 0,
        "status": "queued",
    })
    # Actually enqueue with RQ
    from importlib import import_module
    module_name, func_short = func_name.rsplit(".", 1)
    module = import_module(module_name)
    func = getattr(module, func_short)
    q = Queue(queue_name, connection=r)
    job = q.enqueue(func, *args)
    return job

def incr_done(jobid: str, total: int = None):
    r = _get_redis()
    key = PROGRESS_KEY.format(jobid=jobid)
    if total is not None:
        r.hset(key, "total", total)
    r.hincrby(key, "done", 1)

def init_progress(jobid: str, total_chunks: int, total_emails: int):
    r = _get_redis()
    r.hset(PROGRESS_KEY.format(jobid=jobid), mapping={
        "total": total_emails,
        "done": 0,
        "chunks": total_chunks,
        "status": "running",
    })

def push_file(jobid: str, filename: str):
    r = _get_redis()
    r.rpush(RESULTS_KEY.format(jobid=jobid), filename)

def set_status(jobid: str, status: str):
    r = _get_redis()
    r.hset(PROGRESS_KEY.format(jobid=jobid), "status", status)

def job_status(jobid: str) -> Dict[str, Any]:
    r = _get_redis()
    h = r.hgetall(PROGRESS_KEY.format(jobid=jobid)) or {}
    files = r.lrange(RESULTS_KEY.format(jobid=jobid), 0, -1) or []

    # Normalize output for frontend
    progress = {
        "total": int(h.get("total", 0)),
        "done": int(h.get("done", 0)),
        "chunks": int(h.get("chunks", 0)),
        "status": h.get("status", "unknown"),
    }
    return {
        "jobid": jobid,
        "progress": progress,
        "files": files,
    }

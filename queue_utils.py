import os, csv, uuid
from pathlib import Path
from typing import List, Dict
from redis import Redis
from rq import Queue

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
redis = Redis.from_url(REDIS_URL)
q = Queue("bulk", connection=redis)

PROGRESS_KEY = "job:{jobid}:progress"     # Redis hash
RESULTS_KEY  = "job:{jobid}:files"        # Redis list

CHUNK_SIZE = int(os.getenv("ROWS_PER_CHUNK", "5000"))

def split_csv(in_path: str) -> List[str]:
    p = Path(in_path)
    rows = list(csv.DictReader(p.open(encoding="utf-8", newline="")))
    outdir = p.parent / "chunks"
    outdir.mkdir(parents=True, exist_ok=True)

    headers = rows[0].keys() if rows else ["email"]
    parts = []
    for i in range(0, len(rows), CHUNK_SIZE):
        chunk_rows = rows[i:i+CHUNK_SIZE]
        cpath = outdir / f"chunk_{(i//CHUNK_SIZE)+1}.csv"
        with cpath.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
            w.writerows(chunk_rows)
        parts.append(str(cpath))
    return parts

def init_job(jobid: str, total_rows: int, chunk_count: int):
    redis.hset(PROGRESS_KEY.format(jobid=jobid), mapping={
        "status": "queued",
        "done": 0,
        "total": total_rows,
        "chunk_count": chunk_count
    })

def incr_done(jobid: str, n: int):
    redis.hincrby(PROGRESS_KEY.format(jobid=jobid), "done", n)

def set_status(jobid: str, status: str):
    redis.hset(PROGRESS_KEY.format(jobid=jobid), "status", status)

def push_file(jobid: str, path: str):
    redis.rpush(RESULTS_KEY.format(jobid=jobid), path)

def job_status(jobid: str) -> Dict:
    h = redis.hgetall(PROGRESS_KEY.format(jobid=jobid)) or {}
    files = [b.decode() for b in redis.lrange(RESULTS_KEY.format(jobid=jobid), 0, -1)]
    prog = {k.decode(): v.decode() for k, v in h.items()}
    return {"jobid": jobid, "progress": prog, "files": files}

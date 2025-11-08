# queue_utils.py
import os
import redis
from rq import Queue
from typing import Any, Dict, List

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
PROGRESS_KEY = "job:{jobid}:progress"
RESULTS_KEY  = "job:{jobid}:files"

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

# tasks_rq.py
import os
import json
import csv
from pathlib import Path
from typing import List
from queue_utils import incr_done, push_file, set_status

def verify_chunk(jobid: str, index: int, chunk_path: str,
                 smtp: bool, workers: int, outdir: str):
    """
    This is run by the RQ worker.
    """
    # 1) Read emails from chunk_path
    emails = []
    with open(chunk_path, newline="") as f:
        reader = csv.reader(f)
        headers = next(reader, None)
        for row in reader:
            if row:
                emails.append(row[0].strip())

    # 2) Run your existing validation logic here.
    #    You already have something that writes CSV/JSON, as seen in logs.
    #    I'll sketch it; plug in your real validator.
    results = []
    for email in emails:
        # TODO: call your real single-email validation function
        # For example:
        # res = validate_single_email(email, smtp=smtp)
        res = {
            "email": email,
            "valid_syntax": True,
            "valid_mx": True,
            "smtp_status": "ok" if smtp else "skipped",
        }
        results.append(res)

    # 3) Write chunk results to per-job files
    os.makedirs(outdir, exist_ok=True)
    json_path = os.path.join(outdir, f"chunk_{index}.json")
    with open(json_path, "w") as jf:
        json.dump(results, jf)

    # Optional: also append to a combined CSV/JSON
    # or let another job merge chunks later.

    # 4) Update Redis
    incr_done(jobid, total=len(emails))  # updates done and total
    push_file(jobid, json_path)

    # If you want: when done == chunks -> set_status(jobid, "done")
    # That requires reading current progress; you can add a helper for that.

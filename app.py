#!/usr/bin/env python3
"""
app.py — Async email verifier core

What’s new (high level):
- Async pipeline with asyncio.gather to run DNS (MX/TXT), HTTP probe, and SMTP (wrapped) in parallel.
- MX/ASN fingerprinting to detect disposable providers beyond static lists.
- Dynamic disposable list (remote + cached) with graceful fallback.
- Per-domain TTL cache to avoid re-querying the same domain repeatedly.
- CSV output hides SPF/DKIM/DMARC (still computed for scoring).
"""

from __future__ import annotations
import os
import re
import csv
import json
import time
import random
import socket
import logging
import asyncio
import tempfile
import smtplib
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import dns.exception

# -------------------------
# Config
# -------------------------
LOG_LEVEL = logging.INFO
DNS_TIMEOUT = 3
SMTP_TIMEOUT = 7
SMTP_RETRY_COUNT = 1
SMTP_RETRY_BACKOFF = 2
DEFAULT_WORKERS = 8
MAX_CONCURRENT_SMTP = 60

# Async thread pool (for blocking libs: dnspython/smtplib/urllib)
_EXEC = ThreadPoolExecutor(max_workers=min(64, (os.cpu_count() or 4) * 8))

logger = logging.getLogger("verifier")
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_handler)
logger.setLevel(LOG_LEVEL)

# -------------------------
# Regexes / constants
# -------------------------
EMAIL_REGEX = re.compile(
    r'^(?:"[^"]+"|[A-Za-z0-9!#$%&\'*+/=?^_`{|}~.-]+)@'
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
    r'[A-Za-z]{2,}$'
)

SMTP_USER_NOT_FOUND_RE = re.compile(
    r"user not found|unknown user|no such user|recipient .* not found|mailbox unavailable|"
    r"unknown recipient|550 5\.1\.1|recipient unknown|no mailbox here by that name",
    re.IGNORECASE,
)

ROLE_LOCALPARTS = {
    "admin","administrator","info","support","sales","contact","help","office","postmaster"
}
FREE_PROVIDERS = {"gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com"}

PROVIDER_RULES = {
    "gmail.com": {"mode": "trust_mx"},
    "googlemail.com": {"mode": "trust_mx"},
    "hotmail.com": {"mode": "trust_mx"},
    "outlook.com": {"mode": "trust_mx"},
    "live.com": {"mode": "trust_mx"},
    "yahoo.com": {"mode": "strict"},
    "aol.com": {"mode": "strict"},
    "gmx.com": {"mode": "strict"},
    "zoho.com": {"mode": "strict"},
}

# -------------------------
# Dynamic disposable sources
# -------------------------
DISPOSABLE_FALLBACK = {
    "mailinator.com","tempmail.net","10minutemail.com","trashmail.com","guerrillamail.com","yopmail.com"
}
DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/disposable_email_blacklist.conf",
    "https://disposable.github.io/disposable-email-domains/domains.json",
]

def _fetch_text(url: str, timeout: int = 6) -> Optional[str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = r.read()
            try:
                return data.decode("utf-8")
            except Exception:
                return data.decode("latin-1", errors="ignore")
    except Exception:
        return None

def _parse_domains(payload: str) -> List[str]:
    payload = (payload or "").strip()
    if not payload:
        return []
    try:
        arr = json.loads(payload)
        if isinstance(arr, list):
            return [str(x).strip().lower().rstrip(".") for x in arr if isinstance(x, str) and x.strip()]
    except Exception:
        pass
    out = []
    for line in payload.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or " " in line:
            continue
        out.append(line.lower().rstrip("."))
    return out

def load_disposable_domains_dynamic() -> set:
    disable_fetch = os.getenv("DISPOSABLE_DISABLE_FETCH", "false").lower() == "true"
    ttl = int(os.getenv("DISPOSABLE_TTL_SECONDS", "86400"))
    cache_path = os.getenv("DISPOSABLE_CACHE_PATH") or os.path.join(tempfile.gettempdir(), "disposable_domains.cache")
    src_env = os.getenv("DISPOSABLE_SOURCES")
    sources = [s.strip() for s in src_env.split(",")] if src_env else DEFAULT_SOURCES

    try:
        if os.path.exists(cache_path):
            if (time.time() - os.path.getmtime(cache_path)) <= ttl:
                with open(cache_path, "r", encoding="utf-8") as f:
                    arr = json.load(f)
                    if isinstance(arr, list):
                        return set([d.strip().lower() for d in arr if isinstance(d, str) and d.strip()])
    except Exception:
        pass

    merged = set()
    if not disable_fetch:
        for url in sources:
            txt = _fetch_text(url, timeout=6)
            if not txt:
                continue
            merged.update(_parse_domains(txt))
        if merged:
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(sorted(merged), f)
            except Exception:
                pass
            return merged
    return set(DISPOSABLE_FALLBACK)

DISPOSABLE_DOMAINS = load_disposable_domains_dynamic()

# -------------------------
# Light TTL cache (per-domain)
# -------------------------
class TTLCache:
    def __init__(self, ttl_seconds: int = 86400, max_items: int = 10000):
        self.ttl = ttl_seconds
        self.max_items = max_items
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        v = self._store.get(key)
        if not v:
            return None
        ts, data = v
        if (time.time() - ts) > self.ttl:
            self._store.pop(key, None)
            return None
        return data

    def set(self, key: str, data: Any) -> None:
        if len(self._store) >= self.max_items:
            # simple eviction: drop one old entry
            try:
                self._store.pop(next(iter(self._store)))
            except Exception:
                self._store.clear()
        self._store[key] = (time.time(), data)

DOMAIN_CACHE = TTLCache(ttl_seconds=int(os.getenv("DOMAIN_CACHE_TTL", "86400")))

# -------------------------
# Helpers
# -------------------------
def norm_domain(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")

# dnspython is blocking; wrap with asyncio.to_thread
def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = DNS_TIMEOUT
    return r

async def lookup_mx_async(domain: str) -> Tuple[List[str], bool]:
    domain = norm_domain(domain)
    def _do():
        res = _resolver()
        try:
            answers = res.resolve(domain, "MX", lifetime=DNS_TIMEOUT)
            pairs = []
            for r in answers:
                pref = getattr(r, "preference", 0)
                exch = str(r.exchange).rstrip(".")
                pairs.append((int(pref) if isinstance(pref, int) else 0, exch))
            pairs.sort(key=lambda x: x[0])
            return [e for _, e in pairs], False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            # implicit via A/AAAA
            hosts = []
            try:
                for a in res.resolve(domain, "A", lifetime=DNS_TIMEOUT):
                    hosts.append(str(a))
            except Exception:
                pass
            try:
                for a in res.resolve(domain, "AAAA", lifetime=DNS_TIMEOUT):
                    hosts.append(str(a))
            except Exception:
                pass
            return hosts, True
        except dns.exception.Timeout:
            raise
        except Exception:
            return [], False
    return await asyncio.to_thread(_do)

async def lookup_txt_async(name: str) -> List[str]:
    name = norm_domain(name)
    def _do():
        res = _resolver()
        try:
            answers = res.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
            out = []
            for r in answers:
                try:
                    if hasattr(r, "strings"):
                        parts = [(p.decode(errors="ignore") if isinstance(p, (bytes, bytearray)) else str(p)) for p in r.strings]
                        out.append("".join(parts))
                    else:
                        out.append(r.to_text().strip('"'))
                except Exception:
                    out.append(r.to_text().strip('"'))
            return out
        except Exception:
            return []
    return await asyncio.to_thread(_do)

async def has_spf_async(domain: str) -> bool:
    txts = await lookup_txt_async(domain)
    return any("v=spf1" in t.lower() for t in txts)

async def has_dmarc_async(domain: str) -> bool:
    txts = await lookup_txt_async(f"_dmarc.{domain}")
    return any("v=dmarc1" in t.lower() for t in txts)

async def has_dkim_async(domain: str, selectors: Optional[List[str]] = None) -> bool:
    if selectors is None:
        selectors = ["selector1", "default"]
    tasks = [lookup_txt_async(f"{s}._domainkey.{domain}") for s in selectors]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for txts in results:
        if isinstance(txts, Exception):
            continue
        if any("v=dkim1" in (t.lower()) for t in txts):
            return True
    return False

async def http_head_probe_async(domain: str, timeout: float = 1.0) -> Dict[str, Any]:
    # Simple HEAD/GET marker scan with tight timeout
    def _do():
        url = f"http://{domain}/"
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                server = r.headers.get("Server", "")
                ct = r.headers.get("Content-Type", "")
                return {"ok": True, "server": server, "content_type": ct, "status": getattr(r, "status", 200)}
        except Exception:
            # Fallback GET (sometimes HEAD is blocked)
            try:
                with urllib.request.urlopen(f"http://{domain}/", timeout=timeout) as r:
                    server = r.headers.get("Server", "")
                    ct = r.headers.get("Content-Type", "")
                    return {"ok": True, "server": server, "content_type": ct, "status": getattr(r, "status", 200)}
            except Exception as e:
                return {"ok": False, "error": str(e)}
    return await asyncio.to_thread(_do)

async def resolve_a_async(host: str) -> List[str]:
    host = str(host).rstrip(".")
    def _do():
        res = _resolver()
        ips = []
        try:
            for a in res.resolve(host, "A", lifetime=DNS_TIMEOUT):
                ips.append(str(a))
        except Exception:
            pass
        try:
            for a in res.resolve(host, "AAAA", lifetime=DNS_TIMEOUT):
                ips.append(str(a))
        except Exception:
            pass
        return ips
    return await asyncio.to_thread(_do)

async def asn_lookup_cymru_async(ip: str) -> Optional[str]:
    """
    Team Cymru DNS: <reversed ip>.origin.asn.cymru.com TXT
    Returns ASN as string or None.
    """
    def _do():
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                rev = ".".join(reversed(parts))
                qname = f"{rev}.origin.asn.cymru.com"
            else:
                # rudimentary: skip IPv6 ASN for now
                return None
            res = _resolver()
            answers = res.resolve(qname, "TXT", lifetime=DNS_TIMEOUT)
            for r in answers:
                txt = r.to_text().strip('"')
                # format: "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
                # example: "13335 | 1.1.1.1 | 1.1.1.0/24 | AU | apnic | 2011-08-11 | CLOUDFLARENET - Cloudflare, Inc."
                if "|" in txt:
                    asn = txt.split("|")[0].strip()
                    if asn:
                        return asn
        except Exception:
            return None
        return None
    return await asyncio.to_thread(_do)

def _make_mailfrom(smtp_from: str) -> str:
    smtp_from = (smtp_from or "").strip()
    try:
        local_host = socket.getfqdn() or "localhost"
    except Exception:
        local_host = "localhost"
    if smtp_from == "" or smtp_from.endswith("@example.com") or smtp_from.endswith("@example.org") or smtp_from.endswith("@example.net"):
        return f"noreply@{local_host}"
    return smtp_from

def _smtp_rcpt_once(mx_host: str, smtp_from: str, rcpt: str, timeout: int = SMTP_TIMEOUT) -> Dict[str, Any]:
    res = {"code": None, "message": "", "accepted": None, "perm": False, "temp": False}
    mx_host = str(mx_host).rstrip(".")
    smtp_from = _make_mailfrom(smtp_from)
    try:
        local_hostname = socket.getfqdn() or "localhost"
    except Exception:
        local_hostname = "localhost"
    try:
        s = smtplib.SMTP(timeout=timeout)
        s.connect(mx_host, 25)
        try: s.ehlo(name=local_hostname)
        except Exception:
            try: s.helo(name=local_hostname)
            except Exception: pass
        try: s.mail(smtp_from)
        except Exception: pass
        code, msg = s.rcpt(rcpt)
        try: res["code"] = int(code) if code is not None else None
        except Exception: res["code"] = None
        try:
            res["message"] = msg.decode(errors="ignore") if isinstance(msg, (bytes, bytearray)) else str(msg)
        except Exception:
            res["message"] = str(msg)
        if res["code"] is not None:
            if 200 <= res["code"] < 300:
                res["accepted"] = True
            elif 400 <= res["code"] < 500:
                res["temp"] = True; res["accepted"] = False
            elif 500 <= res["code"] < 600:
                res["perm"] = True; res["accepted"] = False
        if SMTP_USER_NOT_FOUND_RE.search(res["message"] or ""):
            res["perm"] = True; res["accepted"] = False
        try: s.quit()
        except Exception:
            try: s.close()
            except Exception: pass
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        res["message"] = f"connect_error:{e}"
        res["accepted"] = None
        res["temp"] = True
    except Exception as e:
        res["message"] = f"error:{e}"
        res["accepted"] = None
    return res

async def smtp_probe_host_async(host: str, smtp_from: str, rcpt: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_smtp_rcpt_once, host, smtp_from, rcpt, SMTP_TIMEOUT)

async def probe_domain_async(mx_hosts: List[str], domain: str, smtp_from: str, target_email: str, implicit_mx: bool) -> Dict[str, Any]:
    domain = norm_domain(domain)
    if not mx_hosts:
        return {"smtp_ok": None, "catch_all": None, "hosts": [], "reason": "no mx hosts"}

    rand_local = "noexist_" + ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
    random_addr = f"{rand_local}@{domain}"
    # probe only best host (fast path like before)
    host = mx_hosts[0]

    target_task = smtp_probe_host_async(host, smtp_from, target_email)
    random_task = smtp_probe_host_async(host, smtp_from, random_addr)
    target_res, random_res = await asyncio.gather(target_task, random_task)

    host_results = [{"host": host, "target": target_res, "random": random_res}]
    perm_reject_target = [hr for hr in host_results if hr["target"].get("perm")]
    accept_target = [hr for hr in host_results if hr["target"].get("accepted") is True]
    accept_random = [hr for hr in host_results if hr["random"].get("accepted") is True]
    temp_any = any((hr["target"].get("temp") or hr["random"].get("temp")) for hr in host_results)

    smtp_ok = None; catch_all = None; reason = ""
    if accept_target and any(hr for hr in host_results if (hr["random"].get("perm") or hr["random"].get("accepted") is False)):
        smtp_ok = True; catch_all = False; reason = "Target accepted, random rejected"
    elif perm_reject_target and not accept_target:
        smtp_ok = False; catch_all = False; reason = "Hosts permanently rejected target"
    elif accept_target and accept_random:
        smtp_ok = None; catch_all = True; reason = "Accepts target AND random (catch-all)"
    elif accept_target and not accept_random:
        smtp_ok = True; catch_all = False; reason = "Target accepted; random not accepted"
    elif temp_any:
        smtp_ok = None; catch_all = None; reason = "Temporary errors (4xx/greylisting)"
    else:
        smtp_ok = None; catch_all = None; reason = "No clear acceptance pattern"

    return {"smtp_ok": smtp_ok, "catch_all": catch_all, "hosts": host_results, "reason": reason}

# -------------------------
# MX/ASN fingerprinting for disposable
# -------------------------
DISPOSABLE_MX_KEYWORDS = {
    "mailinator","yopmail","guerrillamail","trashmail","tempmail","10minutemail","temp-mail"
}
# Optionally configure known disposable ASNs via env: DISPOSABLE_ASN_LIST="AS1234,AS5678"
DISPOSABLE_ASN_LIST = {
    a.strip().upper() for a in (os.getenv("DISPOSABLE_ASN_LIST", "").split(",")) if a.strip()
}

def mx_matches_disposable_keywords(mx_hosts: List[str]) -> bool:
    mxs = ",".join(mx_hosts).lower()
    return any(k in mxs for k in DISPOSABLE_MX_KEYWORDS)

async def asn_fingerprints_for_mx(mx_hosts: List[str]) -> List[str]:
    asns = []
    if not mx_hosts:
        return asns
    # Only first host (fast)
    ips = await resolve_a_async(mx_hosts[0])
    if not ips:
        return asns
    tasks = [asn_lookup_cymru_async(ip) for ip in ips]
    res = await asyncio.gather(*tasks, return_exceptions=True)
    for r in res:
        if isinstance(r, str) and r:
            asns.append(r.upper() if not r.upper().startswith("AS") else r.upper())
        elif isinstance(r, str):
            asns.append(r)
    # normalize to "AS12345"
    out = []
    for a in asns:
        if not a:
            continue
        a = a.strip().upper()
        if a.startswith("AS"):
            out.append(a)
        else:
            out.append("AS" + a)
    return list(dict.fromkeys(out))  # dedupe, preserve order

# -------------------------
# Validation (async)
# -------------------------
def _count_chars(local: str) -> Tuple[int,int,int]:
    return (
        sum(1 for c in local if c.isalpha()),
        sum(1 for c in local if c.isdigit()),
        sum(1 for c in local if ord(c) > 127)
    )

async def validate_single_async(email: str, smtp_from: str, db_conn, smtp_probe_flag: bool) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "email": email, "local_part": None, "domain": None,
        "syntax_ok": False,
        "disposable": False, "role_based": False, "free_provider": False,
        "mx_hosts": [], "mx_ok": False, "implicit_mx_record": False,
        "spf": False, "dkim": False, "dmarc": False,
        "smtp_tested": False, "smtp_ok": None, "catch_all": None, "smtp_reason": "",
        "score": None, "final_status": None, "notes": [], "probe_details": None,
        "state": None, "reason": None,
        "smtp_provider": None, "mx_record": None,
        "free": False, "role": False, "accept_all": False, "tag": False,
        "numerical_characters": 0, "alphabetical_characters": 0, "unicode_symbols": 0,
        "mailbox_full": False, "no_reply": False, "secure_email_gateway": False,
        "disposable_signals": {"mx_keyword": False, "asn_match": False, "http_marker": False}
    }

    email_str = (email or "").strip()
    res["email"] = email_str
    if not email_str or not EMAIL_REGEX.match(email_str):
        res["final_status"] = "invalid"; res["syntax_ok"] = False
        res["score"] = 0; res["state"] = "Undeliverable"; res["reason"] = "Invalid format"
        return res
    res["syntax_ok"] = True

    local, domain = email_str.rsplit("@", 1)
    domain = norm_domain(domain)
    res["local_part"] = local; res["domain"] = domain

    alpha, digits, uni = _count_chars(local)
    res["alphabetical_characters"] = alpha
    res["numerical_characters"] = digits
    res["unicode_symbols"] = uni
    res["no_reply"] = local.lower().startswith(("no-reply","noreply"))
    res["role"] = local.lower() in ROLE_LOCALPARTS or any(local.lower().startswith(r + "+") for r in ROLE_LOCALPARTS)
    res["free"] = domain in FREE_PROVIDERS
    res["tag"] = "+" in local

    # Domain-level cache
    cached = DOMAIN_CACHE.get(domain)
    if cached:
        mx_hosts = cached.get("mx_hosts", [])
        implicit_mx = cached.get("implicit_mx", False)
        spf = cached.get("spf", False)
        dkim = cached.get("dkim", False)
        dmarc = cached.get("dmarc", False)
        http_info = cached.get("http_info", {"ok": False})
        asns = cached.get("asns", [])
    else:
        mx_task = lookup_mx_async(domain)
        spf_task = has_spf_async(domain)
        dkim_task = has_dkim_async(domain)
        dmarc_task = has_dmarc_async(domain)
        http_task = http_head_probe_async(domain, timeout=float(os.getenv("HTTP_PROBE_TIMEOUT", "1.0")))

        mx_hosts, implicit_mx = await mx_task
        spf, dkim, dmarc, http_info = await asyncio.gather(spf_task, dkim_task, dmarc_task, http_task)

        # ASN lookup depends on MX
        asns = await asn_fingerprints_for_mx(mx_hosts)

        DOMAIN_CACHE.set(domain, {
            "mx_hosts": mx_hosts, "implicit_mx": implicit_mx,
            "spf": spf, "dkim": dkim, "dmarc": dmarc,
            "http_info": http_info, "asns": asns
        })

    res["mx_hosts"] = mx_hosts
    res["mx_ok"] = bool(mx_hosts)
    res["implicit_mx_record"] = bool(implicit_mx)
    res["mx_record"] = (mx_hosts[0] if mx_hosts else None)
    res["spf"] = spf; res["dkim"] = dkim; res["dmarc"] = dmarc

    # Lightweight provider tag
    mx_join = ",".join(mx_hosts).lower()
    if "google" in mx_join or "gmail" in mx_join:
        res["smtp_provider"] = "Google"
    elif any(k in mx_join for k in ("outlook","hotmail","office365","protection.outlook")):
        res["smtp_provider"] = "Microsoft"
    elif "yahoo" in mx_join:
        res["smtp_provider"] = "Yahoo"
    else:
        res["smtp_provider"] = "Other"

    # Dynamic disposable detection
    disposable = (domain in DISPOSABLE_DOMAINS)
    mx_keyword = mx_matches_disposable_keywords(mx_hosts)
    asn_match = any(a in DISPOSABLE_ASN_LIST for a in (asns or []))
    http_marker = False
    # Heuristic: if HTTP server header or title suggests temp mail (keep conservative)
    if isinstance(DOMAIN_CACHE.get(domain), dict):
        info = DOMAIN_CACHE.get(domain).get("http_info", {})
    else:
        info = {}
    server = (info or {}).get("server","").lower()
    if any(k in server for k in ("mailinator","yopmail","temporary","temp-mail","10minutemail")):
        http_marker = True

    res["disposable_signals"] = {"mx_keyword": mx_keyword, "asn_match": asn_match, "http_marker": http_marker}
    if not disposable and (mx_keyword or asn_match or http_marker):
        disposable = True
        res["notes"].append("disposable inferred by MX/ASN/HTTP fingerprint")

    res["disposable"] = disposable

    # Early exit if no MX
    if not mx_hosts:
        res["final_status"] = "invalid"
        res["notes"].append("no MX/A records")
        res["score"] = 0
        res["state"] = "Undeliverable"
        res["reason"] = "No MX or A/AAAA records"
        return res

    # SMTP probing (parallel path)
    if smtp_probe_flag:
        res["smtp_tested"] = True
        probe = await probe_domain_async(mx_hosts, domain, _make_mailfrom(smtp_from), email_str, implicit_mx)
        res["smtp_ok"] = probe["smtp_ok"]
        res["catch_all"] = probe["catch_all"]
        res["smtp_reason"] = probe["reason"]
        res["probe_details"] = probe["hosts"]
        if probe["reason"]:
            res["notes"].append(probe["reason"])

    # Scoring (kept close to your prior logic; still heuristic)
    score = 50
    if res["mx_ok"]:
        score += 12
        if res["implicit_mx_record"]:
            score -= 6
    if res["disposable"]:
        score -= 35
    if res["role"]:
        score -= 10
    if res["free"]:
        score += 5
    if res.get("spf"): score += 4
    if res.get("dkim"): score += 4
    if res.get("dmarc"): score += 4

    if smtp_probe_flag:
        if res["smtp_ok"] is True: score += 25
        elif res["smtp_ok"] is False: score -= 30
        else: score -= 3
        if res["catch_all"]: score -= 15

    pr = PROVIDER_RULES.get(domain)
    if pr:
        mode = pr.get("mode")
        if mode == "trust_mx":
            if res["mx_ok"] and (res["smtp_ok"] is not False): score += 8
            if res["smtp_ok"] is False: score -= 20
        elif mode == "strict":
            if res["smtp_ok"] is True and not res["catch_all"]: score += 12
            elif res["smtp_ok"] is None: score -= 6

    # Guardrails
    if not smtp_probe_flag:
        score = min(score, 60)
    elif res.get("smtp_ok") is None:
        score = min(score, 70)
    if res.get("catch_all"): score = min(score, 60)
    if res.get("smtp_ok") is False: score = min(score, 30)
    if res.get("mx_ok") and res.get("implicit_mx_record"):
        score = min(score, 50)

    score = max(0, min(100, int(score)))
    res["score"] = score

    if res.get("smtp_ok") is True and not res.get("catch_all") and score >= 65:
        final = "valid"
    elif score >= 45:
        final = "risky"
    else:
        final = "invalid"
    res["final_status"] = final
    res["state"] = "Deliverable" if final == "valid" else ("Risky" if final == "risky" else "Undeliverable")
    if res.get("smtp_ok") is True:
        res["reason"] = "ACCEPTED EMAIL"
    elif res.get("smtp_ok") is False:
        res["reason"] = "REJECTED EMAIL"
    else:
        res["reason"] = res["smtp_reason"] or (res["notes"][0] if res["notes"] else "")

    res["accept_all"] = bool(res.get("catch_all"))

    # mailbox full / seg
    if res.get("probe_details"):
        for host in res["probe_details"]:
            tmsg = (host.get("target") or {}).get("message") or ""
            if "mailbox full" in tmsg.lower() or "quota exceeded" in tmsg.lower():
                res["mailbox_full"] = True

    if any(x for x in mx_join.split(",") if any(g in x for g in ("protection","proofpoint","barracuda","mxlogic","emailfilter","email-protection"))):
        res["secure_email_gateway"] = True

    if res["disposable"]:
        res["notes"].append("disposable domain")
    if res["role"]:
        res["notes"].append("role-based mailbox")
    if res["catch_all"]:
        res["notes"].append("catch-all detected")
    if res["smtp_tested"] and res["smtp_ok"] is False:
        res["notes"].append("smtp rejected (permanent)")

    return res

# -------------------------
# Compatibility shims used by main.py
# -------------------------
def connect_db(path: str):  # retained for compatibility
    return None

def init_db(conn):
    return None

# -------------------------
# CSV helpers
# -------------------------
def load_emails_from_csv(path: str) -> List[str]:
    emails: List[str] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        content = f.read()
        if not content:
            return []
        f.seek(0)
        try:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            if headers:
                email_col = None
                for h in headers:
                    if "email" in str(h).lower():
                        email_col = h; break
                if email_col:
                    for row in reader:
                        cell = (row.get(email_col) or "").strip()
                        if cell and "@" in cell and EMAIL_REGEX.match(cell):
                            emails.append(cell)
                    return emails
                f.seek(0)
                rdr = csv.reader(f)
                rows = list(rdr)
                if not rows: return []
                col_counts = {}
                for r in rows[1:]:
                    for idx, val in enumerate(r):
                        if val and "@" in val:
                            col_counts[idx] = col_counts.get(idx, 0) + 1
                if col_counts:
                    best_idx = max(col_counts.items(), key=lambda x: x[1])[0]
                    for r in rows[1:]:
                        if best_idx < len(r):
                            v = r[best_idx].strip()
                            if v and EMAIL_REGEX.match(v):
                                emails.append(v)
                    return emails
                for r in rows[1:]:
                    if r and len(r) > 0:
                        v = r[0].strip()
                        if v and EMAIL_REGEX.match(v):
                            emails.append(v)
                return emails
            else:
                f.seek(0)
                rdr = csv.reader(f)
                rows = list(rdr)
                for r in rows:
                    if not r: continue
                    if len(r) == 1:
                        v = r[0].strip()
                        if v and EMAIL_REGEX.match(v):
                            emails.append(v)
                    else:
                        for c in r:
                            if c and "@" in c and EMAIL_REGEX.match(c):
                                emails.append(c.strip()); break
                return emails
        except Exception:
            f.seek(0)
            for line in f:
                line = line.strip()
                if "@" in line and EMAIL_REGEX.match(line):
                    emails.append(line)
            return emails

def write_outputs(results: List[Dict[str, Any]], outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    csv_path = os.path.join(outdir, "results.csv")
    json_path = os.path.join(outdir, "results.json")
    if not results:
        logger.info("No results to write."); return

    # SPF/DKIM/DMARC intentionally NOT in CSV
    header = [
        "email","state","reason","final_status","score","syntax_ok",
        "local_part","domain",
        "mx_ok","mx_record","implicit_mx_record","mx_hosts",
        "smtp_tested","smtp_ok","catch_all","smtp_reason",
        "free","role","disposable","accept_all","tag",
        "numerical_characters","alphabetical_characters","unicode_symbols",
        "mailbox_full","no_reply","secure_email_gateway",
        "smtp_provider","notes","probe_details",
        # bonus (compact) disposable signals for debugging
        "disposable_mx_keyword","disposable_asn_match","disposable_http_marker"
    ]

    rows = []
    for r in results:
        row = {}
        for h in header:
            if h == "mx_hosts":
                row[h] = ",".join(r.get("mx_hosts") or [])
            elif h == "probe_details":
                pd = r.get("probe_details")
                if not pd: row[h] = ""
                else:
                    parts = []
                    for hr in pd:
                        host = hr.get("host")
                        t = hr.get("target") or {}
                        rr = hr.get("random") or {}
                        parts.append(f"{host}:T({t.get('code')},{int(bool(t.get('accepted')))})R({rr.get('code')},{int(bool(rr.get('accepted')))})")
                    row[h] = " | ".join(parts)
            elif h == "notes":
                row[h] = " ; ".join(r.get("notes") or [])
            elif h == "disposable_mx_keyword":
                row[h] = int(bool((r.get("disposable_signals") or {}).get("mx_keyword")))
            elif h == "disposable_asn_match":
                row[h] = int(bool((r.get("disposable_signals") or {}).get("asn_match")))
            elif h == "disposable_http_marker":
                row[h] = int(bool((r.get("disposable_signals") or {}).get("http_marker")))
            else:
                row[h] = r.get(h) if h in r else ""
        rows.append(row)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header); w.writeheader(); w.writerows(rows)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, indent=2, ensure_ascii=False)
    logger.info(f"Wrote CSV -> {csv_path}")
    logger.info(f"Wrote JSON -> {json_path}")

# -------------------------
# Orchestrators (bulk)
# -------------------------
async def validate_many_async(emails: List[str], smtp_from: str, smtp_flag: bool, workers: int) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(max(1, workers))

    async def _one(e: str):
        async with sem:
            try:
                return await validate_single_async(e, smtp_from, None, smtp_flag)
            except Exception as ex:
                logger.exception(f"validate error for {e}: {ex}")
                return {"email": e, "final_status": "error", "notes": [str(ex)]}

    tasks = [_one(e) for e in emails]
    return await asyncio.gather(*tasks)

# CLI compatibility
def run_file(input_file: str, outdir: str, smtp_flag: bool, smtp_from: str, db_path: str, workers: int) -> None:
    emails = load_emails_from_csv(input_file)
    if not emails:
        write_outputs([], outdir); return
    results = asyncio.run(validate_many_async(emails, smtp_from, smtp_flag, max(1, workers)))
    write_outputs(results, outdir)

def parse_args():
    import argparse
    p = argparse.ArgumentParser(description="Async email verifier")
    p.add_argument("input_file")
    p.add_argument("--outdir", default="results")
    p.add_argument("--smtp", dest="smtp", action="store_true", default=True)
    p.add_argument("--no-smtp", dest="smtp", action="store_false")
    p.add_argument("--smtp-from", default="noreply@example.com")
    p.add_argument("--db", default="")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_file(args.input_file, args.outdir, args.smtp, args.smtp_from, args.db, args.workers)

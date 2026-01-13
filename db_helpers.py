# db_helpers.py
import os
import sqlite3
import hashlib
from datetime import datetime
from db import BASE_DIR

DB_PATH = os.path.join(BASE_DIR, "webscan.db")

def get_conn():
    return sqlite3.connect(DB_PATH)

# --- Minimal collector + normalizer + scoring ---
def collect_domain_data(domain: str):
    # Domain-stable variability via hash
    h = int(hashlib.sha256(domain.lower().encode()).hexdigest(), 16)

    # Simulated signals
    open_ports = [80, 443] + ([22] if (h % 3 == 0) else [])
    ssl_days_left = (h % 90)  # 0-89 days
    has_csp = (h % 5 != 0)
    server = ["Apache", "Nginx", "IIS"][h % 3]
    headers = {
        "CSP": "present" if has_csp else "missing",
        "HSTS": "present" if (h % 4 != 0) else "missing",
        "X-Frame-Options": "present" if (h % 6 != 0) else "missing",
    }

    # Normalized findings
    findings = []
    findings.append({
        "parameter": "Ports:Open",
        "risk": f"Open ports detected: {open_ports}",
        "severity": "medium" if len(open_ports) > 2 else "low",
        "value": ",".join(map(str, open_ports))
    })
    findings.append({
        "parameter": "SSL:ExpiryDays",
        "risk": f"SSL expires in {ssl_days_left} days",
        "severity": "high" if ssl_days_left < 7 else ("medium" if ssl_days_left < 30 else "low"),
        "value": str(ssl_days_left)
    })
    findings.append({
        "parameter": "Headers:CSP",
        "risk": "Missing Content-Security-Policy" if headers["CSP"] == "missing" else "CSP present",
        "severity": "high" if headers["CSP"] == "missing" else "low",
        "value": headers["CSP"]
    })
    findings.append({
        "parameter": "Server:Fingerprint",
        "risk": f"Server: {server}",
        "severity": "medium" if server == "Apache" else "low",
        "value": server
    })

    # Intelligence scoring (simple v0)
    score = 100
    if 22 in open_ports: score -= 15
    if ssl_days_left < 7: score -= 25
    elif ssl_days_left < 30: score -= 10
    if headers["CSP"] == "missing": score -= 20
    if headers["HSTS"] == "missing": score -= 10

    verdict = "Safe" if score >= 85 else ("Warning" if score >= 65 else "Critical")
    severity = "low" if score >= 85 else ("medium" if score >= 65 else "high")

    # Events
    now = datetime.utcnow().isoformat()
    events = [
        {"change": "Scan started", "severity": "low", "time": now},
        {"change": f"Ports analyzed: {open_ports}", "severity": "low", "time": now},
        {"change": f"Headers analyzed (CSP:{headers['CSP']}, HSTS:{headers['HSTS']})", "severity": "low", "time": now},
        {"change": "Scan completed", "severity": "low", "time": now},
    ]

    # Actions (recommendations)
    actions = []
    if headers["CSP"] == "missing":
        actions.append({"issue": "Missing CSP", "risk": "High", "action": "Add Content-Security-Policy", "status": "Open"})
    if ssl_days_left < 7:
        actions.append({"issue": "SSL Expiry <7d", "risk": "High", "action": "Renew certificate immediately", "status": "Open"})
    if 22 in open_ports:
        actions.append({"issue": "SSH exposed", "risk": "Medium", "action": "Restrict SSH or move behind VPN", "status": "Pending"})

    return {
        "trust_score": max(0, min(100, score)),
        "verdict": verdict,
        "severity": severity,
        "findings": findings,
        "events": events,
        "actions": actions
    }

def save_scan_results(domain: str, trust_score: int, verdict: str, severity: str,
                      findings: list, events: list, actions: list):
    conn = get_conn()
    cur = conn.cursor()

    # Insert run
    created_at = datetime.utcnow().isoformat()
    cur.execute("""
        INSERT INTO runs (domain, trust_score, verdict, severity, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (domain, trust_score, verdict, severity, created_at))
    run_id = cur.lastrowid

    # Insert findings
    for f in findings:
        cur.execute("""
            INSERT INTO findings (run_id, parameter, risk, severity, value)
            VALUES (?, ?, ?, ?, ?)
        """, (run_id, f.get("parameter"), f.get("risk"), f.get("severity"), f.get("value")))

    # Insert events
    for e in events:
        cur.execute("""
            INSERT INTO events (domain, change, severity, created_at)
            VALUES (?, ?, ?, ?)
        """, (domain, e.get("change"), e.get("severity"), e.get("time")))

    # Insert actions
    for a in actions:
        cur.execute("""
            INSERT INTO actions (domain, issue, risk, action, status)
            VALUES (?, ?, ?, ?, ?)
        """, (domain, a.get("issue"), a.get("risk"), a.get("action"), a.get("status")))

    conn.commit()
    conn.close()

def enqueue_scan_job(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("""
        INSERT INTO jobs (domain, status, created_at)
        VALUES (?, ?, ?)
    """, (domain, "queued", now))
    job_id = cur.lastrowid
    conn.commit()
    conn.close()
    return job_id

def process_job_simple(job_id: int):
    # Synchronous processor for now
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT domain, status FROM jobs WHERE id=?", (job_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"error": "Job not found"}
    domain, status = row

    started_at = datetime.utcnow().isoformat()
    cur.execute("UPDATE jobs SET status=?, started_at=? WHERE id=?", ("running", started_at, job_id))
    conn.commit()

    try:
        result = collect_domain_data(domain)
        save_scan_results(
            domain,
            result["trust_score"],
            result["verdict"],
            result["severity"],
            result["findings"],
            result["events"],
            result["actions"]
        )
        finished_at = datetime.utcnow().isoformat()
        cur.execute("UPDATE jobs SET status=?, finished_at=? WHERE id=?", ("done", finished_at, job_id))
        conn.commit()
        conn.close()
        return {"status": "done", "domain": domain}
    except Exception as e:
        finished_at = datetime.utcnow().isoformat()
        cur.execute("UPDATE jobs SET status=?, finished_at=?, error=? WHERE id=?", ("error", finished_at, str(e), job_id))
        conn.commit()
        conn.close()
        return {"status": "error", "domain": domain, "error": str(e)}

def job_status(job_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, domain, status, created_at, started_at, finished_at, error FROM jobs WHERE id=?", (job_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {"error": "Job not found"}
    keys = ["id", "domain", "status", "created_at", "started_at", "finished_at", "error"]
    return dict(zip(keys, row))
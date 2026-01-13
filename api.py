# api.py
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime
import sqlite3, os

import auth
import db_helpers

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = FastAPI()

# ------------------------------
# Helpers
# ------------------------------
def get_conn():
    return sqlite3.connect(os.path.join(BASE_DIR, "webscan.db"))

# ------------------------------
# Auth pages (static)
# ------------------------------
@app.get("/")
def root():
    return RedirectResponse(url="/static/dashboard.html")

@app.get("/auth")
def auth_page():
    return RedirectResponse(url="/static/auth.html")

# ------------------------------
# Domain registration & listing
# ------------------------------
@app.post("/register-domain")
def register_domain(domain: str, username: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return {"error": "User not found"}
    user_id = user_row[0]

    cur.execute("SELECT id FROM domains WHERE user_id=? AND domain=?", (user_id, domain))
    if cur.fetchone():
        conn.close()
        return {"message": "Domain already registered"}

    cur.execute(
        "INSERT INTO domains (user_id, domain, created_at) VALUES (?, ?, ?)",
        (user_id, domain, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    # Enqueue and process a first scan synchronously (v0)
    job_id = db_helpers.enqueue_scan_job(domain)
    db_helpers.process_job_simple(job_id)

    return {"message": f"Domain {domain} registered and initial scan completed", "job_id": job_id}

@app.get("/user-domains")
def get_user_domains(username: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return []
    user_id = user_row[0]

    cur.execute("SELECT domain FROM domains WHERE user_id=?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [row[0] for row in rows]

# ------------------------------
# Scan orchestration
# ------------------------------
@app.post("/scan")
def scan(domain: str):
    job_id = db_helpers.enqueue_scan_job(domain)
    # For now, process immediately (synchronous v0)
    db_helpers.process_job_simple(job_id)
    return {"job_id": job_id, "status": db_helpers.job_status(job_id)}

@app.get("/scan/{job_id}")
def scan_status(job_id: int):
    return db_helpers.job_status(job_id)

# ------------------------------
# Intelligence APIs
# ------------------------------
@app.get("/overview/{domain}")
def overview(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT trust_score, verdict, severity, created_at
        FROM runs
        WHERE domain=?
        ORDER BY created_at DESC
        LIMIT 1
    """, (domain,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {
            "domain": domain,
            "trust_score": 0,
            "verdict": "No Data",
            "severity": "low",
            "last_scan": None
        }
    return {
        "domain": domain,
        "trust_score": row[0],
        "verdict": row[1],
        "severity": row[2],
        "last_scan": row[3]
    }

@app.get("/risks/{domain}")
def risks(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT MAX(id) FROM runs WHERE domain=?", (domain,))
    run_row = cur.fetchone()
    run_id = run_row[0] if run_row else None
    if not run_id:
        conn.close()
        return []
    cur.execute("""
        SELECT parameter, risk, severity, value
        FROM findings
        WHERE run_id=?
    """, (run_id,))
    rows = cur.fetchall()
    conn.close()
    return [{"parameter": p, "risk": r, "severity": s, "value": v} for p, r, s, v in rows]

@app.get("/timeline/{domain}")
def timeline(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT change, severity, created_at
        FROM events
        WHERE domain=?
        ORDER BY created_at DESC
    """, (domain,))
    rows = cur.fetchall()
    conn.close()
    return [{"change": c, "severity": s, "time": t} for c, s, t in rows]

@app.get("/actions/{domain}")
def actions(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT issue, risk, action, status
        FROM actions
        WHERE domain=?
    """, (domain,))
    rows = cur.fetchall()
    conn.close()
    return [{"issue": i, "risk": r, "action": a, "status": st} for i, r, a, st in rows]

# ------------------------------
# Static file serving
# ------------------------------
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")

# ------------------------------
# Include auth router
# ------------------------------
app.include_router(auth.router)
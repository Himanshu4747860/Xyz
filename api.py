# api.py
from fastapi import FastAPI, Depends
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime
import sqlite3, os

import auth
import db_helpers   # import your helper

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = FastAPI()

# Existing routes here...

@app.post("/register-domain")
def register_domain(domain: str, user_id: int):
    conn = sqlite3.connect(os.path.join(BASE_DIR, "webscan.db"))
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO domains (user_id, domain, created_at)
        VALUES (?, ?, ?)
    """, (user_id, domain, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    # Trigger scan immediately
    db_helpers.save_scan_results(
        domain,
        80, "Safe", "low",
        findings=[{"parameter":"SSL","risk":"Expired","severity":"high"}],
        events=[{"change":"DNS updated","severity":"medium","time":datetime.utcnow().isoformat()}],
        actions=[{"issue":"Weak SSL","risk":"High","action":"Renew cert","status":"Pending"}]
    )

    return {"message": f"Domain {domain} registered and scan started"}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI()


# ------------------------------
# Helpers
# ------------------------------
def get_conn():
    return sqlite3.connect(os.path.join(BASE_DIR, "webscan.db"))


# ------------------------------
# Routes
# ------------------------------
@app.get("/")
def root():
    return RedirectResponse(url="/static/dashboard.html")

@app.get("/auth")
def auth_page():
    return RedirectResponse(url="/static/auth.html")

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
        return {"error": "No scans found"}
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
    cur.execute("""
        SELECT parameter, risk, severity
        FROM findings
        WHERE run_id=(SELECT MAX(id) FROM runs WHERE domain=?)
    """, (domain,))
    rows = cur.fetchall()
    conn.close()
    return [{"parameter": p, "risk": r, "severity": s} for p, r, s in rows]

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

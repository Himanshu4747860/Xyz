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
def register_domain(domain: str, username: str):
    conn = get_conn()
    cur = conn.cursor()
    # Get user_id from username
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return {"error": "User not found"}
    user_id = user_row[0]

    # Check if domain already exists for this user
    cur.execute("SELECT id FROM domains WHERE user_id=? AND domain=?", (user_id, domain))
    if cur.fetchone():
        conn.close()
        return {"message": "Domain already registered"}

    cur.execute("""
        INSERT INTO domains (user_id, domain, created_at)
        VALUES (?, ?, ?)
    """, (user_id, domain, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    # Trigger mock scan results for demonstration
    db_helpers.save_scan_results(
        domain,
        75, "Warning", "medium",
        findings=[
            {"parameter":"SSL","risk":"Expiring in 5 days","severity":"medium"},
            {"parameter":"Headers","risk":"Missing CSP","severity":"high"}
        ],
        events=[
            {"change":"Domain registered","severity":"low","time":datetime.utcnow().isoformat()},
            {"change":"Initial scan completed","severity":"low","time":datetime.utcnow().isoformat()}
        ],
        actions=[
            {"issue":"Missing CSP Header","risk":"High","action":"Add Content-Security-Policy","status":"Open"},
            {"issue":"SSL Expiry","risk":"Medium","action":"Renew SSL Certificate","status":"Pending"}
        ]
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

@app.get("/user-domains")
def get_user_domains(username: str):
    conn = get_conn()
    cur = conn.cursor()
    # First get user_id
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

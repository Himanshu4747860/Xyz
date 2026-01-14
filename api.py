import os
import sqlite3
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
import db_helpers
import auth
import models

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# Include auth router
app.include_router(auth.router)

def get_conn():
    return sqlite3.connect(os.path.join(BASE_DIR, "webscan.db"))

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

@app.post("/register-domain")
def register_domain(domain: str, username: str):
    try:
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

        cur.execute("""
            INSERT INTO domains (user_id, domain, created_at)
            VALUES (?, ?, ?)
        """, (user_id, domain, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        # Trigger mock scan results
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
    except Exception as e:
        return {"error": str(e)}

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
    cur.execute("SELECT id FROM runs WHERE domain=? ORDER BY created_at DESC LIMIT 1", (domain,))
    run_row = cur.fetchone()
    if not run_row:
        conn.close()
        return []
    run_id = run_row[0]
    cur.execute("SELECT parameter, risk, severity FROM findings WHERE run_id=?", (run_id,))
    rows = cur.fetchall()
    conn.close()
    return [{"parameter": r[0], "risk": r[1], "severity": r[2]} for r in rows]

@app.get("/actions/{domain}")
def actions(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT issue, risk, action, status FROM actions WHERE domain=?", (domain,))
    rows = cur.fetchall()
    conn.close()
    return [{"issue": r[0], "risk": r[1], "action": r[2], "status": r[3]} for r in rows]

@app.get("/timeline/{domain}")
def timeline(domain: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT change, severity, created_at FROM events WHERE domain=? ORDER BY created_at DESC", (domain,))
    rows = cur.fetchall()
    conn.close()
    return [{"change": r[0], "severity": r[1], "time": r[2]} for r in rows]

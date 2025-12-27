# db_helpers.py
from datetime import datetime
import sqlite3, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_conn():
    return sqlite3.connect(os.path.join(BASE_DIR, "webscan.db"))

def save_scan_results(domain, trust_score, verdict, severity, findings, events, actions):
    conn = get_conn()
    cur = conn.cursor()

    # Insert run
    cur.execute("""
        INSERT INTO runs (domain, trust_score, verdict, severity, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (domain, trust_score, verdict, severity, datetime.utcnow().isoformat()))
    run_id = cur.lastrowid

    # Insert findings
    for f in findings:
        cur.execute("""
            INSERT INTO findings (run_id, parameter, risk, severity)
            VALUES (?, ?, ?, ?)
        """, (run_id, f["parameter"], f["risk"], f["severity"]))

    # Insert events
    for e in events:
        cur.execute("""
            INSERT INTO events (domain, change, severity, created_at)
            VALUES (?, ?, ?, ?)
        """, (domain, e["change"], e["severity"], e["time"]))

    # Insert actions
    for a in actions:
        cur.execute("""
            INSERT INTO actions (domain, issue, risk, action, status)
            VALUES (?, ?, ?, ?, ?)
        """, (domain, a["issue"], a["risk"], a["action"], a["status"]))

    conn.commit()
    conn.close()

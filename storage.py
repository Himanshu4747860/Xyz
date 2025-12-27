import json
from pathlib import Path
from typing import Optional
from .models import CheckResult
from .models import now_iso
# webscan/storage.py
import os, sqlite3
try:
    import psycopg2
except ImportError:
    psycopg2 = None
# --- Artifact functions ---
def ensure_url_folder(base: str, domain: str) -> Path:
    path = Path(base) / domain
    path.mkdir(parents=True, exist_ok=True)
    (path / "artifacts").mkdir(exist_ok=True)
    (path / "logs").mkdir(exist_ok=True)
    return path

def write_artifact(base: str, domain: str, kind: str, filename: str, content: bytes) -> Path:
    folder = ensure_url_folder(base, domain) / "artifacts"
    path = folder / filename
    path.write_bytes(content)
    return path

def write_text_artifact(base: str, domain: str, kind: str, filename: str, text: str) -> Path:
    return write_artifact(base, domain, kind, filename, text.encode("utf-8"))

def write_json(base: str, domain: str, filename: str, obj: dict) -> Path:
    folder = ensure_url_folder(base, domain)
    path = folder / filename
    path.write_text(json.dumps(obj, indent=2))
    return path

# --- Database functions ---

def connect(db_url):
    if (db_url.startswith("postgres://") or db_url.startswith("postgresql://")) and psycopg2:
        return psycopg2.connect(db_url), "pg"
    else:
        os.makedirs(os.path.dirname(db_url), exist_ok=True)
        return sqlite3.connect(db_url), "sqlite"

def init_schema(conn, kind="sqlite"):
    cur = conn.cursor()

    # Runs table (overall scan results)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            trust_score INTEGER,
            verdict TEXT,
            severity TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Findings table (parameter-level risks)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings(
            run_id INTEGER,
            parameter TEXT,
            risk REAL,
            category TEXT,
            severity TEXT
        )
    """)

    # Events table (timeline of changes between scans)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            domain TEXT,
            change TEXT,
            severity TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Actions table (recommended fixes for risks)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS actions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            issue TEXT,
            risk TEXT,
            action TEXT,
            status TEXT DEFAULT 'open'
        )
    """)

    conn.commit()


def save_run(conn, domain, summary, parameters):
    cur = conn.cursor()

    # Insert into runs table
    cur.execute("""
        INSERT INTO runs(domain, trust_score, verdict, severity)
        VALUES(?,?,?,?)
    """, (domain, summary.get("trust_score"), summary.get("verdict"), summary.get("severity")))
    run_id = cur.lastrowid   # 🔹 capture the auto-incremented run ID

    # Insert findings
    for param, risk in parameters.items():
        cur.execute("""
            INSERT INTO findings(run_id, parameter, risk, category, severity)
            VALUES(?,?,?,?,?)
        """, (run_id, param, risk, summary.get("category", "general"), summary.get("severity")))

    conn.commit()
    return run_id   # 🔹 return run_id for later use

def ensure_url_folder(base: str, domain: str) -> Path:
    path = Path(base) / domain
    path.mkdir(parents=True, exist_ok=True)
    (path / "artifacts").mkdir(exist_ok=True)
    (path / "logs").mkdir(exist_ok=True)
    return path

def write_artifact(base: str, domain: str, kind: str, filename: str, content: bytes) -> Path:
    folder = ensure_url_folder(base, domain) / "artifacts"
    path = folder / filename
    path.write_bytes(content)
    return path

def write_text_artifact(base: str, domain: str, kind: str, filename: str, text: str) -> Path:
    return write_artifact(base, domain, kind, filename, text.encode("utf-8"))

def write_json(base: str, domain: str, filename: str, obj: dict) -> Path:
    folder = ensure_url_folder(base, domain)
    path = folder / filename
    path.write_text(json.dumps(obj, indent=2))
    return path

def detect_changes(conn, domain, parameters):
    cur = conn.cursor()
    cur.execute("SELECT parameter, risk FROM findings WHERE domain=? ORDER BY rowid DESC LIMIT 1", (domain,))
    prev = {row[0]: row[1] for row in cur.fetchall()}
    changes = []
    for param, risk in parameters.items():
        if param in prev and prev[param] != risk:
            changes.append((domain, f"{param} changed from {prev[param]} to {risk}", "MEDIUM"))
    return changes

def map_actions(findings):
    actions = []
    for f in findings:
        if f["risk"] != "SAFE":
            actions.append({
                "issue": f["issue"],
                "risk": f["risk"],
                "action": f"Investigate {f['issue']} risk",
                "status": "open"
            })
    return actions

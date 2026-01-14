import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "webscan.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    print("Creating tables...")
    
    # Users table (handled by SQLAlchemy usually, but ensuring here)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")
    
    # Domains table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )""")
    
    # Runs table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        trust_score INTEGER,
        verdict TEXT,
        severity TEXT,
        created_at TEXT NOT NULL
    )""")
    
    # Findings table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        parameter TEXT,
        risk TEXT,
        severity TEXT,
        FOREIGN KEY (run_id) REFERENCES runs (id)
    )""")
    
    # Events table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        change TEXT,
        severity TEXT,
        created_at TEXT NOT NULL
    )""")
    
    # Actions table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        issue TEXT,
        risk TEXT,
        action TEXT,
        status TEXT
    )""")
    
    conn.commit()
    conn.close()
    print("All tables created successfully.")

if __name__ == "__main__":
    init_db()

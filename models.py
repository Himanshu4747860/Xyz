# models.py
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from db import Base

# --- Existing dataclass for scan results ---
@dataclass
class CheckResult:
    category: str
    name: str
    status: str            # PASS/FAIL/WARN/INFO/ERROR
    value: Optional[str]
    details: Optional[str]

def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec='seconds') + "Z"

# --- Users ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    domains = relationship("Domain", back_populates="user")

# --- Domains ---
class Domain(Base):
    __tablename__ = "domains"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    created_at = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="domains")

    __table_args__ = (
        UniqueConstraint("user_id", "domain", name="uq_user_domain"),
        Index("ix_domain_domain", "domain"),
    )

# --- Runs (scan summary per domain) ---
class Run(Base):
    __tablename__ = "runs"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    trust_score = Column(Integer, nullable=False)
    verdict = Column(String, nullable=False)        # e.g., Safe/Warning/Critical
    severity = Column(String, nullable=False)       # e.g., low/medium/high
    created_at = Column(String, nullable=False)

# --- Findings (linked to run) ---
class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False)
    parameter = Column(String, nullable=False)      # e.g., Headers:CSP
    risk = Column(String, nullable=False)           # description
    severity = Column(String, nullable=False)       # low/medium/high
    value = Column(String, nullable=True)           # optional evidence/value

    __table_args__ = (
        Index("ix_findings_run_id", "run_id"),
    )

# --- Events (timeline per domain) ---
class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    change = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    created_at = Column(String, nullable=False)

# --- Actions (recommendations per domain) ---
class Action(Base):
    __tablename__ = "actions"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    issue = Column(String, nullable=False)
    risk = Column(String, nullable=False)
    action = Column(String, nullable=False)
    status = Column(String, nullable=False)         # Open/Pending/Resolved

# --- Jobs (scan orchestration) ---
class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    status = Column(String, nullable=False)         # queued/running/done/error
    created_at = Column(String, nullable=False)
    started_at = Column(String, nullable=True)
    finished_at = Column(String, nullable=True)
    error = Column(String, nullable=True)
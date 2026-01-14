from dataclasses import dataclass
from typing import Optional
from datetime import datetime

from sqlalchemy import Column, Integer, String
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


# --- New ORM model for authentication ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)  # ⚠️ plain text for now, will hash later

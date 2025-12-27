import whois
from datetime import datetime

def fetch_whois(domain: str):
    try:
        data = whois.whois(domain)
        return {
            "domain_name": str(data.domain_name) if data.domain_name else domain,
            "registrar": data.registrar,
            "creation_date": _to_iso(data.creation_date),
            "expiration_date": _to_iso(data.expiration_date),
            "name_servers": data.name_servers if data.name_servers else [],
            "statuses": data.status if data.status else [],
            "emails": data.emails if data.emails else [],
            "whois_server": data.whois_server,
            "raw": str(data.text) if hasattr(data, "text") else None
        }
    except Exception as e:
        return {"error": str(e)}

def _to_iso(dt):
    if dt is None:
        return None
    if isinstance(dt, list):
        dt = dt[0]
    if isinstance(dt, datetime):
        return dt.isoformat() + "Z"
    try:
        return datetime.fromisoformat(str(dt)).isoformat() + "Z"
    except Exception:
        return str(dt)

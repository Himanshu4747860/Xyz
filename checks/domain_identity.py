from datetime import datetime
from dateutil import parser
from ..models import CheckResult

def run(whois_data) -> list[CheckResult]:
    results = []

    # 1 Domain age
    age_days = None
    if whois_data.get("creation_date"):
        try:
            created = parser.isoparse(whois_data["creation_date"])
            age_days = (datetime.utcnow() - created.replace(tzinfo=None)).days
            status = "PASS" if age_days and age_days > 180 else "WARN"
            results.append(CheckResult("DOMAIN & IDENTITY", "Domain age", status, str(age_days), f"{age_days} days"))
        except Exception as e:
            results.append(CheckResult("DOMAIN & IDENTITY", "Domain age", "ERROR", None, str(e)))
    else:
        results.append(CheckResult("DOMAIN & IDENTITY", "Domain age", "INFO", None, "Missing creation_date"))

    # 2 Domain registration date
    results.append(CheckResult("DOMAIN & IDENTITY", "Domain registration date", "INFO", whois_data.get("creation_date"), None))

    # 3 Domain expiry date
    exp = whois_data.get("expiration_date")
    results.append(CheckResult("DOMAIN & IDENTITY", "Domain expiry date", "INFO", exp, None))
    try:
        if exp:
            days_left = (parser.isoparse(exp) - datetime.utcnow()).days
            status = "WARN" if days_left < 30 else "PASS"
            results.append(CheckResult("DOMAIN & IDENTITY", "Expiry days left", status, str(days_left), f"{days_left} days"))
    except Exception:
        pass

    # 4 Registrar name
    reg = whois_data.get("registrar")
    results.append(CheckResult("DOMAIN & IDENTITY", "Registrar name", "INFO", reg, None))

    # 5 Registrar reputation (stub)
    results.append(CheckResult("DOMAIN & IDENTITY", "Registrar reputation", "INFO", None, "Not implemented"))

    # 6 WHOIS privacy enabled (heuristic)
    privacy = False
    emails = whois_data.get("emails") or []
    privacy = any("privacy" in str(e).lower() or "protect" in str(e).lower() for e in emails)
    results.append(CheckResult("DOMAIN & IDENTITY", "WHOIS privacy enabled", "INFO", str(privacy), None))

    # 7-15 stubs
    for name in [
        "WHOIS email change", "WHOIS name change", "Nameserver count",
        "Nameserver change history", "DNSSEC enabled", "DNS TTL values",
        "Parked domain detection", "Suspicious registrar country", "IDN homograph risk"
    ]:
        results.append(CheckResult("DOMAIN & IDENTITY", name, "INFO", None, "Not implemented"))
    return results

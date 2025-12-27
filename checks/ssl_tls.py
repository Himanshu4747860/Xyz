from datetime import datetime
from dateutil import parser
from ..models import CheckResult

def run(cert_info: dict | None) -> list[CheckResult]:
    results = []
    if not cert_info:
        results.append(CheckResult("SSL / TLS", "HTTPS availability", "FAIL", None, "No certificate"))
        # Add stubs for remaining
        for name in [
            "Certificate issuer","Certificate chain validity","Certificate expiry days",
            "Self-signed cert detection","TLS version support","Weak cipher support",
            "OCSP stapling","Certificate transparency logs","HTTPS redirect enforced",
            "Mixed content detection","SAN mismatch","SSL handshake errors",
            "Expired intermediate cert","Cert pinning presence"
        ]:
            results.append(CheckResult("SSL / TLS", name, "INFO", None, "Not implemented"))
        return results

    results.append(CheckResult("SSL / TLS", "HTTPS availability", "PASS", "True", None))
    issuer = cert_info.get("issuer", {}).get("O")
    results.append(CheckResult("SSL / TLS", "Certificate issuer", "INFO", issuer, None))
    # 31 expiry days
    try:
        exp = parser.isoparse(cert_info["not_after"])
        days = (exp.replace(tzinfo=None) - datetime.utcnow()).days
        results.append(CheckResult("SSL / TLS", "Certificate expiry days", "WARN" if days < 30 else "PASS", str(days), f"{days} days"))
    except Exception as e:
        results.append(CheckResult("SSL / TLS", "Certificate expiry days", "ERROR", None, str(e)))

    # 39 SAN mismatch (basic)
    san = cert_info.get("san", [])
    results.append(CheckResult("SSL / TLS", "SAN entries count", "INFO", str(len(san)), None))

    # Stubs for the rest
    for name in [
        "Certificate chain validity","Self-signed cert detection","TLS version support","Weak cipher support",
        "OCSP stapling","Certificate transparency logs","HTTPS redirect enforced","Mixed content detection",
        "SSL handshake errors","Expired intermediate cert","Cert pinning presence"
    ]:
        results.append(CheckResult("SSL / TLS", name, "INFO", None, "Not implemented"))
    return results

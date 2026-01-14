import whois
import dns.resolver
from datetime import datetime
from models import CheckResult
from checks import ssl_tls, security_headers, domain_identity
from checks.ssl_tls import fetch_certificate

def collect_domain_data(domain: str):
    findings = []

    # WHOIS
    try:
        w = whois.whois(domain)
        whois_data = {
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "registrar": w.registrar,
            "emails": w.emails,
        }
        findings.extend(domain_identity.run(whois_data))
    except Exception as e:
        findings.append(CheckResult("DOMAIN & IDENTITY", "WHOIS lookup", "ERROR", None, str(e)))

    # SSL/TLS
    cert_info = fetch_certificate(domain)
    findings.extend(ssl_tls.run(cert_info))

    # DNS (fetch + analyze inline)
    try:
        a_records = [str(r) for r in dns.resolver.resolve(domain, "A")]
        findings.append(CheckResult("DNS", "A records", "PASS", ",".join(a_records), None))
    except Exception as e:
        findings.append(CheckResult("DNS", "A records", "ERROR", None, str(e)))

    try:
        mx_records = [str(r) for r in dns.resolver.resolve(domain, "MX")]
        findings.append(CheckResult("DNS", "MX records", "INFO", ",".join(mx_records), None))
    except Exception as e:
        findings.append(CheckResult("DNS", "MX records", "ERROR", None, str(e)))

    try:
        ns_records = [str(r) for r in dns.resolver.resolve(domain, "NS")]
        findings.append(CheckResult("DNS", "NS records", "INFO", ",".join(ns_records), None))
    except Exception as e:
        findings.append(CheckResult("DNS", "NS records", "ERROR", None, str(e)))

    # Security headers
    findings.extend(security_headers.run(domain))

    # --- scoring logic ---
    score = 100
    for f in findings:
        if f.status == "WARN":
            score -= 10
        elif f.status == "ERROR":
            score -= 5
        elif f.status == "FAIL":
            score -= 20

    verdict = "Safe" if score >= 85 else ("Warning" if score >= 65 else "Critical")
    severity = "low" if score >= 85 else ("medium" if score >= 65 else "high")

    return {
        "trust_score": max(0, min(100, score)),
        "verdict": verdict,
        "severity": severity,
        "findings": [f.__dict__ for f in findings],
        "events": [{"change": "Scan completed", "severity": "low", "time": datetime.utcnow().isoformat()}],
        "actions": []
    }
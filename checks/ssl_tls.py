import ssl, socket
from datetime import datetime
from dateutil import parser
from models import CheckResult

def fetch_certificate(domain: str) -> dict | None:
    """Fetch SSL certificate from a domain and return as dict."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
        return cert
    except Exception:
        return None

def run(cert_info: dict | None) -> list[CheckResult]:
    results = []
    if not cert_info:
        results.append(CheckResult("SSL / TLS", "HTTPS availability", "FAIL", None, "No certificate"))
        # Stub checks
        for name in [
            "Certificate issuer","Certificate chain validity","Certificate expiry days",
            "Self-signed cert detection","TLS version support","Weak cipher support",
            "OCSP stapling","Certificate transparency logs","HTTPS redirect enforced",
            "Mixed content detection","SAN mismatch","SSL handshake errors",
            "Expired intermediate cert","Cert pinning presence"
        ]:
            results.append(CheckResult("SSL / TLS", name, "INFO", None, "Not implemented"))
        return results

    # HTTPS available
    results.append(CheckResult("SSL / TLS", "HTTPS availability", "PASS", "True", None))

    # Issuer parsing
    issuer_name = None
    issuer = cert_info.get("issuer", [])
    if isinstance(issuer, (list, tuple)):
        for tup in issuer:
            for key, value in tup:
                if key.lower() in ["organizationname", "o"]:
                    issuer_name = value
    results.append(CheckResult("SSL / TLS", "Certificate issuer", "INFO", issuer_name, None))

    # Expiry days
    try:
        exp = parser.parse(cert_info["notAfter"])
        days = (exp.replace(tzinfo=None) - datetime.utcnow()).days
        status = "WARN" if days < 30 else "PASS"
        results.append(CheckResult("SSL / TLS", "Certificate expiry days", status, str(days), None))
    except Exception as e:
        results.append(CheckResult("SSL / TLS", "Certificate expiry days", "ERROR", None, str(e)))

    # SAN entries
    san = cert_info.get("subjectAltName", [])
    results.append(CheckResult("SSL / TLS", "SAN entries count", "INFO", str(len(san)), None))

    # Stub checks
    for name in [
        "Certificate chain validity","Self-signed cert detection","TLS version support","Weak cipher support",
        "OCSP stapling","Certificate transparency logs","HTTPS redirect enforced","Mixed content detection",
        "SSL handshake errors","Expired intermediate cert","Cert pinning presence"
    ]:
        results.append(CheckResult("SSL / TLS", name, "INFO", None, "Not implemented"))

    return results

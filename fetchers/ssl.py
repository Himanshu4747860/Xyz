import ssl
import socket
from datetime import datetime
from OpenSSL import crypto
from typing import Dict, Any

def fetch_certificate(hostname: str, port: int = 443):
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(True)
            pem = ssl.DER_cert_to_PEM_cert(der)
            return pem

def parse_cert_pem(pem: str) -> Dict[str, Any]:
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
    issuer = dict(cert.get_issuer().get_components())
    subject = dict(cert.get_subject().get_components())
    not_before = datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
    not_after = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
    san = []
    try:
        ext_count = cert.get_extension_count()
        for i in range(ext_count):
            ext = cert.get_extension(i)
            if ext.get_short_name().decode() == "subjectAltName":
                san = [x.strip() for x in ext.__str__().split(",")]
    except Exception:
        pass
    return {
        "issuer": {k.decode(): v.decode() for k, v in issuer.items()},
        "subject": {k.decode(): v.decode() for k, v in subject.items()},
        "not_before": not_before.isoformat() + "Z",
        "not_after": not_after.isoformat() + "Z",
        "san": san
    }

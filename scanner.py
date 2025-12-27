import json
from urllib.parse import urlparse
from .utils import normalize_url, extract_domain
from .fetchers.http import fetch_url
from .fetchers.dns import resolve_records
from .fetchers.ssl import fetch_certificate, parse_cert_pem
from .fetchers.whois import fetch_whois
from .fetchers.headers import extract_security_headers
from .fetchers.content import parse_html
from .fetchers.performance import measure_response
from .checks.domain_identity import run as domain_identity_run
from .checks.dns_network import run as dns_network_run
from .checks.ssl_tls import run as ssl_tls_run
from .checks.security_headers import run as security_headers_run
from .checks.basic_security import run as basic_security_run
from .checks.content_integrity import run as content_integrity_run
from .checks.ai_spam_signals import run as ai_spam_run
from .checks.seo_trust import run as seo_trust_run
from .checks.performance_availability import run as perf_avail_run
from .checks.behavior_change import run as behavior_change_run
from .checks.compliance_legal import run as compliance_legal_run

def scan_single(url: str, config: dict):
    url = normalize_url(url)
    domain = extract_domain(url)

    # Fetch HTTP response and HTML
    resp = fetch_url(url, config)
    status_code = None
    headers = {}
    html = None
    if hasattr(resp, "status_code"):
        status_code = resp.status_code
        headers = dict(resp.headers)
        html = resp.text if config.get("fetch_html", True) else None

    # DNS
    dns_data = resolve_records(domain)

    # CERT
    cert_info = None
    try:
        cert_pem = fetch_certificate(domain)
        cert_info = parse_cert_pem(cert_pem)
    except Exception:
        cert_info = None

    # WHOIS
    whois_data = fetch_whois(domain)

    # Security headers
    sec_headers = extract_security_headers(headers)

    # Parsed HTML
    parsed = parse_html(html or "")

    # Performance
    perf = measure_response(url, {"User-Agent": config.get("user_agent", "WebScanBot/1.0")}, timeout=config.get("timeout_seconds", 20))

    # Aggregate checks
    checks = []
    checks += domain_identity_run(whois_data)
    checks += dns_network_run(domain, dns_data)
    checks += ssl_tls_run(cert_info)
    checks += security_headers_run(sec_headers)
    checks += basic_security_run(url, html)
    checks += content_integrity_run(parsed)
    checks += ai_spam_run(parsed.get("text") or "")
    checks += seo_trust_run(parsed)
    checks += perf_avail_run(perf)
    checks += behavior_change_run()
    checks += compliance_legal_run(parsed, parsed.get("text") or "")

    artifacts = {
        "status_code": status_code,
        "headers": headers,
        "dns": dns_data,
        "cert": cert_info,
        "whois": whois_data,
        "html": html,
        "parsed": parsed,
        "perf": perf
    }
    return domain, checks, artifacts

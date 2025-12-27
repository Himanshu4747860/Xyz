# webscan/severity_mapping.py
SEVERITY_MAP = {
    "ssl_expired": "CRITICAL",
    "malware_detected": "CRITICAL",
    "phishing_pattern": "CRITICAL",
    "blacklist_hit": "CRITICAL",
    "ssl_expiry_days": "HIGH",
    "missing_csp_header": "HIGH",
    "dkim_absent": "HIGH",
    "spf_absent": "HIGH",
    "open_ports": "HIGH",
    "weak_cipher_suites": "MEDIUM",
    "robots_txt_sensitive": "MEDIUM",
    "missing_hsts_header": "MEDIUM",
    "favicon_hash_missing": "LOW",
    "minor_header_issue": "LOW",
}

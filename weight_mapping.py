# webscan/weight_mapping.py
WEIGHT_MAP = {
    "ssl_expired": 1.0,
    "malware_detected": 1.0,
    "phishing_pattern": 1.0,
    "blacklist_hit": 1.0,
    "ssl_expiry_days": 0.8,
    "missing_csp_header": 0.7,
    "dkim_absent": 0.7,
    "spf_absent": 0.7,
    "open_ports": 0.6,
    "weak_cipher_suites": 0.5,
    "robots_txt_sensitive": 0.4,
    "missing_hsts_header": 0.4,
    "favicon_hash_missing": 0.2,
    "minor_header_issue": 0.2,
}

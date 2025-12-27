# webscan/scoring.py
from webscan.severity_mapping import SEVERITY_MAP
from webscan.weight_mapping import WEIGHT_MAP

CATEGORY_WEIGHTS = {
    "Security": 0.30,
    "SEO & Content": 0.20,
    "Stability & Behavior": 0.20,
    "Identity & Domain": 0.15,
    "Compliance & Trust": 0.15,
}

CRITICAL_FLAGS = {"ssl_expired","malware_detected","phishing_pattern","blacklist_hit","domain_expired","gdpr_violation","ccpa_violation","hidden_spam_links","deceptive_redirects","site_unreachable","cookie_banner_missing"}

def normalize_piecewise(value, threshold):
    # risk = min(1, max(0, (threshold - value) / threshold))
    r = (threshold - value) / threshold
    return max(0.0, min(1.0, r))

def category_of(param):
    if param in {"ssl_expired","missing_csp_header","dkim_absent","spf_absent","open_ports","weak_cipher_suites","robots_txt_sensitive","missing_hsts_header","favicon_hash_missing","minor_header_issue"}:
        return "Security"
    if param in {"hidden_spam_links","deceptive_redirects","indexed_pages_drop","duplicate_meta_titles","missing_meta_description","poor_mobile_optimization","missing_alt_text","weak_keyword_density"}:
        return "SEO & Content"
    if param in {"site_unreachable","response_time_high","frequent_5xx_errors","response_time_medium","occasional_404_spikes","minor_js_errors","css_validation_issues"}:
        return "Stability & Behavior"
    if param in {"domain_expired","whois_privacy_disabled_sensitive","dns_misconfig","whois_privacy_disabled","registrar_lock_disabled","missing_org_info"}:
        return "Identity & Domain"
    if param in {"cookie_banner_missing","gdpr_violation","ccpa_violation","privacy_policy_missing","terms_missing","cookie_banner_nonfunctional","accessibility_statement_missing","weak_contact_page"}:
        return "Compliance & Trust"
    return "Security"

def assign_severity(trust_score, category_risks, critical_flags, trend_drop=0):
    # Handle empty category_risks gracefully
    max_category_risk = max(category_risks.values()) if category_risks else 0.0

    if trust_score < 50 or max_category_risk > 0.7 or trend_drop > 15:
        return "CRITICAL"
    elif trust_score < 70 or max_category_risk > 0.5:
        return "HIGH"
    elif trust_score < 85 or max_category_risk > 0.3:
        return "MEDIUM"
    else:
        return "LOW"

def compute_scores(parameter_risks):
    # parameter_risks: dict[param_name] = risk_value in [0,1]
    # Build category aggregates
    cat_scores = {}
    cat_weights = {}
    for p, r in parameter_risks.items():
        w = WEIGHT_MAP.get(p, 0.2)
        cat = category_of(p)
        cat_scores[cat] = cat_scores.get(cat, 0.0) + r * w
        cat_weights[cat] = cat_weights.get(cat, 0.0) + w

    category_risks = {c: (cat_scores[c] / cat_weights[c]) if cat_weights[c] > 0 else 0.0 for c in cat_scores}
    # Global risk and trust
    global_risk = sum(category_risks.get(c,0.0) * CATEGORY_WEIGHTS.get(c,0.0) for c in CATEGORY_WEIGHTS)
    trust_score = round(100 * (1 - global_risk))
    # Verdict
    verdict = "SAFE"
    if trust_score < 50: verdict = "UNSAFE"
    elif trust_score < 70: verdict = "AT_RISK"
    elif trust_score < 85: verdict = "SAFE_WITH_CAUTION"

    # Critical overrides
    critical_flags = [p for p in parameter_risks.keys() if p in CRITICAL_FLAGS and parameter_risks[p] > 0.0]
    if critical_flags:
        verdict = "UNSAFE"

    # Severity
    severity = assign_severity(trust_score, category_risks, bool(critical_flags))

    return {
        "trust_score": trust_score,
        "verdict": verdict,
        "category_risks": category_risks,
        "severity": severity,
        "critical_flags": critical_flags,
    }

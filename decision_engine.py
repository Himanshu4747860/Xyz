import sqlite3
from typing import List, Dict, Any, Tuple

def compute_decision_score(params: List[Tuple[str, float, float]]) -> float:
    """
    params: list of (name, weight, risk_value), risk_value in [0,1]
    returns: weighted normalized score in [0,1]
    """
    total_w = sum(w for _, w, _ in params)
    if total_w == 0:
        return 0.0
    return sum(w * rv for _, w, rv in params) / total_w

def rules_for_domain(conn: sqlite3.Connection, domain: str) -> List[Dict[str, Any]]:
    """
    Generate decision alerts for a domain based on latest run + findings.
    """
    cur = conn.cursor()

    # Latest run
    cur.execute("""
        SELECT id, trust_score, verdict, severity, created_at
        FROM runs WHERE domain=? ORDER BY created_at DESC LIMIT 1
    """, (domain,))
    run = cur.fetchone()
    if not run:
        return []

    run_id = run[0]

    # Findings for latest run
    cur.execute("SELECT parameter, value, risk, severity FROM findings WHERE run_id=?", (run_id,))
    findings = {p: {"value": v, "risk": r, "severity": s} for p, v, r, s in cur.fetchall()}

    decisions: List[Dict[str, Any]] = []

    # Rule 1: Missing security headers
    missing = []
    for header in ["content_security_policy", "x_frame_options", "x_content_type_options", "referrer_policy"]:
        meta = findings.get(header)
        if meta and ((meta["value"] == 0) or (meta["risk"] and meta["risk"] >= 0.7)):
            missing.append(header)
    if missing:
        params = [(h, 0.25, 1.0) for h in missing]
        decisions.append({
            "category": "Security",
            "title": "Missing or weak security headers",
            "description": f"Issues with: {', '.join(missing)}",
            "decision_score": compute_decision_score(params),
            "confidence": 0.85,
            "impact_level": "High",
            "time_to_damage_days": 21,
            "recommendation": "Add CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
            "parameters": [{"name": n, "weight": w, "risk_value": rv} for n, w, rv in params]
        })

    # Rule 2: CLS risk
    cls = findings.get("cls_score")
    if cls and cls["value"] and cls["value"] > 0.1:
        params = [("cls_score", 0.6, min(1.0, cls["value"]/0.3))]
        decisions.append({
            "category": "SEO",
            "title": "Cumulative Layout Shift risk",
            "description": f"CLS {cls['value']:.3f} above threshold",
            "decision_score": compute_decision_score(params),
            "confidence": 0.75,
            "impact_level": "Medium",
            "time_to_damage_days": 14,
            "recommendation": "Reserve space for images/ads, preload fonts",
            "parameters": [{"name": n, "weight": w, "risk_value": rv} for n, w, rv in params]
        })

    # Rule 3: Performance slowdown
    perf_params = []
    lcp = findings.get("lcp")
    ttfb = findings.get("ttfb")
    if lcp and lcp["value"] and lcp["value"] > 2.5:
        perf_params.append(("lcp", 0.5, min(1.0, (lcp["value"]-2.5)/2.5)))
    if ttfb and ttfb["value"] and ttfb["value"] > 0.6:
        perf_params.append(("ttfb", 0.5, min(1.0, (ttfb["value"]-0.6)/0.6)))
    if perf_params:
        decisions.append({
            "category": "Performance",
            "title": "Page load slowdown",
            "description": "LCP/TTFB above thresholds",
            "decision_score": compute_decision_score(perf_params),
            "confidence": 0.9,
            "impact_level": "High",
            "time_to_damage_days": 7,
            "recommendation": "Optimize images, reduce blocking JS/CSS, enable caching",
            "parameters": [{"name": n, "weight": w, "risk_value": rv} for n, w, rv in perf_params]
        })

    return decisions

def insert_decisions(conn: sqlite3.Connection, domain: str, decisions: List[Dict[str, Any]]) -> int:
    """
    Insert generated decisions + parameters into DB.
    Returns number of decisions inserted.
    """
    cur = conn.cursor()
    count = 0

    for d in decisions:
        # Insert decision
        cur.execute("""
            INSERT INTO decisions (domain, category, title, description, decision_score,
                                   confidence, impact_level, time_to_damage_days, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            d["category"],
            d["title"],
            d["description"],
            d["decision_score"],
            d["confidence"],
            d["impact_level"],
            d["time_to_damage_days"],
            d["recommendation"]
        ))
        decision_id = cur.lastrowid

        # Insert parameters linked to this decision
        for p in d.get("parameters", []):
            cur.execute("""
                INSERT INTO parameters (decision_id, name, weight, risk_value)
                VALUES (?, ?, ?, ?)
            """, (decision_id, p["name"], p["weight"], p["risk_value"]))

        count += 1

    conn.commit()
    return count


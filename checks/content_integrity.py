import hashlib
from models import CheckResult

def run(parsed: dict) -> list[CheckResult]:
    results = []
    text = parsed.get("text") or ""
    html_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    # 65 Homepage content hash
    results.append(CheckResult("CONTENT INTEGRITY", "Homepage content hash", "INFO", html_hash, None))

    # 66 Sudden content size change (stub; requires history)
    results.append(CheckResult("CONTENT INTEGRITY", "Sudden content size change", "INFO", None, "Not implemented"))

    # 67 Unauthorized JS injection (heuristic: many external scripts)
    scripts = parsed.get("scripts") or []
    ext_scripts = [s for s in scripts if s and s.startswith("http")]
    inj = len(ext_scripts) > 10
    results.append(CheckResult("CONTENT INTEGRITY", "Unauthorized JS injection", "WARN" if inj else "PASS", str(inj), f"External scripts: {len(ext_scripts)}"))

    # 68 Suspicious iframe inclusion
    ifr = parsed.get("iframes") or []
    suspicious_ifr = any("ad" in (src or "").lower() for src in ifr)
    results.append(CheckResult("CONTENT INTEGRITY", "Suspicious iframe inclusion", "WARN" if suspicious_ifr else "PASS", str(suspicious_ifr), None))

    # 69 External script reputation (stub)
    results.append(CheckResult("CONTENT INTEGRITY", "External script reputation", "INFO", None, "Not implemented"))

    # 70 Hidden text detection (stub)
    results.append(CheckResult("CONTENT INTEGRITY", "Hidden text detection", "INFO", None, "Not implemented"))

    # 71 Hidden links detection (stub)
    results.append(CheckResult("CONTENT INTEGRITY", "Hidden links detection", "INFO", None, "Not implemented"))

    # 72 Spam keyword density (basic)
    spam_terms = ["free", "win", "credit", "loan", "viagra", "casino"]
    found = sum(text.lower().count(term) for term in spam_terms)
    results.append(CheckResult("CONTENT INTEGRITY", "Spam keyword density", "INFO", str(found), f"Matches: {found}"))

    # 73-76 stubs
    for name in ["Cloaking signals","Doorway page patterns","Adult/malware keyword leak","Copyright text changes"]:
        results.append(CheckResult("CONTENT INTEGRITY", name, "INFO", None, "Not implemented"))
    return results

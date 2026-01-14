from models import CheckResult

def run(parsed: dict, text: str) -> list[CheckResult]:
    results = []
    links = parsed.get("links") or []
    lower_text = text.lower()

    # 113 Privacy policy presence
    has_privacy = any("privacy" in (l or "").lower() for l in links) or ("privacy policy" in lower_text)
    results.append(CheckResult("COMPLIANCE & LEGAL", "Privacy policy presence", "PASS" if has_privacy else "WARN", str(has_privacy), None))

    # 114 Terms of service presence
    has_terms = any("terms" in (l or "").lower() for l in links) or ("terms of service" in lower_text)
    results.append(CheckResult("COMPLIANCE & LEGAL", "Terms of service presence", "PASS" if has_terms else "WARN", str(has_terms), None))

    # 115 Cookie consent banner (stub; needs screenshot/JS eval)
    results.append(CheckResult("COMPLIANCE & LEGAL", "Cookie consent banner", "INFO", None, "Not implemented"))

    # 116 GDPR signals (stub)
    results.append(CheckResult("COMPLIANCE & LEGAL", "GDPR signals", "INFO", None, "Not implemented"))

    # 117 Contact information validity (heuristic)
    has_contact = any("contact" in (l or "").lower() for l in links) or ("contact us" in lower_text)
    results.append(CheckResult("COMPLIANCE & LEGAL", "Contact information validity", "INFO", str(has_contact), "Heuristic"))

    # 118 Business address consistency (stub)
    results.append(CheckResult("COMPLIANCE & LEGAL", "Business address consistency", "INFO", None, "Not implemented"))

    # 119 Abuse email existence (stub)
    results.append(CheckResult("COMPLIANCE & LEGAL", "Abuse email existence", "INFO", None, "Not implemented"))

    # 120 DMCA takedown signals (stub)
    results.append(CheckResult("COMPLIANCE & LEGAL", "DMCA takedown signals", "INFO", None, "Not implemented"))
    return results

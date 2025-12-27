from ..models import CheckResult

def run(parsed: dict) -> list[CheckResult]:
    results = []
    title = parsed.get("title")
    desc = parsed.get("meta_description")
    canonical = parsed.get("canonical")
    text = parsed.get("text") or ""

    # 85 Meta title change frequency (stub requires history)
    results.append(CheckResult("SEO & SEARCH TRUST", "Meta title change frequency", "INFO", None, "Not implemented"))

    # 86 Meta description spam (heuristic)
    spammy = desc and any(x in desc.lower() for x in ["free", "win", "cheap"])
    results.append(CheckResult("SEO & SEARCH TRUST", "Meta description spam", "WARN" if spammy else "PASS", str(bool(spammy)), None))

    # 87 Canonical tag misuse (basic)
    misuse = canonical and not canonical.startswith("http")
    results.append(CheckResult("SEO & SEARCH TRUST", "Canonical tag misuse", "WARN" if misuse else "PASS", canonical, None))

    # 88 Noindex tag presence
    noindex = "<meta name=\"robots\" content=\"noindex\"" in text.lower()
    results.append(CheckResult("SEO & SEARCH TRUST", "Noindex tag presence", "INFO", str(noindex), None))

    # 89 Robots.txt disallow change (stub)
    results.append(CheckResult("SEO & SEARCH TRUST", "Robots.txt disallow change", "INFO", None, "Not implemented"))

    # 90 Sitemap availability (stub fetch)
    results.append(CheckResult("SEO & SEARCH TRUST", "Sitemap availability", "INFO", None, "Not implemented"))

    # 91 Sitemap freshness (stub)
    results.append(CheckResult("SEO & SEARCH TRUST", "Sitemap freshness", "INFO", None, "Not implemented"))

    # 92 Schema markup validity (stub)
    results.append(CheckResult("SEO & SEARCH TRUST", "Schema markup validity", "INFO", None, "Not implemented"))

    # 93 Structured data spam (stub)
    results.append(CheckResult("SEO & SEARCH TRUST", "Structured data spam", "INFO", None, "Not implemented"))

    # 94 Keyword stuffing (heuristic)
    kws = ["buy", "cheap", "best", "discount"]
    count = sum(text.lower().count(k) for k in kws)
    status = "WARN" if count > 50 else "PASS"
    results.append(CheckResult("SEO & SEARCH TRUST", "Keyword stuffing", status, str(count), None))

    # 95 Thin content pages (heuristic length)
    status = "WARN" if len(text) < 300 else "PASS"
    results.append(CheckResult("SEO & SEARCH TRUST", "Thin content pages", status, str(len(text)), "Characters"))

    # 96 Internal link imbalance (stub)
    results.append(CheckResult("SEO & SEARCH TRUST", "Internal link imbalance", "INFO", None, "Not implemented"))
    return results

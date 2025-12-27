from bs4 import BeautifulSoup
from ..models import CheckResult

def run(url: str, html: str | None) -> list[CheckResult]:
    results = []
    soup = BeautifulSoup(html or "", "html.parser")
    # 55 Directory listing enabled (heuristic on title)
    title = soup.title.string.lower() if soup.title and soup.title.string else ""
    dir_listing = "index of /" in title
    results.append(CheckResult("BASIC SECURITY POSTURE", "Directory listing enabled", "WARN" if dir_listing else "PASS", str(dir_listing), None))

    # 56 Admin panel exposed (basic heuristic)
    admin_paths = ["/admin", "/administrator", "/wp-admin", "/login"]
    exposed = any(p in (html or "").lower() for p in ["wp-admin", "administrator"])
    results.append(CheckResult("BASIC SECURITY POSTURE", "Admin panel exposed", "WARN" if exposed else "PASS", str(exposed), "Heuristic"))

    # 57 Common backup files exposed (stub)
    results.append(CheckResult("BASIC SECURITY POSTURE", "Common backup files exposed", "INFO", None, "Not implemented"))

    # 58 .env file accessible (stub)
    results.append(CheckResult("BASIC SECURITY POSTURE", ".env file accessible", "INFO", None, "Not implemented"))

    # 59 robots.txt sensitive paths (stub)
    results.append(CheckResult("BASIC SECURITY POSTURE", "robots.txt sensitive paths", "INFO", None, "Not implemented"))

    # 60 WAF detected (stub)
    results.append(CheckResult("BASIC SECURITY POSTURE", "WAF detected", "INFO", None, "Not implemented"))

    # 61 Rate limiting detected (stub)
    results.append(CheckResult("BASIC SECURITY POSTURE", "Rate limiting detected", "INFO", None, "Not implemented"))

    # 62 CAPTCHA presence (stub)
    results.append(CheckResult("BASIC SECURITY POSTURE", "CAPTCHA presence", "INFO", None, "Not implemented"))

    # 63 CMS detection (basic heuristic)
    cms = "wordpress" if "wp-content" in (html or "").lower() else None
    results.append(CheckResult("BASIC SECURITY POSTURE", "CMS detection", "INFO", cms, None))

    # 64 CMS version exposure (stub)
    results.append(CheckResult("BASIC SECURITY POSTURE", "CMS version exposure", "INFO", None, "Not implemented"))
    return results

from models import CheckResult

def run(perf: dict) -> list[CheckResult]:
    results = []
    ms = perf.get("ms")
    code = perf.get("status_code")
    redirects = perf.get("redirects", 0)

    # 97 HTTP response code history (stub)
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "HTTP response code history", "INFO", None, "Not implemented"))

    # 98 Redirect loops
    loop = redirects > 5
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "Redirect loops", "WARN" if loop else "PASS", str(redirects), None))

    # 99 Average response time (single sample)
    status = "WARN" if ms and ms > 2000 else "PASS"
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "Average response time", status, str(ms), "ms"))

    # 100 Sudden latency spike (stub)
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "Sudden latency spike", "INFO", None, "Not implemented"))

    # 101 CDN cache status (stub)
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "CDN cache status", "INFO", None, "Not implemented"))

    # 102 Server timeout errors
    timeout_err = perf.get("error") and "timeout" in perf["error"].lower()
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "Server timeout errors", "WARN" if timeout_err else "PASS", str(bool(timeout_err)), None))

    # 103 5xx error frequency (single sample)
    is5xx = code and int(code) >= 500
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "5xx error frequency", "WARN" if is5xx else "PASS", str(code), None))

    # 104 Geo-availability consistency (stub)
    results.append(CheckResult("PERFORMANCE & AVAILABILITY", "Geo-availability consistency", "INFO", None, "Not implemented"))
    return results

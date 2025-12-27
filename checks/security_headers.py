from ..models import CheckResult

def run(sec_headers: dict) -> list[CheckResult]:
    results = []

    # 43 CSP
    csp = sec_headers.get("Content-Security-Policy")
    results.append(CheckResult("SECURITY HEADERS", "Content-Security-Policy", "PASS" if csp else "WARN", csp, None))

    # 44 CSP unsafe-inline usage
    unsafe = csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp)
    results.append(CheckResult("SECURITY HEADERS", "CSP unsafe-inline usage", "WARN" if unsafe else "PASS", str(bool(unsafe)), None))

    # 45 HSTS enabled
    hsts = sec_headers.get("Strict-Transport-Security")
    results.append(CheckResult("SECURITY HEADERS", "HSTS enabled", "PASS" if hsts else "WARN", hsts, None))

    # 46 HSTS max-age
    max_age = None
    if hsts and "max-age=" in hsts:
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0])
        except Exception:
            pass
    results.append(CheckResult("SECURITY HEADERS", "HSTS max-age", "INFO", str(max_age) if max_age is not None else None, None))

    # 47 X-Frame-Options
    xfo = sec_headers.get("X-Frame-Options")
    results.append(CheckResult("SECURITY HEADERS", "X-Frame-Options", "PASS" if xfo else "WARN", xfo, None))

    # 48 X-Content-Type-Options
    xcto = sec_headers.get("X-Content-Type-Options")
    results.append(CheckResult("SECURITY HEADERS", "X-Content-Type-Options", "PASS" if xcto else "WARN", xcto, None))

    # 49 Referrer-Policy
    rp = sec_headers.get("Referrer-Policy")
    results.append(CheckResult("SECURITY HEADERS", "Referrer-Policy", "PASS" if rp else "WARN", rp, None))

    # 50 Permissions-Policy
    pp = sec_headers.get("Permissions-Policy")
    results.append(CheckResult("SECURITY HEADERS", "Permissions-Policy", "INFO", pp, None))

    # 51 Expect-CT
    ect = sec_headers.get("Expect-CT")
    results.append(CheckResult("SECURITY HEADERS", "Expect-CT", "INFO", ect, None))

    # 52-54 COOP/COEP/CORP
    coop = sec_headers.get("Cross-Origin-Opener-Policy")
    coep = sec_headers.get("Cross-Origin-Embedder-Policy")
    corp = sec_headers.get("Cross-Origin-Resource-Policy")
    results.append(CheckResult("SECURITY HEADERS", "Cross-Origin-Opener-Policy", "INFO", coop, None))
    results.append(CheckResult("SECURITY HEADERS", "Cross-Origin-Embedder-Policy", "INFO", coep, None))
    results.append(CheckResult("SECURITY HEADERS", "Cross-Origin-Resource-Policy", "INFO", corp, None))
    return results

from ..models import CheckResult

def run(domain: str, dns_data: dict) -> list[CheckResult]:
    results = []

    # 16 A record count
    a_count = len(dns_data.get("A", []))
    results.append(CheckResult("DNS & NETWORK", "A record count", "INFO", str(a_count), None))

    # 17 AAAA record presence
    has_aaaa = len(dns_data.get("AAAA", [])) > 0
    results.append(CheckResult("DNS & NETWORK", "AAAA record presence", "INFO", str(has_aaaa), None))

    # 18 MX record existence
    has_mx = len(dns_data.get("MX", [])) > 0
    results.append(CheckResult("DNS & NETWORK", "MX record existence", "INFO", str(has_mx), None))

    # 19 SPF record
    spf = any("v=spf1" in txt.lower() for txt in dns_data.get("TXT", []))
    results.append(CheckResult("DNS & NETWORK", "SPF record", "INFO", str(spf), None))

    # 20 DKIM record (basic heuristic on common selector, stub)
    dkim = any("dkim" in txt.lower() for txt in dns_data.get("TXT", []))
    results.append(CheckResult("DNS & NETWORK", "DKIM record", "INFO", str(dkim), "Selector-based check not implemented"))

    # 21 DMARC policy
    dmarc_present = False
    # In V0, we don't query _dmarc subdomain to avoid complexity; mark stub
    results.append(CheckResult("DNS & NETWORK", "DMARC policy", "INFO", str(dmarc_present), "Not implemented"))

    # 22 CDN usage (stub)
    results.append(CheckResult("DNS & NETWORK", "CDN usage", "INFO", None, "Not implemented"))

    # 23 ASN reputation (stub)
    results.append(CheckResult("DNS & NETWORK", "ASN reputation", "INFO", None, "Not implemented"))

    # 24 IP geolocation change (stub)
    results.append(CheckResult("DNS & NETWORK", "IP geolocation change", "INFO", None, "Not implemented"))

    # 25 IP blacklist presence (stub)
    results.append(CheckResult("DNS & NETWORK", "IP blacklist presence", "INFO", None, "Not implemented"))

    # 26 Reverse DNS validity (stub per IP)
    results.append(CheckResult("DNS & NETWORK", "Reverse DNS validity", "INFO", None, "Not implemented"))

    # 27 DNS misconfiguration (basic)
    misconfig = (a_count == 0 and len(dns_data.get("AAAA", [])) == 0)
    results.append(CheckResult("DNS & NETWORK", "DNS misconfiguration", "WARN" if misconfig else "PASS", str(misconfig), None))
    return results

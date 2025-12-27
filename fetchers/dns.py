import dns.resolver
import dns.dnssec
import dns.name
import dns.query
import dns.message

def resolve_records(domain: str):
    # configure=False prevents trying to open /etc/resolv.conf
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare DNS
    res.timeout = 5
    res.lifetime = 10

    data = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS"]:
        try:
            answers = res.resolve(domain, rtype)
            data[rtype] = [a.to_text() for a in answers]
        except Exception:
            data[rtype] = []
    return data

def check_reverse_dns(ip: str) -> bool:
    try:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = ["8.8.8.8", "1.1.1.1"]
        answers = res.resolve_address(ip)
        return len(answers) > 0
    except Exception:
        return False

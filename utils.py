import re
import tldextract
from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^https?://', url, re.I):
        url = 'https://' + url
    return url

def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    ext = tldextract.extract(host)
    return ".".join(filter(None, [ext.domain, ext.suffix])) if ext.suffix else host

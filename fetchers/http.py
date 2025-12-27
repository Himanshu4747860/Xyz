import requests
from requests.exceptions import RequestException
from typing import Dict, Any

def fetch_url(url: str, config: Dict[str, Any]):
    headers = {
        "User-Agent": config.get("user_agent", "WebScanBot/1.0")
    }
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=config.get("timeout_seconds", 20),
            allow_redirects=True
        )
        return resp
    except RequestException as e:
        return e

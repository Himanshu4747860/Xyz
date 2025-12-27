import time
import requests

def measure_response(url: str, headers: dict, timeout: int = 20):
    start = time.time()
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        elapsed = (time.time() - start) * 1000.0
        return {"ms": int(elapsed), "status_code": resp.status_code, "redirects": len(resp.history)}
    except Exception as e:
        elapsed = (time.time() - start) * 1000.0
        return {"ms": int(elapsed), "error": str(e)}

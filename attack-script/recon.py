"""Reconnaissance / port-scan style enumeration.

Rapidly probes many DISTINCT endpoints with scanner user-agents. Most return
404, producing high diff_srv_rate + rerror_rate in the sensor.

Signature -> model class: Probe
"""

import itertools
import random
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from config import ATTACKER_IPS, RECON_WORKERS, REQUEST_TIMEOUT, TARGET_URL

SCANNER_UAS = [
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "masscan/1.3",
    "Go-http-client/1.1",
    "gobuster/3.6",
]

# Enumeration wordlist - generic discovery paths (kept out of the auth/RCE
# vocab so this reads as scanning, not credential abuse or exploitation).
WORDLIST = [
    "/robots.txt", "/sitemap.xml", "/api", "/api/v1", "/api/v2", "/status",
    "/health", "/metrics", "/static", "/assets", "/images", "/js", "/css",
    "/user", "/users", "/account", "/profile", "/search", "/upload",
    "/download", "/report", "/dashboard", "/settings", "/v1/info", "/version",
    "/api/v1/products", "/api/v1/orders", "/api/v1/items", "/graphql",
]


def _scan(path: str):
    try:
        headers = {
            "X-Forwarded-For": random.choice(ATTACKER_IPS),
            "X-Sim-Scenario": "recon",  # ground-truth tag (not a model feature)
            "User-Agent": random.choice(SCANNER_UAS),
        }
        requests.get(f"{TARGET_URL}{path}", headers=headers, timeout=REQUEST_TIMEOUT)
    except Exception:
        pass


def run(stop=None):
    """Loop until `stop` (a threading.Event) is set, or forever if None."""
    print(f"[recon] scanning {len(WORDLIST)} endpoints against {TARGET_URL}")
    counter = itertools.count(1)
    while not (stop and stop.is_set()):
        with ThreadPoolExecutor(max_workers=RECON_WORKERS) as ex:
            for path in random.sample(WORDLIST, len(WORDLIST)):
                # Append a random token so each request hits a distinct "service".
                ex.submit(_scan, f"{path}/{random.randint(1000, 9999)}")
        print(f"[recon] completed scan sweep #{next(counter)}")
        time.sleep(0.5)


if __name__ == "__main__":
    run()

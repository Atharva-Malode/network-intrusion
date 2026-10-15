"""Normal traffic: legitimate browsing of the netflix-clone via the proxy.

Signature -> model class: Normal
"""

import random
import time

import requests

from config import (
    NORMAL_IPS,
    NORMAL_MAX_DELAY,
    NORMAL_MIN_DELAY,
    REQUEST_TIMEOUT,
    TARGET_URL,
)

PATHS = ["/", "/browse", "/movies", "/latest", "/my-list"]
BROWSER_UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def run(stop=None):
    """Loop until `stop` (a threading.Event) is set, or forever if None."""
    print(f"[normal] legitimate browsing against {TARGET_URL}")
    while not (stop and stop.is_set()):
        try:
            headers = {
                "X-Forwarded-For": random.choice(NORMAL_IPS),
                "X-Sim-Scenario": "normal",  # ground-truth tag (not a model feature)
                "User-Agent": random.choice(BROWSER_UAS),
            }
            path = random.choice(PATHS)
            requests.get(f"{TARGET_URL}{path}", headers=headers, timeout=REQUEST_TIMEOUT)
            print(f"[normal] GET {path}")
        except Exception as e:
            print(f"[normal] request failed: {e}")
        time.sleep(random.uniform(NORMAL_MIN_DELAY, NORMAL_MAX_DELAY))


if __name__ == "__main__":
    run()

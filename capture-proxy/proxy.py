"""
Capture proxy - the traffic sensor that replaces the Next.js middleware.

Sits in front of the netflix-clone demo site: browse to the proxy instead of the
site directly. For every request it:
  1. transparently forwards to the real site and streams the response back,
  2. computes an NSL-KDD 41-feature connection record (feature_extractor),
  3. fires the record to the backend /ingest endpoint (non-blocking),
where the pretrained model classifies the attack class.

Run:  python proxy.py    (uv run python proxy.py)
Then open http://localhost:8080  (instead of :3000).
"""

from __future__ import annotations

import asyncio
import socket
import sys

import aiohttp
from aiohttp import web

from config import (
    BACKEND_INGEST_URL,
    INGEST_TIMEOUT,
    LISTEN_HOST,
    LISTEN_PORT,
    TARGET_URL,
    TELEMETRY_BURST,
    TELEMETRY_MAX_RATE,
    UPSTREAM_TIMEOUT,
)
from feature_extractor import FeatureExtractor

# Hop-by-hop headers that must not be forwarded verbatim.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
    "content-encoding",
}

extractor = FeatureExtractor()

# Ground-truth tag set by attack-script (lab traffic generator) on every request.
# It is NOT a feature and never reaches the model: the backend uses it only to
# record labelled sensor data for calibration and to score the live confusion
# matrix. It is stripped before forwarding so the protected site never sees it.
SCENARIO_HEADER = "X-Sim-Scenario"


def _client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    peer = request.remote or "127.0.0.1"
    return peer


# Token bucket: refills at TELEMETRY_MAX_RATE/s up to TELEMETRY_BURST. Unlike a
# fixed minimum gap, a burst (a scanner firing 12 requests at once) is sampled
# instead of collapsing to one record, while a sustained flood is still capped.
_bucket = {"tokens": float(TELEMETRY_BURST), "at": 0.0}


def _take_token(now: float) -> bool:
    if TELEMETRY_MAX_RATE <= 0:
        return True
    _bucket["tokens"] = min(float(TELEMETRY_BURST),
                            _bucket["tokens"] + (now - _bucket["at"]) * TELEMETRY_MAX_RATE)
    _bucket["at"] = now
    if _bucket["tokens"] >= 1.0:
        _bucket["tokens"] -= 1.0
        return True
    return False


async def _send_telemetry(app: web.Application, features: dict, meta: dict) -> None:
    payload = {"features": features, "meta": meta}
    session: aiohttp.ClientSession = app["session"]
    try:
        async with session.post(
            BACKEND_INGEST_URL,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=INGEST_TIMEOUT),
        ) as resp:
            await resp.read()
    except Exception as e:  # noqa: BLE001 - telemetry must never break proxying
        # repr() so empty-string exceptions (e.g. TimeoutError) are identifiable.
        print(f"[proxy] telemetry error: {e!r}", flush=True)


# Static assets are forwarded but NOT sensed: a single page load fires dozens of
# _next/asset requests, which would otherwise swamp the sensor's request-rate
# count and cause false DoS positives. Only "real" navigations/API calls count.
_STATIC_PREFIXES = ("/_next/", "/static/", "/movie-assets/", "/favicon", "/assets/")
_STATIC_SUFFIXES = (
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".txt",
)


def _is_static(path: str) -> bool:
    p = path.split("?")[0].lower()
    return p.startswith(_STATIC_PREFIXES) or p.endswith(_STATIC_SUFFIXES)


async def handle(request: web.Request) -> web.StreamResponse:
    app = request.app
    session: aiohttp.ClientSession = app["session"]

    body = await request.read()
    # request.raw_path is the percent-encoded PATH_INFO including the query string.
    target = TARGET_URL.rstrip("/") + request.raw_path

    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
        and k.lower() not in ("host", SCENARIO_HEADER.lower())
    }

    loop = asyncio.get_event_loop()
    t0 = loop.time()
    status = None
    resp_body = b""
    resp_headers: dict = {}

    try:
        async with session.request(
            request.method,
            target,
            headers=fwd_headers,
            data=body if body else None,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=UPSTREAM_TIMEOUT),
        ) as upstream:
            status = upstream.status
            resp_body = await upstream.read()
            resp_headers = {
                k: v for k, v in upstream.headers.items()
                if k.lower() not in HOP_BY_HOP
            }
    except Exception as e:  # noqa: BLE001 - upstream down / timeout
        status = 502
        resp_body = f"Capture proxy: upstream error ({e})".encode()
        resp_headers = {"Content-Type": "text/plain"}

    duration = loop.time() - t0

    # Static assets are forwarded above but not sensed (see _is_static).
    if _is_static(request.path):
        return web.Response(status=status, body=resp_body, headers=resp_headers)

    # Build features and dispatch telemetry without blocking the client response.
    src_ip = _client_ip(request)
    features = extractor.extract(
        path=request.raw_path,  # path + query string (payloads live in the query)
        method=request.method,
        status=status,
        duration=duration,
        src_bytes=len(body),
        dst_bytes=len(resp_body),
        src_ip=src_ip,
        user_agent=request.headers.get("User-Agent", ""),
    )
    meta = {
        "src_ip": src_ip,
        "path": request.path_qs,
        "method": request.method,
        "status": status,
        "user_agent": request.headers.get("User-Agent", ""),
        "src_bytes": len(body),
        "dst_bytes": len(resp_body),
        "scenario": request.headers.get(SCENARIO_HEADER, ""),
    }
    # Rate-limit telemetry sends. The window above already counted this request,
    # so `count` stays accurate even for requests whose telemetry we skip.
    if _take_token(loop.time()):
        asyncio.create_task(_send_telemetry(app, features, meta))

    return web.Response(status=status, body=resp_body, headers=resp_headers)


async def on_startup(app: web.Application) -> None:
    # Keep-alive pooled connector; force IPv4 to avoid happy-eyeballs latency.
    connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, family=socket.AF_INET)
    # auto_decompress=True: aiohttp adds Accept-Encoding upstream, so the site
    # may gzip/br the response. We DECOMPRESS it here and forward plain bytes,
    # because `content-encoding` is stripped as a hop-by-hop header below — if we
    # forwarded the still-compressed body without that header the browser would
    # render gibberish. (This is the fix for "the proxy shows a garbled page".)
    app["session"] = aiohttp.ClientSession(auto_decompress=True, connector=connector)
    print(f"[proxy] listening on http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"[proxy] forwarding to {TARGET_URL}", flush=True)
    print(f"[proxy] telemetry -> {BACKEND_INGEST_URL}", flush=True)


async def on_cleanup(app: web.Application) -> None:
    await app["session"].close()


def make_app() -> web.Application:
    app = web.Application(client_max_size=64 * 1024 * 1024)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_route("*", "/{tail:.*}", handle)
    return app


if __name__ == "__main__":
    try:
        web.run_app(make_app(), host=LISTEN_HOST, port=LISTEN_PORT, print=None)
    except KeyboardInterrupt:
        sys.exit(0)

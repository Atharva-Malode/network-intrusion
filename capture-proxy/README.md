# Capture Proxy — traffic sensor

A reverse proxy that sits **in front of** the netflix-clone demo site and
replaces the old Next.js `middleware.ts` as the traffic-capture mechanism.

```
browser / attack-script ──▶ capture-proxy (:8080) ──▶ netflix-clone (:3000)
                                     │
                                     └──▶ backend /ingest  (NSL-KDD feature record)
```

For every request it:
1. transparently forwards to the real site and streams the response back,
2. computes an NSL-KDD 41-feature connection record over sliding windows
   (see [`feature_extractor.py`](feature_extractor.py)),
3. fires the record to the backend `/ingest` endpoint, where the pretrained
   model classifies the attack class.

## Why a proxy instead of middleware

- **Sensor placement like a real NIDS** — sits on the network path, not inside
  the app. The demo site has zero detection code.
- Lets the sensor measure real connection-level signals (duration, byte counts,
  request-rate windows) that middleware cannot see cleanly.
- One sensor works regardless of what framework the protected site is built in.

## Run

```bash
cd capture-proxy
uv sync            # or: pip install -e .
uv run python proxy.py
```

Then browse the site through the proxy: **http://localhost:8080** (not :3000),
and point the attack-script at the proxy (it already targets :8080).

Config via env vars (see [`config.py`](config.py)): `PROXY_PORT`,
`PROXY_TARGET`, `BACKEND_INGEST_URL`.

> Run the demo site with `next build && next start` so the proxy forwards plain
> HTTP without dev-mode HMR websockets.

## Feature-mapping honesty

Some NSL-KDD features are not directly observable at the HTTP layer; those are
derived from attack indicators (sensitive paths, failed auth, RCE tokens). This
is documented in `feature_extractor.py`. The model is trained on real NSL-KDD;
the sensor is a best-effort bridge.

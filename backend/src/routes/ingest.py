import asyncio
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs

from fastapi import APIRouter
from pydantic import BaseModel

from src.models.traffic import TrafficEvent
from src.storage.memory import traffic_events, baseline_events
from src.websocket.manager import manager
from src.services.drift_engine import get_cached_drift
from src.services import nids_engine
from src.services import learning_engine
from src.services import live_capture

router = APIRouter()


class IngestPayload(BaseModel):
    features: Dict[str, Any]
    meta: Dict[str, Any] = {}


def _build_event(features: Dict[str, Any], meta: Dict[str, Any]) -> TrafficEvent:
    """Construct a TrafficEvent (for the drift engine) from the sensor record."""
    import time

    raw_path = str(meta.get("path", "/"))
    parsed = urlparse(raw_path)
    path = parsed.path or "/"
    query_string = parsed.query
    query_param_count = len(parse_qs(query_string)) if query_string else 0
    path_depth = len([p for p in path.split("/") if p])

    return TrafficEvent(
        timestamp=float(meta.get("timestamp", time.time() * 1000.0)),
        path=path,
        full_url=f"http://localhost:8080{raw_path}",
        method=str(meta.get("method", "GET")),
        ip=str(meta.get("src_ip", "127.0.0.1")),
        user_agent=str(meta.get("user_agent", "")),
        referer="",
        host="localhost:8080",
        origin="",
        content_length=int(features.get("src_bytes", 0) or 0),
        content_type="",
        accept="",
        accept_language="",
        accept_encoding="",
        cache_control="",
        connection="",
        query_string=query_string,
        query_param_count=query_param_count,
        path_depth=path_depth,
        protocol="http",
        sec_fetch_site="",
        sec_fetch_mode="",
        sec_fetch_dest="",
    )


ASSIST_ENABLED = os.environ.get("NIDS_ASSIST", "1") != "0"


def _assist(detection: Dict[str, Any], scenario: str) -> None:
    """Replace a verdict that disagrees with the scenario tag; mark it assisted."""
    expected = live_capture.expected_for(scenario)
    if expected is None:
        return
    unknown = expected == live_capture.NOVEL_LABEL
    shown = "Unknown" if detection.get("novel") else detection.get("label")
    if shown == ("Unknown" if unknown else expected):
        return
    detection["model_label"] = detection.get("label")
    detection["label"] = "Unknown" if unknown else expected
    detection["novel"] = unknown
    detection["description"] = nids_engine.CLASS_DESCRIPTIONS.get(
        expected, nids_engine._learned_description(expected))
    detection["source"] = "assisted"


def _process(features: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    """CPU-bound work (model inference + drift). Runs in a threadpool so it does
    not block the event loop under high ingest rates."""
    detection = nids_engine.classify(features)
    drift_data = get_cached_drift()

    # Novelty is decided per event in nids_engine.classify(): an outlier to all
    # sensor-domain training data (open-set detector) that no signature explains
    # and the model cannot confidently place. Drift is reported alongside as the
    # window-level signal but is not required: it also rises for KNOWN attacks,
    # so gating on it would let normal browsing during an attack into the bucket.
    novel = bool(detection.get("novel"))

    # Ground-truth tag from the lab traffic generator (never a model input):
    # record known classes for calibration, and score the REAL model verdict in
    # the live confusion matrix (/learning) BEFORE any demo display override, so
    # that page keeps showing the model's honest live accuracy.
    scenario = str(meta.get("scenario") or "").lower()
    if scenario:
        live_capture.record(features, scenario)
        live_capture.tally(scenario, detection)

    if novel:
        learning_engine.add_candidate(features, meta, detection)

    # Ground-truth assist (lab demo only): when the detector's verdict disagrees
    # with the attack script's tag, show the tagged class instead so the live
    # walkthrough is reliable. Applied AFTER the novel bucket and the live
    # matrix above, so learning and scoring still use the detector's own
    # verdict. Always disclosed: source="assisted", and the dashboard marks it.
    # Untagged real browsing is never touched. Disable with NIDS_ASSIST=0.
    if ASSIST_ENABLED and scenario:
        _assist(detection, scenario)

    nids_engine.record_detection(detection, meta)

    event = _build_event(features, meta)
    traffic_events.append(event)

    return {
        "type": "traffic",
        "timestamp": event.timestamp,
        "path": event.path,
        "method": event.method,
        "ip": event.ip,
        "content_length": event.content_length,
        "path_depth": event.path_depth,
        "user_agent": event.user_agent,
        "status": meta.get("status"),
        "detection": detection,
        "threat_summary": nids_engine.threat_summary(),
        "drift": drift_data,
    }


# Broadcast throttle: under a flood the proxy posts telemetry many times a second
# and each would otherwise fan out to every WS client. Coalesce to ~12/s — the
# dashboard can't render faster than that anyway, and it keeps the event loop
# free so /metrics, /detection/status and the WebSocket stay responsive.
_last_broadcast = {"t": 0.0}
_BROADCAST_MIN_GAP = 0.08  # seconds (~12 broadcasts/sec max)

# Load shedding. One classify() is ~66ms (600-tree forest + novelty detector), so
# sustained input above ~15/s would queue without bound: latency grows until the
# WebSocket and REST endpoints starve and the backend looks hung. Cap how many
# classifications may be in flight and drop the excess — telemetry is a SAMPLE of
# the traffic anyway (the sensor counts every request itself), so shedding costs
# nothing but keeps the service responsive no matter how hard it is flooded.
_MAX_INFLIGHT = 4
_inflight = {"n": 0}


@router.post("/ingest")
async def ingest(payload: IngestPayload):
    """
    Receives an NSL-KDD feature record from the capture proxy, classifies the
    attack class with the pretrained model, and broadcasts detection + drift.
    """
    if _inflight["n"] >= _MAX_INFLIGHT:
        # Overloaded: skip this sample rather than queue it behind the others.
        return {"status": "shed", "detection": None}

    _inflight["n"] += 1
    try:
        return await _ingest_one(payload)
    finally:
        _inflight["n"] -= 1


async def _ingest_one(payload: IngestPayload):
    loop = asyncio.get_event_loop()
    message = await loop.run_in_executor(None, _process, payload.features, payload.meta)
    # Fire-and-forget + throttled: never make /ingest wait on the WebSocket fan-out
    # (a slow client must not add latency here or back up the proxy under a flood).
    now = loop.time()
    if now - _last_broadcast["t"] >= _BROADCAST_MIN_GAP:
        _last_broadcast["t"] = now
        asyncio.create_task(manager.broadcast(message))
    return {"status": "received", "detection": message["detection"]}


@router.get("/detection/status")
async def detection_status():
    """Model load state + rolling threat summary."""
    return {
        "model": nids_engine.model_status(),
        "threat_summary": nids_engine.threat_summary(),
    }

from fastapi import APIRouter
from src.models.traffic import TrafficEvent
from src.storage.memory import traffic_events, baseline_events
from src.websocket.manager import manager
from src.services.drift_engine import calculate_drift_metrics

router = APIRouter()

ATTACK_IPS_SET = {
    "185.220.101.5", "185.220.101.44", "185.220.102.78", "45.83.223.12",
    "45.83.223.99", "103.21.244.15", "103.21.244.201", "194.26.29.11"
}


@router.post("/traffic")
async def receive_traffic(event: TrafficEvent):
    # If baseline window is not fully populated (< 300 items), add clean requests
    if len(baseline_events) < 300:
        # Strict clean traffic check for baseline candidates
        is_clean = (
            event.ip not in ATTACK_IPS_SET and
            event.path_depth <= 3 and
            event.method == "GET" and
            not any(kw in event.path for kw in ["admin", "env", "debug", "bypass", "phpmyadmin", "config", "exec"]) and
            not any(ua in event.user_agent.lower() for ua in ["sqlmap", "nikto", "nmap", "go-http-client"])
        )
        if is_clean:
            baseline_events.append(event)

    traffic_events.append(event)

    print(
        f"[TRAFFIC] {event.method:<6} {event.path:<25} IP={event.ip:<15} UA={event.user_agent[:30]}"
    )

    # Compute updated drift stats
    drift_data = calculate_drift_metrics()

    # Broadcast event payload and drift status over WebSocket
    await manager.broadcast({
        "type": "traffic",
        "timestamp": event.timestamp,
        "path": event.path,
        "method": event.method,
        "ip": event.ip,
        "content_length": event.content_length,
        "path_depth": event.path_depth,
        "user_agent": event.user_agent,
        "drift": drift_data,
    })

    return {"status": "received"}


@router.get("/events")
async def recent_events(limit: int = 50):
    """Returns latest N traffic events."""
    events_list = list(traffic_events)
    return events_list[-limit:]
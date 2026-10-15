from fastapi import APIRouter
from src.storage.memory import traffic_events, baseline_events
from src.websocket.manager import manager
from src.services.drift_engine import calculate_drift_metrics

router = APIRouter()


@router.get("/metrics")
async def metrics():
    events_list = list(traffic_events)
    unique_ips = len({x.ip for x in events_list})
    unique_paths = len({x.path for x in events_list})

    drift_data = calculate_drift_metrics()

    return {
        "total_requests": len(events_list),
        "baseline_events": len(baseline_events),
        "unique_ips": unique_ips,
        "unique_paths": unique_paths,
        "websocket_clients": len(manager.active_connections),
        "drift": drift_data,
    }
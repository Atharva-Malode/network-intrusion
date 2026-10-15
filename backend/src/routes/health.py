from fastapi import APIRouter
from src.storage.memory import traffic_events, baseline_events

router = APIRouter()


@router.get("/")
@router.get("/health")
async def health():
    return {
        "status": "online",
        "service": "Network Intrusion & Concept Drift Sentinel Backend",
        "events_stored": len(traffic_events),
        "baseline_stored": len(baseline_events),
    }
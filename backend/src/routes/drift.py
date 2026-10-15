from fastapi import APIRouter
from src.services.drift_engine import calculate_drift_metrics
from src.storage.memory import baseline_events, seed_initial_baseline, traffic_events

router = APIRouter()


@router.get("/drift")
async def get_drift_analysis():
    """Returns multi-technique concept drift detection metrics."""
    return calculate_drift_metrics()


@router.post("/drift/reset")
async def reset_baseline():
    """Resets baseline window and re-seeds clean reference benchmark events."""
    baseline_events.clear()
    traffic_events.clear()
    seed_initial_baseline()
    return {
        "status": "success",
        "message": "Baseline window reset and re-seeded with 250 clean benchmark events.",
        "baseline_size": len(baseline_events)
    }

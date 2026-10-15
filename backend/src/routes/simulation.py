import asyncio
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Optional

from src.services.simulator import start_simulation_task
from src.storage.memory import simulation_state

router = APIRouter()


class SimulationRequest(BaseModel):
    mode: str = "normal"  # "normal", "gradual", "spike", "custom"
    count: int = 50
    delay: float = 0.1
    custom_ip: Optional[str] = None
    custom_path: Optional[str] = None


@router.post("/simulate")
async def trigger_simulation(req: SimulationRequest, background_tasks: BackgroundTasks):
    """Triggers background traffic simulation with fake IPs and custom attack patterns."""
    if simulation_state["active"]:
        return {
            "status": "already_running",
            "message": "A simulation is currently in progress.",
            "state": simulation_state
        }

    background_tasks.add_task(
        start_simulation_task,
        mode=req.mode,
        count=req.count,
        delay=req.delay,
        custom_ip=req.custom_ip,
        custom_path=req.custom_path
    )

    return {
        "status": "started",
        "mode": req.mode,
        "count": req.count,
        "custom_ip": req.custom_ip,
        "message": f"Simulation '{req.mode}' initiated in background."
    }


@router.get("/simulate/status")
async def simulation_status():
    """Returns status of ongoing traffic simulation."""
    return simulation_state

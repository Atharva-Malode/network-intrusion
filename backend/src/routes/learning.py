from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from src.services import learning_engine, live_capture

router = APIRouter()


class LabelRequest(BaseModel):
    name: str


@router.get("/learning/status")
async def learning_status():
    """Everything the Learning dashboard needs: pending novel bucket, custom
    classes, model metrics (current + previous), and retrain state."""
    return learning_engine.status()


@router.post("/learning/label")
async def label_bucket(req: LabelRequest):
    """Name the pending novel bucket, synthesize samples, append to the dataset."""
    return learning_engine.label_bucket(req.name)


class RetrainRequest(BaseModel):
    name: Optional[str] = None


@router.post("/learning/retrain")
async def retrain(req: Optional[RetrainRequest] = None):
    """Retrain the model on NSL-KDD + the custom labeled dataset (background).
    With a name, the pending novel bucket is first labeled as that class."""
    return learning_engine.start_retrain(req.name if req else None)


@router.post("/learning/reset")
async def reset_to_base():
    """Forget all learned classes and retrain on the 5 base classes."""
    return learning_engine.reset_to_base()


class AutoLearnRequest(BaseModel):
    enabled: bool


@router.post("/learning/auto")
async def auto_learn(req: AutoLearnRequest):
    """Turn automatic novel-attack learning (label + retrain) on or off."""
    return learning_engine.set_auto_learn(req.enabled)


@router.post("/learning/capture/reset")
async def reset_capture():
    """Delete the calibration recording (start a fresh `main.py calibrate`)."""
    return live_capture.reset_capture()


@router.post("/learning/live-matrix/reset")
async def reset_live_matrix():
    """Clear the real-time confusion matrix tally."""
    live_capture.reset_matrix()
    return live_capture.live_matrix()

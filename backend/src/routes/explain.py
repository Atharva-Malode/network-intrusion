from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from src.services import explain_engine

router = APIRouter()


class ExplainPayload(BaseModel):
    # All optional: the client sends the snapshot it is showing; the server
    # falls back to its own live state for anything missing.
    detection: Optional[Dict[str, Any]] = None
    threat_summary: Optional[Dict[str, Any]] = None
    drift: Optional[Dict[str, Any]] = None


@router.post("/explain")
async def explain(payload: ExplainPayload):
    """Return a one-paragraph plain-language explanation of the current situation."""
    return explain_engine.explain(payload.model_dump())


@router.get("/explain")
async def explain_get():
    """Explain using only server-side live state (no client snapshot)."""
    return explain_engine.explain({})

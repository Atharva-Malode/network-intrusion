from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.routes.health import router as health_router
from src.routes.metrics import router as metrics_router
from src.routes.traffic import router as traffic_router
from src.routes.websocket import router as websocket_router
from src.routes.drift import router as drift_router
from src.routes.simulation import router as simulation_router
from src.routes.ingest import router as ingest_router
from src.routes.learning import router as learning_router
from src.routes.explain import router as explain_router

app = FastAPI(
    title="Network Intrusion & Concept Drift Sentinel API",
    version="2.0.0",
    description="Real-time Network Telemetry Ingestion, Multi-Technique Concept Drift Engine & Attack Simulator",
)

# Enable CORS for Next.js frontend, demo sites, and WebSocket clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register modularized APIRouters
app.include_router(health_router)
app.include_router(metrics_router)
app.include_router(traffic_router)
app.include_router(websocket_router)
app.include_router(drift_router)
app.include_router(simulation_router)
app.include_router(ingest_router)
app.include_router(learning_router)
app.include_router(explain_router)
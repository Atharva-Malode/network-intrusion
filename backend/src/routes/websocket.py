from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from src.websocket.manager import manager
from src.storage.memory import traffic_events
from src.services.drift_engine import calculate_drift_metrics

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    print(f"[WS] Client connected ({len(manager.active_connections)} active)")

    # Send initial snapshot upon connection
    try:
        drift_data = calculate_drift_metrics()
        await websocket.send_json({
            "type": "init",
            "events_count": len(traffic_events),
            "drift": drift_data,
        })
    except Exception as e:
        print(f"[WS] Init error: {e}")

    try:
        while True:
            # Keep connection alive & receive client pings/messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print(f"[WS] Client disconnected ({len(manager.active_connections)} active)")
    except Exception as e:
        manager.disconnect(websocket)
        print(f"[WS] Exception: {e}")

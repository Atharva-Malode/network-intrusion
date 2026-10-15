import asyncio

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, payload: dict):
        """Push `payload` to every connected client.

        Sends to all clients CONCURRENTLY, each with a short timeout. This is
        critical: the old version awaited each `send_json` sequentially, so under
        a flood a single slow or half-dead client (its TCP send buffer full)
        would block the event loop and hang the whole backend. Here a stuck
        client is simply dropped after the timeout and never blocks the others.
        """
        conns = list(self.active_connections)
        if not conns:
            return

        async def _send(conn: WebSocket):
            try:
                await asyncio.wait_for(conn.send_json(payload), timeout=1.5)
                return None
            except Exception:
                return conn  # timed out / errored -> prune it

        results = await asyncio.gather(*(_send(c) for c in conns))
        for conn in results:
            if conn is not None:
                self.disconnect(conn)


manager = ConnectionManager()

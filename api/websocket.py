"""WebSocket manager for real-time alert streaming to the dashboard.

`WebSocketManager` tracks active connections and broadcasts JSON alerts;
`broadcast_alert()` is the module-level entry point other routes call when a
trigger, kill-switch, rotation, or system event fires.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger

router = APIRouter()

PING_INTERVAL_SECS = 30

# Valid alert types (per the Phase 7 schema).
ALERT_TYPES = {"honeytoken_trigger", "killswitch_fired", "token_rotated", "system_info"}


class WebSocketManager:
    def __init__(self) -> None:
        self._active: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._active.append(websocket)
        logger.info("WebSocket client connected ({} active)", len(self._active))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._active:
                self._active.remove(websocket)
        logger.info("WebSocket client disconnected ({} active)", len(self._active))

    async def broadcast(self, message: dict) -> None:
        # Snapshot under lock; send outside it. Drop any connection that errors.
        async with self._lock:
            targets = list(self._active)
        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self._active:
                        self._active.remove(ws)

    @property
    def connection_count(self) -> int:
        return len(self._active)


manager = WebSocketManager()


def make_alert(alert_type: str, token_id: str | None = None, data: dict | None = None) -> dict:
    if alert_type not in ALERT_TYPES:
        logger.warning("Unknown alert type {!r}", alert_type)
    return {
        "type": alert_type,
        "token_id": token_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
    }


async def broadcast_alert(alert: dict) -> None:
    """Broadcast an alert dict to all connected WebSocket clients."""
    await manager.broadcast(alert)
    logger.info("Broadcast {} alert to {} client(s)", alert.get("type"), manager.connection_count)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "message": "AC-2035 alert stream active"})
        while True:
            # Wait for a client message; on timeout, send a keepalive ping.
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=PING_INTERVAL_SECS)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.warning("WebSocket error: {}", e)
        await manager.disconnect(websocket)

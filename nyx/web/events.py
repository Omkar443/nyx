"""
NYX WebSocket Event Broadcasting Engine
Provides real-time event streaming for dashboard clients.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket client connections and event broadcasting."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        mission_id: Optional[str] = None,
    ) -> None:
        """Broadcast a structured security event to all connected WebSocket clients."""
        payload = {
            "event": event_type,
            "timestamp": datetime.now().isoformat(),
            "mission_id": mission_id,
            "data": data or {},
        }
        
        message_str = json.dumps(payload)
        dead_connections = []

        for connection in list(self.active_connections):
            try:
                await connection.send_text(message_str)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


# Global event manager instance
ws_manager = ConnectionManager()


async def emit_event(
    event_type: str,
    data: Optional[Dict[str, Any]] = None,
    mission_id: Optional[str] = None,
) -> None:
    """Convenience helper to broadcast WebSocket events asynchronously."""
    await ws_manager.broadcast_event(event_type, data=data, mission_id=mission_id)

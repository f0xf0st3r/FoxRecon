"""WebSocket module for real-time scan progress updates."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections import defaultdict

from fastapi import WebSocket, WebSocketDisconnect

from internal.utils.logging import get_logger

logger = get_logger(module="websocket")


class ConnectionManager:
    """Manages WebSocket connections for real-time updates.

    Organizes connections by:
    - scan_job_id: Updates for a specific scan
    - target_id: Updates for all scans on a target
    - user_id: User-specific notifications
    """

    def __init__(self) -> None:
        # scan_job_id -> set of websockets
        self.scan_connections: dict[str, set[WebSocket]] = defaultdict(set)
        # target_id -> set of websockets
        self.target_connections: dict[str, set[WebSocket]] = defaultdict(set)
        # user_id -> set of websockets
        self.user_connections: dict[str, set[WebSocket]] = defaultdict(set)
        # All active connections for broadcasting
        self.active_connections: set[WebSocket] = set()

    async def connect(
        self,
        websocket: WebSocket,
        scan_job_id: str | None = None,
        target_id: str | None = None,
        user_id: str | None = None,
    ) -> None:
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)

        if scan_job_id:
            self.scan_connections[scan_job_id].add(websocket)
        if target_id:
            self.target_connections[target_id].add(websocket)
        if user_id:
            self.user_connections[user_id].add(websocket)

        logger.info(
            "websocket_connected",
            scan_job_id=scan_job_id,
            target_id=target_id,
            user_id=user_id,
        )

    def disconnect(
        self,
        websocket: WebSocket,
        scan_job_id: str | None = None,
        target_id: str | None = None,
        user_id: str | None = None,
    ) -> None:
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)

        if scan_job_id:
            self.scan_connections[scan_job_id].discard(websocket)
            if not self.scan_connections[scan_job_id]:
                del self.scan_connections[scan_job_id]

        if target_id:
            self.target_connections[target_id].discard(websocket)
            if not self.target_connections[target_id]:
                del self.target_connections[target_id]

        if user_id:
            self.user_connections[user_id].discard(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]

    async def send_scan_update(
        self,
        scan_job_id: str,
        update: dict,
    ) -> None:
        """Send a scan progress update to all subscribers."""
        message = {
            "type": "scan_update",
            "scan_job_id": scan_job_id,
            "data": update,
        }
        await self._send_to_group(self.scan_connections.get(scan_job_id, set()), message)

    async def send_finding(
        self,
        scan_job_id: str,
        target_id: str,
        finding: dict,
    ) -> None:
        """Send a new finding to scan and target subscribers."""
        message = {
            "type": "new_finding",
            "scan_job_id": scan_job_id,
            "target_id": target_id,
            "data": finding,
        }
        # Send to scan subscribers
        await self._send_to_group(self.scan_connections.get(scan_job_id, set()), message)
        # Send to target subscribers
        await self._send_to_group(self.target_connections.get(target_id, set()), message)

    async def send_notification(
        self,
        user_id: str,
        notification: dict,
    ) -> None:
        """Send a notification to a specific user."""
        message = {
            "type": "notification",
            "data": notification,
        }
        await self._send_to_group(self.user_connections.get(user_id, set()), message)

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected clients."""
        await self._send_to_group(self.active_connections, message)

    async def _send_to_group(
        self,
        connections: set[WebSocket],
        message: dict,
    ) -> None:
        """Send a message to a group of connections, removing dead ones."""
        dead_connections = set()
        message_str = json.dumps(message)

        for ws in connections:
            try:
                await ws.send_text(message_str)
            except Exception:
                dead_connections.add(ws)

        # Clean up dead connections
        for ws in dead_connections:
            self.active_connections.discard(ws)
            connections.discard(ws)


# Global connection manager instance
manager = ConnectionManager()

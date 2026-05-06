"""WebSocket routes for real-time updates."""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from internal.websocket.manager import manager
from internal.utils.logging import get_logger

logger = get_logger(module="websocket_routes")

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scan/{scan_job_id}")
async def scan_websocket(websocket: WebSocket, scan_job_id: str):
    """WebSocket endpoint for real-time scan progress updates.

    Connect to receive live updates for a specific scan job.
    Messages are JSON with the following structure:

    {
        "type": "scan_update",
        "scan_job_id": "...",
        "data": {
            "stage": "recon",
            "status": "running",
            "progress": 0.5,
            "items_found": 42,
        }
    }
    """
    await manager.connect(websocket, scan_job_id=scan_job_id)

    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await websocket.receive_text()
            # Echo back acknowledgment
            await websocket.send_json({
                "type": "ack",
                "message": "Connection active",
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_job_id=scan_job_id)
        logger.info("scan_websocket_disconnected", scan_job_id=scan_job_id)


@router.websocket("/ws/target/{target_id}")
async def target_websocket(websocket: WebSocket, target_id: str):
    """WebSocket endpoint for all scan updates on a target.

    Receives updates from all scan jobs running against the target,
    plus new finding notifications.
    """
    await manager.connect(websocket, target_id=target_id)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, target_id=target_id)


@router.websocket("/ws/notifications")
async def notifications_websocket(
    websocket: WebSocket,
    user_id: str | None = None,
):
    """WebSocket endpoint for user notifications.

    Receives system-wide and user-specific notifications including:
    - Scan completion alerts
    - Critical finding alerts
    - System notifications
    """
    await manager.connect(websocket, user_id=user_id)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id=user_id)

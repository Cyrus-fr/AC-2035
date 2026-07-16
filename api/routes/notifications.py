"""Notification routes — surface the notifier's local `.alert` fallback files
so the dashboard can display alerts even when every external channel is down
(U0)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter

from notifier import fallback

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
async def list_notifications(limit: int = 50) -> list[dict]:
    """Recent notifier fallback alerts (newest first)."""
    return await asyncio.to_thread(fallback.read_alerts, limit)

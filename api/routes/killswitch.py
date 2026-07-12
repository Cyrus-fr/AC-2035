"""Kill-switch routes — list pending approvals, approve one, or execute
directly against a supplied AttackObject."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Body, HTTPException
from loguru import logger

from api.models import KillSwitchResultResponse, PendingItem
from api.websocket import broadcast_alert, make_alert
from killswitch import orchestrator

router = APIRouter(prefix="/api/killswitch", tags=["killswitch"])


@router.get("/pending", response_model=list[PendingItem])
async def list_pending() -> list[dict]:
    return [
        {
            "pending_id": pid,
            "token_id": ao.get("token_id"),
            "entry_point": ao.get("entry_point"),
            "confidence": ao.get("confidence"),
        }
        for pid, ao in orchestrator.pending_map().items()
    ]


@router.post("/approve/{pending_id}", response_model=KillSwitchResultResponse)
async def approve(pending_id: str) -> dict:
    if pending_id not in orchestrator.pending_map():
        raise HTTPException(status_code=404, detail=f"No pending kill-switch {pending_id}")

    result = await asyncio.to_thread(orchestrator.approve, pending_id)
    await broadcast_alert(make_alert(
        "killswitch_fired",
        token_id=result.attack_object_token_id,
        data={"status": result.status, "triggered_by": result.triggered_by, "pending_id": pending_id},
    ))
    return result.to_dict()


@router.post("/execute", response_model=KillSwitchResultResponse)
async def execute(attack_object: dict[str, Any] = Body(...)) -> dict:
    if not attack_object.get("token_id"):
        raise HTTPException(status_code=422, detail="AttackObject must include token_id")

    try:
        result = await asyncio.to_thread(orchestrator.execute, attack_object, "auto")
    except Exception as e:
        logger.warning("Kill-switch execute failed: {}", e)
        raise HTTPException(status_code=500, detail=f"Kill-switch execute failed: {e}")

    await broadcast_alert(make_alert(
        "killswitch_fired",
        token_id=result.attack_object_token_id,
        data={"status": result.status, "triggered_by": result.triggered_by},
    ))
    return result.to_dict()

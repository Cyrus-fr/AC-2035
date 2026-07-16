"""Alert routes — kill-switch audit history and the end-to-end trigger
pipeline (backtrace → kill-switch)."""

from __future__ import annotations

import asyncio
import json
import os

from fastapi import APIRouter, HTTPException
from loguru import logger

from api.models import KillSwitchResultResponse, TriggerEventBody, TriggerResponse
from api.websocket import broadcast_alert, make_alert
from backtrace.engine import run_backtrace
from collector.pubsub_listener import TriggerEvent
from killswitch import AUDIT_DIR
from killswitch import orchestrator

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _load_audit_logs() -> list[dict]:
    """Read every kill-switch audit JSON. Missing dir → empty list."""
    if not AUDIT_DIR.exists():
        return []
    logs = []
    for path in AUDIT_DIR.glob("*.json"):
        try:
            logs.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception as e:
            logger.warning("Skipping unreadable audit log {}: {}", path.name, e)
    logs.sort(key=lambda r: r.get("executed_at") or "", reverse=True)
    return logs


@router.get("", response_model=list[KillSwitchResultResponse])
async def list_alerts(limit: int = 50) -> list[dict]:
    logs = await asyncio.to_thread(_load_audit_logs)
    return logs[: max(0, limit)]


@router.get("/{token_id}", response_model=list[KillSwitchResultResponse])
async def alerts_for_token(token_id: str) -> list[dict]:
    logs = await asyncio.to_thread(_load_audit_logs)
    matching = [r for r in logs if r.get("attack_object_token_id") == token_id]
    if not matching:
        raise HTTPException(status_code=404, detail=f"No audit logs for token {token_id}")
    return matching


@router.post("/trigger", response_model=TriggerResponse)
async def trigger(event: TriggerEventBody) -> TriggerResponse:
    """Run the full pipeline for a honeytoken trigger: backtrace the attack,
    then fire (or stage) the kill-switch per KILLSWITCH_MODE, broadcasting a
    live alert."""
    trigger_event = TriggerEvent.from_dict(event.model_dump())

    try:
        attack = await asyncio.to_thread(run_backtrace, trigger_event)
    except Exception as e:
        logger.warning("Backtrace failed for token {}: {}", event.token_id, e)
        raise HTTPException(status_code=500, detail=f"Backtrace failed: {e}")

    mode = os.getenv("KILLSWITCH_MODE", "manual")
    try:
        result = await asyncio.to_thread(orchestrator.execute, attack, mode)
    except Exception as e:
        logger.warning("Kill-switch failed for token {}: {}", event.token_id, e)
        raise HTTPException(status_code=500, detail=f"Kill-switch failed: {e}")

    await broadcast_alert(make_alert(
        "honeytoken_trigger",
        token_id=event.token_id,
        data={
            "entry_point": attack.entry_point,
            "confidence": attack.confidence,
            "killswitch_status": result.status,
            "mode": mode,
        },
    ))

    # U0 — best-effort external alert (Slack/Discord/PagerDuty + .alert fallback).
    try:
        import notifier

        notifier.notify(
            "honeytoken_trigger",
            token_id=event.token_id,
            summary=f"Honeytoken {event.token_id} triggered from {attack.entry_point}",
            fields={
                "entry_point": attack.entry_point,
                "confidence": attack.confidence,
                "killswitch_status": result.status,
                "mode": mode,
            },
        )
    except Exception as e:  # notifier is non-fatal
        logger.warning("Notifier hook failed (non-fatal): {}", e)

    return TriggerResponse(attack_object=attack.to_dict(), killswitch_result=result.to_dict())

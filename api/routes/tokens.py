"""Token routes — read the honeytoken registry and trigger rotation.

token_value is never exposed: the response model omits it and it is popped
defensively before serialization."""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, HTTPException
from loguru import logger

from api.models import RotateResponse, TokenItem
from api.websocket import broadcast_alert, make_alert
from deployer import registry, rotator

router = APIRouter(prefix="/api/tokens", tags=["tokens"])


def _safe_get_all() -> list[dict]:
    """registry.get_all() creates the table if the DB is new, so a missing
    registry just yields an empty list rather than an error."""
    try:
        rows = registry.get_all()
    except Exception as e:
        logger.warning("registry.get_all failed: {}", e)
        return []
    for row in rows:
        row.pop("token_value", None)  # never leave the sandbox
    return rows


@router.get("", response_model=list[TokenItem])
async def list_tokens(status: Optional[str] = None) -> list[dict]:
    rows = await asyncio.to_thread(_safe_get_all)
    if status:
        rows = [r for r in rows if r.get("status") == status]
    return rows


@router.get("/{token_id}", response_model=TokenItem)
async def get_token(token_id: str) -> dict:
    rows = await asyncio.to_thread(_safe_get_all)
    for row in rows:
        if row.get("token_id") == token_id:
            return row
    raise HTTPException(status_code=404, detail=f"Token {token_id} not found")


@router.post("/rotate", response_model=RotateResponse)
async def rotate_tokens() -> RotateResponse:
    try:
        count = await asyncio.to_thread(rotator.rotate_all)
    except Exception as e:
        logger.warning("Rotation failed: {}", e)
        raise HTTPException(status_code=500, detail=f"Rotation failed: {e}")

    await broadcast_alert(make_alert("token_rotated", data={"rotated": count}))
    return RotateResponse(rotated=count)

"""Local `.alert` file fallback for the notifier circuit breaker (U0).

When an external channel fails (or none is configured), the alert is still
persisted here so the dashboard can surface it by polling GET /api/notifications.
An attacker who kills your Slack/PagerDuty webhook can't also silence the alert.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

FALLBACK_DIR = Path(__file__).resolve().parent / "fallback_alerts"


def write_alert(event: dict) -> Path:
    """Persist an alert as a timestamped .alert JSON file. Never raises."""
    try:
        FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        token = event.get("token_id") or "alert"
        path = FALLBACK_DIR / f"{token}_{ts}.alert"
        payload = {**event, "fallback": True, "written_at": datetime.now(timezone.utc).isoformat()}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.warning("Notifier fallback .alert written: {}", path)
        return path
    except Exception as e:  # pragma: no cover — fallback must never crash caller
        logger.error("Failed to write .alert fallback (non-fatal): {}", e)
        return FALLBACK_DIR


def read_alerts(limit: int = 50) -> list[dict]:
    """Return recent fallback alerts (newest first). Missing dir -> empty."""
    if not FALLBACK_DIR.exists():
        return []
    out: list[dict] = []
    for p in sorted(FALLBACK_DIR.glob("*.alert"), reverse=True):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception as e:
            logger.warning("Skipping unreadable .alert {}: {}", p.name, e)
    return out[: max(0, limit)]

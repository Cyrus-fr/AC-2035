"""External alerting (U0).

Fan out honeytoken-trigger and kill-switch alerts to Slack / Discord /
PagerDuty with a per-channel circuit breaker and a local `.alert` fallback.

Best-effort and non-blocking BY CONTRACT: notification never blocks or crashes
the kill-switch pipeline. `dispatch()` runs on a daemon thread, swallows every
error, and — on a channel failure (404/403/timeout/connection error) — logs
CRITICAL and writes a local `.alert` the dashboard can poll.
"""

from __future__ import annotations

import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from notifier import fallback
from notifier.base import CircuitBreaker, Notifier, env
from notifier.discord import DiscordNotifier
from notifier.pagerduty import PagerDutyNotifier
from notifier.slack import SlackNotifier

# Persistent channel singletons so circuit-breaker state survives across alerts.
_CHANNELS: list[Notifier] = [SlackNotifier(), DiscordNotifier(), PagerDutyNotifier()]


def build_event(kind: str, token_id: str, summary: str,
                fields: Optional[dict] = None, severity: str = "critical") -> dict:
    return {
        "kind": kind,
        "token_id": token_id,
        "title": summary,
        "severity": severity,
        "fields": fields or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _dispatch_sync(event: dict, channels: list[Notifier]) -> None:
    active = [c for c in channels if c.configured()]
    if not active:
        # Nothing wired up — still record the alert locally so it's never lost.
        fallback.write_alert(event)
        return
    for ch in active:
        if not ch.breaker.allow():
            logger.warning("Notifier {} circuit OPEN — skipping send, writing .alert fallback", ch.name)
            fallback.write_alert(event)
            continue
        try:
            ch.post(event)
            ch.breaker.record_success()
            logger.info("Alert sent via {}", ch.name)
        except Exception as e:
            # A 404/403 (misconfigured webhook), timeout, or connection error.
            ch.breaker.record_failure()
            logger.critical("Notifier {} FAILED ({}) — writing local .alert fallback", ch.name, e)
            fallback.write_alert(event)


def _safe(event: dict, channels: list[Notifier]) -> None:
    try:
        _dispatch_sync(event, channels)
    except Exception as e:  # pragma: no cover — dispatch must never surface errors
        logger.error("Notifier dispatch crashed (non-fatal): {}", e)


def dispatch(event: dict, channels: Optional[list[Notifier]] = None) -> threading.Thread:
    """Fan out `event` on a daemon thread. Returns the thread (tests may join
    it); never raises, never blocks the caller."""
    chans = channels if channels is not None else _CHANNELS
    t = threading.Thread(target=_safe, args=(event, chans), name="notifier-dispatch", daemon=True)
    t.start()
    return t


def notify(kind: str, token_id: str, summary: str,
           fields: Optional[dict] = None, severity: str = "critical") -> threading.Thread:
    """Build and dispatch an alert. Best-effort, non-blocking."""
    return dispatch(build_event(kind, token_id, summary, fields, severity))

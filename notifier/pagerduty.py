"""PagerDuty channel (U0): triggers an incident via the Events API v2 using
PAGERDUTY_ROUTING_KEY."""

from __future__ import annotations

import httpx

from notifier.base import Notifier, env

_ENQUEUE = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyNotifier(Notifier):
    name = "pagerduty"

    def _key(self) -> str:
        return env("PAGERDUTY_ROUTING_KEY")

    def configured(self) -> bool:
        return bool(self._key())

    def post(self, event: dict) -> None:
        payload = {
            "routing_key": self._key(),
            "event_action": "trigger",
            "payload": {
                "summary": str(event.get("title", "AC-2035 alert"))[:1024],
                "severity": "critical" if event.get("severity") == "critical" else "warning",
                "source": "ac-2035",
                "custom_details": event.get("fields", {}) or {},
            },
        }
        resp = httpx.post(_ENQUEUE, json=payload, timeout=self.timeout_s)
        resp.raise_for_status()

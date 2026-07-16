"""Slack channel (U0): posts a Block Kit message to an incoming-webhook URL
from SLACK_WEBHOOK_URL."""

from __future__ import annotations

import httpx

from notifier.base import Notifier, env


class SlackNotifier(Notifier):
    name = "slack"

    def _url(self) -> str:
        return env("SLACK_WEBHOOK_URL")

    def configured(self) -> bool:
        return bool(self._url())

    def post(self, event: dict) -> None:
        title = str(event.get("title", "AC-2035 alert"))
        fields = event.get("fields", {}) or {}
        body = "\n".join(f"*{k}:* {v}" for k, v in fields.items()) or "-"
        payload = {
            "text": title,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
                {"type": "section", "text": {"type": "mrkdwn", "text": body}},
            ],
        }
        resp = httpx.post(self._url(), json=payload, timeout=self.timeout_s)
        resp.raise_for_status()

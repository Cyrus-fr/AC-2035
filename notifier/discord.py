"""Discord channel (U0): posts an embed to a webhook URL from
DISCORD_WEBHOOK_URL."""

from __future__ import annotations

import httpx

from notifier.base import Notifier, env

_RED = 0xE5484D
_GREEN = 0x4CC38A


class DiscordNotifier(Notifier):
    name = "discord"

    def _url(self) -> str:
        return env("DISCORD_WEBHOOK_URL")

    def configured(self) -> bool:
        return bool(self._url())

    def post(self, event: dict) -> None:
        title = str(event.get("title", "AC-2035 alert"))
        fields = event.get("fields", {}) or {}
        embed = {
            "title": title[:256],
            "color": _RED if event.get("severity") == "critical" else _GREEN,
            "fields": [
                {"name": str(k)[:256], "value": str(v)[:1024], "inline": True}
                for k, v in fields.items()
            ],
        }
        resp = httpx.post(self._url(), json={"embeds": [embed]}, timeout=self.timeout_s)
        resp.raise_for_status()

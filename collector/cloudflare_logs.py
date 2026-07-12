"""Pulls Cloudflare access logs via the Logpull API
(GET /zones/{zone_id}/logs/received) for the 30-minute window before a
honeytoken trigger.

Degrades to a logged warning + empty list when CLOUDFLARE_API_TOKEN or
CLOUDFLARE_ZONE_ID is missing, or the request fails, so the pipeline still
produces a (partial) timeline from whatever other sources succeed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import httpx
from loguru import logger

from .normalizer import NormalizedEvent, make_event

WINDOW_MINUTES = 30
_LOGPULL_FIELDS = (
    "ClientIP,RayID,ClientRequestMethod,ClientRequestURI,"
    "EdgeResponseStatus,EdgeStartTimestamp"
)
_TIMEOUT_SECS = 30.0


def fetch_cloudflare_logs(
    trigger_time: datetime, api_token: str, zone_id: str
) -> list[NormalizedEvent]:
    if not api_token or not zone_id:
        logger.warning(
            "CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID missing — skipping Cloudflare log fetch"
        )
        return []

    window_start = trigger_time - timedelta(minutes=WINDOW_MINUTES)
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/logs/received"
    params = {
        "start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": trigger_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fields": _LOGPULL_FIELDS,
    }
    headers = {"Authorization": f"Bearer {api_token}"}

    try:
        response = httpx.get(url, params=params, headers=headers, timeout=_TIMEOUT_SECS)
        response.raise_for_status()

        # Logpull returns newline-delimited JSON, not a JSON array.
        events: list[NormalizedEvent] = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            events.append(
                make_event(
                    event_type="cloudflare_access",
                    source="cloudflare",
                    timestamp=entry.get("EdgeStartTimestamp") or trigger_time,
                    raw=entry,
                    src_ip=entry.get("ClientIP"),
                    cf_ray=entry.get("RayID"),
                )
            )

        logger.info("Fetched {} Cloudflare access log entries", len(events))
        return events
    except httpx.HTTPError as e:
        logger.warning("Cloudflare Logpull fetch failed: {}", e)
        return []
    except Exception as e:
        logger.warning("Unexpected error during Cloudflare Logpull fetch: {}", e)
        return []

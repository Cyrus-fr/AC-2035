"""Merges raw events from gcp_logs / vpc_flow / cloudflare_logs into one
unified, timestamp-sorted timeline and persists it as JSON.

Never touches credential values — `raw` carries whatever the source gave
us verbatim, but nothing here inspects or logs its contents.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from loguru import logger

TIMELINES_DIR = Path(__file__).resolve().parent / "timelines"

# Cloudflare's Logpull API emits RFC3339 with nanosecond precision (9 digits),
# but datetime.fromisoformat only accepts up to microseconds (6 digits).
_EXCESS_FRAC_RE = re.compile(r"\.(\d{7,})")


@dataclass
class NormalizedEvent:
    event_id: str
    event_type: str  # k8s_log / vpc_flow / cloudflare_access
    timestamp: str  # ISO 8601, UTC
    source: str  # gcp_logging / vpc_flow / cloudflare
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    cf_ray: Optional[str] = None
    process_name: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _to_iso(ts: Union[str, datetime]) -> str:
    """Normalize any incoming timestamp (datetime, or an ISO-ish string
    including Cloudflare's nanosecond-precision RFC3339) to a canonical,
    UTC, fixed-width isoformat string so timelines sort reliably."""
    if isinstance(ts, datetime):
        dt = ts
    else:
        trimmed = _EXCESS_FRAC_RE.sub(lambda m: "." + m.group(1)[:6], ts)
        dt = datetime.fromisoformat(trimmed)

    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds")


def make_event(
    event_type: str,
    source: str,
    timestamp: Union[str, datetime],
    raw: dict,
    *,
    pod_name: Optional[str] = None,
    namespace: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    cf_ray: Optional[str] = None,
    process_name: Optional[str] = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=_to_iso(timestamp),
        source=source,
        pod_name=pod_name,
        namespace=namespace,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        cf_ray=cf_ray,
        process_name=process_name,
        raw=raw,
    )


def build_timeline(*event_lists: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Flatten one or more event lists into a single list sorted ascending
    by timestamp."""
    merged = [event for events in event_lists for event in events]
    merged.sort(key=lambda e: datetime.fromisoformat(e.timestamp))
    return merged


def save_timeline(token_id: str, events: list[NormalizedEvent]) -> Path:
    TIMELINES_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = TIMELINES_DIR / f"{token_id}_{ts}.json"

    payload = [e.to_dict() for e in events]
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    logger.info("Saved timeline for token {} ({} events) to {}", token_id, len(events), path)
    return path


def load_timeline(token_id: str) -> list[dict]:
    """Load the most recently saved timeline JSON for `token_id`."""
    matches = sorted(TIMELINES_DIR.glob(f"{token_id}_*.json"))
    if not matches:
        logger.warning("No timeline found for token {}", token_id)
        return []

    latest = matches[-1]
    return json.loads(latest.read_text(encoding="utf-8"))

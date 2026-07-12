"""Pulls VPC Flow Log entries (via Cloud Logging) for the 30-minute window
before a honeytoken trigger.

Degrades to a logged warning + empty list when GCP_PROJECT_ID is empty or
credentials are unavailable, so the pipeline still produces a (partial)
timeline from whatever other sources succeed.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from google.api_core.exceptions import GoogleAPICallError
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import logging as gcp_logging
from loguru import logger

from .normalizer import NormalizedEvent, make_event

WINDOW_MINUTES = 30


def fetch_vpc_flow_logs(project_id: str, trigger_time: datetime) -> list[NormalizedEvent]:
    """Fetch vpc_flows log entries in the 30-minute window ending at
    `trigger_time`. Protocol/bytes/packets/start_time/end_time stay in
    `raw` — the shared NormalizedEvent schema only has slots for
    src/dst ip+port."""
    if not project_id:
        logger.warning("GCP_PROJECT_ID is empty — skipping VPC Flow Log fetch")
        return []

    window_start = trigger_time - timedelta(minutes=WINDOW_MINUTES)
    filter_str = (
        'log_name:"vpc_flows" '
        f'AND timestamp>="{window_start.isoformat()}" '
        f'AND timestamp<="{trigger_time.isoformat()}"'
    )

    try:
        client = gcp_logging.Client(project=project_id)
        entries = client.list_entries(
            resource_names=[f"projects/{project_id}"],
            filter_=filter_str,
            order_by=gcp_logging.ASCENDING,
        )

        events: list[NormalizedEvent] = []
        for entry in entries:
            payload = entry.payload if isinstance(entry.payload, dict) else {}
            conn = payload.get("connection", {}) or {}
            events.append(
                make_event(
                    event_type="vpc_flow",
                    source="vpc_flow",
                    timestamp=entry.timestamp or trigger_time,
                    raw=payload,
                    src_ip=conn.get("src_ip"),
                    dst_ip=conn.get("dest_ip"),
                    src_port=conn.get("src_port"),
                    dst_port=conn.get("dest_port"),
                )
            )

        logger.info("Fetched {} VPC Flow Log entries", len(events))
        return events
    except DefaultCredentialsError as e:
        logger.warning("No GCP credentials available — skipping VPC Flow Log fetch: {}", e)
        return []
    except GoogleAPICallError as e:
        logger.warning("VPC Flow Log fetch failed: {}", e)
        return []
    except Exception as e:
        logger.warning("Unexpected error during VPC Flow Log fetch: {}", e)
        return []

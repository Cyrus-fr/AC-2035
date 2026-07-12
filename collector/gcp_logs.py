"""Pulls GCP Cloud Logging entries for the 30-minute window before a
honeytoken trigger.

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


def fetch_gcp_logs(project_id: str, namespace: str, trigger_time: datetime) -> list[NormalizedEvent]:
    """Fetch k8s_container log entries for `namespace` in the 30-minute
    window ending at `trigger_time`."""
    if not project_id:
        logger.warning("GCP_PROJECT_ID is empty — skipping GCP Cloud Logging fetch")
        return []

    window_start = trigger_time - timedelta(minutes=WINDOW_MINUTES)
    filter_str = (
        'resource.type="k8s_container" '
        f'AND resource.labels.namespace_name="{namespace}" '
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
            payload = entry.payload if isinstance(entry.payload, dict) else {"message": entry.payload}
            resource_labels = (entry.resource.labels if entry.resource else None) or {}
            events.append(
                make_event(
                    event_type="k8s_log",
                    source="gcp_logging",
                    timestamp=entry.timestamp or trigger_time,
                    raw=payload,
                    pod_name=resource_labels.get("pod_name"),
                    namespace=resource_labels.get("namespace_name"),
                )
            )

        logger.info("Fetched {} GCP Cloud Logging entries for namespace {}", len(events), namespace)
        return events
    except DefaultCredentialsError as e:
        logger.warning("No GCP credentials available — skipping GCP Cloud Logging fetch: {}", e)
        return []
    except GoogleAPICallError as e:
        logger.warning("GCP Cloud Logging fetch failed: {}", e)
        return []
    except Exception as e:
        logger.warning("Unexpected error during GCP Cloud Logging fetch: {}", e)
        return []

"""Subscribes to the honeytoken-triggers Pub/Sub topic and runs the
collection pipeline (GCP logs + VPC Flow + Cloudflare -> normalized
timeline) for each trigger event received.

Falls back to a local simulation mode — trigger events read as JSON lines
from stdin — when GCP_PROJECT_ID is empty, so the pipeline is runnable
without a live GCP project.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

# Allow `python collector/pubsub_listener.py` to import the `collector`
# package: this file's own directory is what Python puts on sys.path for a
# direct script invocation, not the repo root, so `from collector import
# ...` would otherwise fail.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from google.cloud import pubsub_v1
from loguru import logger

from collector import cloudflare_logs, gcp_logs, vpc_flow
from collector.normalizer import NormalizedEvent, build_timeline, save_timeline


@dataclass
class TriggerEvent:
    token_id: str
    token_type: str
    trigger_time: str  # ISO timestamp
    pod_name: str
    pod_namespace: str
    process_name: str
    pid: int
    source: str  # falco or ebpf

    @property
    def trigger_datetime(self) -> datetime:
        return datetime.fromisoformat(self.trigger_time)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "TriggerEvent":
        return cls(
            token_id=data["token_id"],
            token_type=data["token_type"],
            trigger_time=data["trigger_time"],
            pod_name=data["pod_name"],
            pod_namespace=data["pod_namespace"],
            process_name=data["process_name"],
            pid=int(data["pid"]),
            source=data["source"],
        )


def run_pipeline(trigger: TriggerEvent) -> list[NormalizedEvent]:
    """Fetch all sources for the 30-minute window before the trigger, merge
    into one sorted timeline, and save it to disk."""
    project_id = os.getenv("GCP_PROJECT_ID", "")
    cf_token = os.getenv("CLOUDFLARE_API_TOKEN", "")
    cf_zone = os.getenv("CLOUDFLARE_ZONE_ID", "")
    trigger_dt = trigger.trigger_datetime

    logger.info(
        "Running collection pipeline for token {} (trigger at {})",
        trigger.token_id, trigger.trigger_time,
    )

    k8s_events = gcp_logs.fetch_gcp_logs(project_id, trigger.pod_namespace, trigger_dt)
    flow_events = vpc_flow.fetch_vpc_flow_logs(project_id, trigger_dt)
    cf_events = cloudflare_logs.fetch_cloudflare_logs(trigger_dt, cf_token, cf_zone)

    timeline = build_timeline(k8s_events, flow_events, cf_events)
    save_timeline(trigger.token_id, timeline)

    logger.info(
        "Pipeline complete for token {}: {} events ({} k8s, {} vpc_flow, {} cloudflare)",
        trigger.token_id, len(timeline), len(k8s_events), len(flow_events), len(cf_events),
    )
    return timeline


def _handle_message(message) -> None:
    try:
        data = json.loads(message.data.decode("utf-8"))
        trigger = TriggerEvent.from_dict(data)
        run_pipeline(trigger)
        message.ack()
    except Exception as e:
        logger.warning("Failed to process trigger message: {}", e)
        message.nack()


def _run_pubsub_mode(project_id: str) -> None:
    subscription_id = os.getenv("PUBSUB_TRIGGER_TOPIC", "honeytoken-triggers") + "-sub"
    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(project_id, subscription_id)

    logger.info("Listening for honeytoken triggers on {}", subscription_path)
    future = subscriber.subscribe(subscription_path, callback=_handle_message)
    try:
        future.result()
    except KeyboardInterrupt:
        future.cancel()
        logger.info("Pub/Sub listener stopped")


def _run_simulation_mode() -> None:
    logger.warning(
        "GCP_PROJECT_ID is empty — running in local simulation mode. "
        "Paste a TriggerEvent JSON object per line on stdin (Ctrl+D / Ctrl+Z then Enter to exit)."
    )
    # Windows' default stdin codec (cp1252 here) mangles UTF-8 text piped in
    # from PowerShell into mojibake before it ever reaches json.loads.
    # utf-8-sig decodes as UTF-8 and also transparently strips a leading BOM,
    # which PowerShell's pipe-to-native-process path can add.
    sys.stdin.reconfigure(encoding="utf-8-sig")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            trigger = TriggerEvent.from_dict(data)
            run_pipeline(trigger)
        except Exception as e:
            logger.warning("Failed to process simulated trigger: {}", e)


def start_listener() -> None:
    project_id = os.getenv("GCP_PROJECT_ID", "")
    if project_id:
        _run_pubsub_mode(project_id)
    else:
        _run_simulation_mode()


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    start_listener()

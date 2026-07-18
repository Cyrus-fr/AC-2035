"""U8 — shared scaffolding for the five reproducible APT attack scenarios.

Deterministic by construction: every timestamp derives from BASE_TRIGGER_TIME,
every IP / pod / token_id is a fixed constant, and event_ids are stamped
sequentially. No randomness, no uuid4, no wall-clock — the same scenario emits
byte-identical telemetry on any machine, so U9 can measure backtrace accuracy
against a known ground truth objectively.

Telemetry is built with the real `collector.normalizer.make_event`, so a
scenario timeline is schema-identical to one the live collector would produce.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from collector.normalizer import NormalizedEvent, make_event
from collector.pubsub_listener import TriggerEvent

# Fixed reference instant — every scenario timestamp is an offset from this.
BASE_TRIGGER_TIME = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)

# Documentation-range attacker IP (RFC 5737) and a fixed internal pod fleet.
ATTACKER_IP = "198.51.100.77"
NAMESPACE = "prod"
CF_COLO = "IAD"
INSIDER_IP = "10.20.9.100"  # an internal principal with no external origin

# Ordered pod fleet: name -> internal IP. Scenarios traverse a prefix of these.
PODS: dict[str, str] = {
    "checkout-api-9c4f2": "10.20.4.15",
    "inventory-worker-3a1d8": "10.20.4.22",
    "notifications-svc-77b2e": "10.20.4.31",
    "billing-worker-1f0a4": "10.20.4.44",
    "reporting-svc-5d9c3": "10.20.4.57",
}
POD_NAMES = list(PODS)
POD_IPS = list(PODS.values())

TOKEN_READ_MSG = "env var read: HONEYTOKEN_API_TOKEN"


@dataclass
class GroundTruth:
    """The objectively-correct reconstruction for a scenario. U9 scores the
    engine's output against this."""

    token_id: str
    entry_ip: Optional[str]
    path_nodes: list = field(default_factory=list)  # ordered: entry -> pods -> token pod
    strategy: str = "cf_ray"        # cf_ray / vpc_flow / temporal_lineage / unattributed
    unattributed: bool = False
    tamper_detected: bool = False
    dwell_time_seconds: int = 0
    expected_confidence: str = "low"

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "entry_ip": self.entry_ip,
            "path_nodes": list(self.path_nodes),
            "strategy": self.strategy,
            "unattributed": self.unattributed,
            "tamper_detected": self.tamper_detected,
            "dwell_time_seconds": self.dwell_time_seconds,
            "expected_confidence": self.expected_confidence,
        }


def cf_ray(colo: str = CF_COLO, seq: int = 1) -> str:
    """A stable, deterministic CF-Ray id (no randomness)."""
    return f"{seq:016x}-{colo}"


def ts(seconds_before: int) -> datetime:
    return BASE_TRIGGER_TIME - timedelta(seconds=seconds_before)


def cf_event(seconds_before: int, src_ip: str, pod: str, ray: str,
             uri: str = "/api/v1/checkout", status: int = 200) -> NormalizedEvent:
    """A Cloudflare access event that reached `pod` (the controlled-scenario
    pod is set explicitly; the real Logpull fetcher can't know it)."""
    return make_event(
        event_type="cloudflare_access",
        source="cloudflare",
        timestamp=ts(seconds_before),
        raw={"RayID": ray, "ClientIP": src_ip, "ClientRequestURI": uri,
             "EdgeResponseStatus": status},
        src_ip=src_ip,
        pod_name=pod,
        namespace=NAMESPACE,
        cf_ray=ray,
        dst_port=443,
    )


def vpc_event(seconds_before: int, src_ip: str, dst_ip: str,
              src_port: int = 51000, dst_port: int = 443) -> NormalizedEvent:
    return make_event(
        event_type="vpc_flow",
        source="vpc_flow",
        timestamp=ts(seconds_before),
        raw={"connection": {"src_ip": src_ip, "dest_ip": dst_ip,
                            "src_port": src_port, "dest_port": dst_port, "protocol": 6},
             "bytes_sent": 2048, "packets_sent": 12},
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def k8s_event(seconds_before: int, pod: str, message: str,
              process: str = "python3") -> NormalizedEvent:
    return make_event(
        event_type="k8s_log",
        source="gcp_logging",
        timestamp=ts(seconds_before),
        raw={"message": message},
        pod_name=pod,
        namespace=NAMESPACE,
        process_name=process,
    )


def tamper_event(seconds_before: int, pod: str,
                 missing=("ac2035_file_open",)) -> NormalizedEvent:
    """An eBPF tamper marker in the timeline — the shape the U4 watchdog
    publishes when a hook is detached. Lets a scenario exercise U4's
    integration with backtrace without a live kernel."""
    return make_event(
        event_type="ebpf_tamper",
        source="ebpf",
        timestamp=ts(seconds_before),
        raw={"type": "ebpf_tamper", "severity": "critical", "missing_hooks": list(missing)},
        pod_name=pod,
        namespace=NAMESPACE,
    )


def make_trigger(token_id: str, pod: str, pid: int = 4242,
                 token_type: str = "api_token") -> TriggerEvent:
    return TriggerEvent(
        token_id=token_id,
        token_type=token_type,
        trigger_time=BASE_TRIGGER_TIME.isoformat(),
        pod_name=pod,
        pod_namespace=NAMESPACE,
        process_name="python3",
        pid=pid,
        source="ebpf",
    )


def finalize(token_id: str, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Sort by timestamp and stamp deterministic event_ids (make_event assigns
    a uuid4), so a scenario emits identical telemetry on every run."""
    events = sorted(events, key=lambda e: e.timestamp)
    for i, e in enumerate(events):
        e.event_id = f"{token_id}-evt-{i:02d}"
    return events

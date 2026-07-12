"""Local simulation of a full Phase 2 collection cycle: generates a fake
TriggerEvent, generates a mixed batch of fake NormalizedEvents (k8s_log,
vpc_flow, cloudflare_access) with realistic IPs/timestamps/CF-Ray values,
merges/sorts them into a timeline via normalizer.py, saves it, and prints
it — without touching GCP or Cloudflare.
"""

from __future__ import annotations

import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from collector.normalizer import NormalizedEvent, build_timeline, make_event, save_timeline
from collector.pubsub_listener import TriggerEvent

_POD_NAMES = ["payments-api-7d9f6", "orders-worker-2b8c1", "auth-svc-5f3a9"]
_NAMESPACES = ["default", "prod", "staging"]
_PROCESS_NAMES = ["python3", "curl", "bash", "node", "java"]
_CF_COLOS = ["SJC", "LHR", "FRA", "SIN", "IAD", "NRT"]
_K8S_MESSAGES = [
    "env var read: HONEYTOKEN_API_TOKEN",
    "process exec: /bin/sh -c 'env | grep HONEYTOKEN'",
    "file access: /var/run/secrets/kubernetes.io/serviceaccount/token",
    "outbound connection attempt",
]
_HTTP_PATHS = ["/api/v1/login", "/api/v1/data", "/health", "/api/v1/upload"]


def _rand_public_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _rand_internal_ip() -> str:
    return f"10.20.{random.randint(0, 15)}.{random.randint(2, 254)}"


def _rand_cf_ray() -> str:
    return f"{uuid.uuid4().hex[:16]}-{random.choice(_CF_COLOS)}"


def _fake_trigger_event() -> TriggerEvent:
    return TriggerEvent(
        token_id=str(uuid.uuid4()),
        token_type=random.choice(["gcp_key", "gcp_api_key", "db_connection", "api_token"]),
        trigger_time=datetime.now(timezone.utc).isoformat(),
        pod_name=random.choice(_POD_NAMES),
        pod_namespace=random.choice(_NAMESPACES),
        process_name=random.choice(_PROCESS_NAMES),
        pid=random.randint(1000, 65000),
        source=random.choice(["falco", "ebpf"]),
    )


def _fake_k8s_log_event(trigger: TriggerEvent, ts: datetime) -> NormalizedEvent:
    return make_event(
        event_type="k8s_log",
        source="gcp_logging",
        timestamp=ts,
        raw={"message": random.choice(_K8S_MESSAGES), "severity": random.choice(["INFO", "WARNING", "NOTICE"])},
        pod_name=trigger.pod_name,
        namespace=trigger.pod_namespace,
        process_name=trigger.process_name,
    )


def _fake_vpc_flow_event(trigger: TriggerEvent, ts: datetime) -> NormalizedEvent:
    src_ip, dst_ip = _rand_internal_ip(), _rand_public_ip()
    src_port, dst_port = random.randint(1024, 65535), random.choice([443, 80, 22, 8443])

    return make_event(
        event_type="vpc_flow",
        source="vpc_flow",
        timestamp=ts,
        raw={
            "connection": {
                "src_ip": src_ip, "dest_ip": dst_ip,
                "src_port": src_port, "dest_port": dst_port,
                "protocol": 6,
            },
            "bytes_sent": random.randint(64, 8192),
            "packets_sent": random.randint(1, 20),
            "start_time": ts.isoformat(),
            "end_time": (ts + timedelta(seconds=random.randint(1, 30))).isoformat(),
        },
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def _fake_cloudflare_event(trigger: TriggerEvent, ts: datetime) -> NormalizedEvent:
    client_ip, ray_id = _rand_public_ip(), _rand_cf_ray()

    return make_event(
        event_type="cloudflare_access",
        source="cloudflare",
        timestamp=ts,
        raw={
            "ClientIP": client_ip,
            "RayID": ray_id,
            "ClientRequestMethod": random.choice(["GET", "POST"]),
            "ClientRequestURI": random.choice(_HTTP_PATHS),
            "EdgeResponseStatus": random.choice([200, 401, 403, 404, 500]),
            "EdgeStartTimestamp": ts.isoformat(),
        },
        src_ip=client_ip,
        cf_ray=ray_id,
    )


_GENERATORS = [_fake_k8s_log_event, _fake_vpc_flow_event, _fake_cloudflare_event]


def simulate() -> list[NormalizedEvent]:
    trigger = _fake_trigger_event()
    trigger_dt = trigger.trigger_datetime
    window_start = trigger_dt - timedelta(minutes=30)

    logger.info(
        "Simulating trigger for token {} (pod={}/{})",
        trigger.token_id, trigger.pod_namespace, trigger.pod_name,
    )

    n_events = random.randint(20, 30)
    raw_events = [
        random.choice(_GENERATORS)(trigger, window_start + timedelta(seconds=random.uniform(0, 30 * 60)))
        for _ in range(n_events)
    ]

    timeline = build_timeline(raw_events)
    path = save_timeline(trigger.token_id, timeline)

    logger.info("Simulated timeline: {} events -> {}", len(timeline), path)
    print(json.dumps([e.to_dict() for e in timeline], indent=2))
    return timeline


if __name__ == "__main__":
    simulate()

"""Writes a normalized event timeline (Phase 2 output) into Neo4j as nodes
and edges.

Every node is MERGEd (idempotent — re-ingesting the same timeline never
creates duplicate Pods / ExternalIPs / Honeytokens). Every edge is CREATEd
(each event is a distinct occurrence in time, so re-ingesting the same
timeline is expected to add duplicate edges — only node de-duplication is
a correctness requirement here).

NormalizedEvent has no token_id field (a token is a property of the
*trigger* that kicked off the Phase 2 pipeline, not of any individual
log/flow/CF entry), so the Honeytoken node is merged once per ingestion
run from the token_id/token_type the caller already has in hand, and
every k8s_log event with a process_name gets an ACCESSED edge to it.
"""

from __future__ import annotations

import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Optional, Union

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger
from neo4j import Driver

from collector.normalizer import NormalizedEvent
from graph.schema import get_driver

BATCH_SIZE = 100

_CLOUDFLARE_EDGE = """
MERGE (ip:ExternalIP {address: $src_ip})
MERGE (pod:Pod {name: $pod_name, namespace: $namespace})
CREATE (ip)-[:CONNECTED_TO $props]->(pod)
"""

_CLOUDFLARE_IP_ONLY = "MERGE (ip:ExternalIP {address: $src_ip})"

_VPC_FLOW_EDGE = """
MERGE (a:ExternalIP {address: $src_ip})
MERGE (b:ExternalIP {address: $dst_ip})
CREATE (a)-[:CONNECTED_TO $props]->(b)
"""

_K8S_POD_TOUCH = """
MERGE (pod:Pod {name: $pod_name, namespace: $namespace})
SET pod.last_seen = $timestamp
"""

_K8S_ACCESSED_EDGE = """
MERGE (pod:Pod {name: $pod_name, namespace: $namespace})
SET pod.last_seen = $timestamp
MERGE (ht:Honeytoken {token_id: $token_id})
CREATE (pod)-[:ACCESSED $props]->(ht)
"""

_HONEYTOKEN_MERGE = """
MERGE (ht:Honeytoken {token_id: $token_id})
SET ht.token_type = $token_type,
    ht.pod = $pod_name,
    ht.namespace = $namespace
"""


def _as_dict(event: Union[NormalizedEvent, dict]) -> dict:
    return asdict(event) if is_dataclass(event) else event


def _clean(props: dict) -> dict:
    """Neo4j has no null property value — passing one through means "don't
    set this property", not "set it to null", so strip them before they
    reach the driver."""
    return {k: v for k, v in props.items() if v is not None}


def _write_cloudflare(tx, event: dict) -> None:
    src_ip = event.get("src_ip")
    if not src_ip:
        logger.debug("cloudflare_access event {} has no src_ip — skipping", event.get("event_id"))
        return

    pod_name = event.get("pod_name")
    if pod_name:
        props = _clean(
            {
                "timestamp": event.get("timestamp"),
                "cf_ray": event.get("cf_ray"),
                "src_port": event.get("src_port"),
                "dst_port": event.get("dst_port"),
                "protocol": "https",
                "event_id": event.get("event_id"),
            }
        )
        tx.run(
            _CLOUDFLARE_EDGE,
            src_ip=src_ip,
            pod_name=pod_name,
            namespace=event.get("namespace"),
            props=props,
        )
    else:
        # Real cloudflare_logs.py fetches don't carry pod_name (Cloudflare
        # has no notion of which pod served the request) — still record the
        # external IP so it exists for later CF-Ray correlation elsewhere.
        tx.run(_CLOUDFLARE_IP_ONLY, src_ip=src_ip)


def _write_vpc_flow(tx, event: dict) -> None:
    src_ip, dst_ip = event.get("src_ip"), event.get("dst_ip")
    if not src_ip or not dst_ip:
        logger.debug("vpc_flow event {} missing src_ip/dst_ip — skipping", event.get("event_id"))
        return

    raw = event.get("raw") or {}
    conn = raw.get("connection") or {}
    props = _clean(
        {
            "timestamp": event.get("timestamp"),
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port"),
            "protocol": conn.get("protocol"),
            "bytes_sent": raw.get("bytes_sent"),
            "packets": raw.get("packets_sent"),
            "event_id": event.get("event_id"),
        }
    )
    tx.run(_VPC_FLOW_EDGE, src_ip=src_ip, dst_ip=dst_ip, props=props)


def _write_k8s_log(tx, event: dict, token_id: Optional[str]) -> None:
    pod_name = event.get("pod_name")
    if not pod_name:
        logger.debug("k8s_log event {} has no pod_name — skipping", event.get("event_id"))
        return

    namespace = event.get("namespace")
    process_name = event.get("process_name")

    if process_name and token_id:
        raw = event.get("raw") or {}
        props = _clean(
            {
                "timestamp": event.get("timestamp"),
                "process_name": process_name,
                "pid": raw.get("pid"),
                "event_id": event.get("event_id"),
            }
        )
        tx.run(
            _K8S_ACCESSED_EDGE,
            pod_name=pod_name,
            namespace=namespace,
            timestamp=event.get("timestamp"),
            token_id=token_id,
            props=props,
        )
    else:
        tx.run(_K8S_POD_TOUCH, pod_name=pod_name, namespace=namespace, timestamp=event.get("timestamp"))


_SIMPLE_WRITERS = {
    "cloudflare_access": _write_cloudflare,
    "vpc_flow": _write_vpc_flow,
}


def _write_batch(tx, batch: list[dict], token_id: Optional[str]) -> None:
    for event in batch:
        event_type = event.get("event_type")
        try:
            if event_type == "k8s_log":
                _write_k8s_log(tx, event, token_id)
            elif event_type in _SIMPLE_WRITERS:
                _SIMPLE_WRITERS[event_type](tx, event)
            else:
                logger.warning("Unknown event_type {!r} on event {} — skipping", event_type, event.get("event_id"))
        except Exception as e:
            # One malformed event (e.g. a pod_name reused across two
            # namespaces, which fights the name-only Pod uniqueness
            # constraint) shouldn't sink the rest of the batch.
            logger.warning("Failed to write event {}: {}", event.get("event_id"), e)


def ingest_events(
    events: list[Union[NormalizedEvent, dict]],
    *,
    driver: Optional[Driver] = None,
    token_id: Optional[str] = None,
    token_type: Optional[str] = None,
) -> int:
    """Write a normalized event timeline into Neo4j in batches of at most
    `BATCH_SIZE` events per transaction. If `token_id` is given, a
    Honeytoken node is merged up front (pod/namespace derived from the
    first event that has them) and k8s_log events with a process_name get
    an ACCESSED edge to it. Returns the number of events processed."""
    driver = driver or get_driver()
    dicts = [_as_dict(e) for e in events]

    if token_id:
        pod_name = next((e.get("pod_name") for e in dicts if e.get("pod_name")), None)
        namespace = next((e.get("namespace") for e in dicts if e.get("namespace")), None)
        with driver.session() as session:
            session.run(
                _HONEYTOKEN_MERGE,
                token_id=token_id,
                token_type=token_type or "unknown",
                pod_name=pod_name,
                namespace=namespace,
            )

    for i in range(0, len(dicts), BATCH_SIZE):
        batch = dicts[i : i + BATCH_SIZE]
        with driver.session() as session:
            session.execute_write(_write_batch, batch, token_id)

    logger.info(
        "Ingested {} events into Neo4j{}",
        len(dicts),
        f" (token {token_id})" if token_id else "",
    )
    return len(dicts)

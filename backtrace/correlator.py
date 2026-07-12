"""Deterministic correlation logic — the heart of AC-2035's attribution.

CF-Ray headers (from Cloudflare) and VPC Flow Log connections are used as
hard correlation keys to bridge the *external* view of an attacker (a
request that reached the edge) with the *internal* view (which pod the
connection actually landed on, which process touched the token). When no
CF-Ray can be tied to the trigger pod, callers fall back to temporal
proximity.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from graph import queries
from graph.schema import get_driver

CFRAY_WINDOW_MINUTES = 5
VPC_WINDOW_MINUTES = 30


def _parse(ts: Optional[str]) -> Optional[datetime]:
    """Parse an ISO timestamp into a tz-aware UTC datetime, or None."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def find_cf_ray(trigger_event, timeline: list[dict], window_minutes: int = CFRAY_WINDOW_MINUTES) -> Optional[str]:
    """Find the CF-Ray of the Cloudflare request that reached the trigger
    pod within `window_minutes` before the trigger. Returns None (→ callers
    fall back to temporal correlation) if nothing matches.

    A Cloudflare event with no pod destination (the real Logpull fetcher
    can't know which pod served a request) is not rejected on the pod test
    — only events that name a *different* pod are ruled out."""
    trigger_dt = trigger_event.trigger_datetime
    window_start = trigger_dt - timedelta(minutes=window_minutes)

    candidates = []
    for event in timeline:
        if event.get("event_type") != "cloudflare_access":
            continue
        cf_ray = event.get("cf_ray")
        if not cf_ray:
            continue
        ts = _parse(event.get("timestamp"))
        if ts is None or not (window_start <= ts <= trigger_dt):
            continue
        pod = event.get("pod_name")
        if pod is not None and pod != trigger_event.pod_name:
            continue
        candidates.append((ts, cf_ray))

    if not candidates:
        logger.info(
            "No CF-Ray reached pod {} within {}min before trigger — falling back to temporal correlation",
            trigger_event.pod_name, window_minutes,
        )
        return None

    candidates.sort()
    cf_ray = candidates[-1][1]  # closest to the trigger
    logger.info("CF-Ray correlated to trigger pod {}: {}", trigger_event.pod_name, cf_ray)
    return cf_ray


def trace_entry(cf_ray: Optional[str], timeline: list[dict], driver=None) -> Optional[str]:
    """Resolve the external IP that sent the request carrying `cf_ray`,
    checking the in-memory timeline first, then the Neo4j graph."""
    if not cf_ray:
        return None

    for event in timeline:
        if event.get("event_type") == "cloudflare_access" and event.get("cf_ray") == cf_ray:
            ip = event.get("src_ip")
            if ip:
                logger.info("Entry IP {} traced from timeline for CF-Ray {}", ip, cf_ray)
                return ip

    try:
        rows = queries.find_cf_ray_chain(cf_ray, driver=driver or get_driver())
        for row in rows:
            ip = dict(row["ip"]).get("address")
            if ip:
                logger.info("Entry IP {} traced from graph for CF-Ray {}", ip, cf_ray)
                return ip
    except Exception as e:
        logger.warning("Graph CF-Ray lookup failed for {}: {}", cf_ray, e)

    logger.info("Could not resolve an entry IP for CF-Ray {}", cf_ray)
    return None


def temporal_entry(trigger_event, timeline: list[dict], window_minutes: int = VPC_WINDOW_MINUTES) -> Optional[str]:
    """Fallback used when CF-Ray correlation fails: the earliest external
    source IP seen in the window before the trigger."""
    trigger_dt = trigger_event.trigger_datetime
    window_start = trigger_dt - timedelta(minutes=window_minutes)

    best: Optional[tuple[datetime, str]] = None
    for event in timeline:
        if event.get("event_type") not in ("cloudflare_access", "vpc_flow"):
            continue
        ip = event.get("src_ip")
        if not ip:
            continue
        ts = _parse(event.get("timestamp"))
        if ts is None or not (window_start <= ts <= trigger_dt):
            continue
        if best is None or ts < best[0]:
            best = (ts, ip)

    if best:
        logger.info("Temporal fallback entry IP: {}", best[1])
        return best[1]
    logger.info("No temporal entry IP could be inferred")
    return None


def find_vpc_chain(src_ip: str, trigger_time: datetime, timeline: Optional[list[dict]] = None, driver=None,
                   window_minutes: int = VPC_WINDOW_MINUTES) -> list[str]:
    """Ordered list of IPs forming the VPC Flow lateral-movement chain that
    involves `src_ip` in the window before the trigger."""
    end = trigger_time.astimezone(timezone.utc)
    start = end - timedelta(minutes=window_minutes)

    try:
        rows = queries.find_vpc_flow_chain(
            src_ip,
            start.isoformat(timespec="microseconds"),
            end.isoformat(timespec="microseconds"),
            driver=driver or get_driver(),
        )
    except Exception as e:
        logger.warning("VPC flow chain query failed for {}: {}", src_ip, e)
        rows = []

    edges = []
    for row in rows:
        edges.append((dict(row["r"]).get("timestamp") or "", dict(row["a"]).get("address"),
                      dict(row["b"]).get("address")))
    edges.sort(key=lambda e: e[0])

    chain: list[str] = []
    for _ts, a, b in edges:
        for ip in (a, b):
            if ip and ip not in chain:
                chain.append(ip)
    if src_ip:
        if src_ip in chain:
            chain.remove(src_ip)
        chain.insert(0, src_ip)

    logger.info("VPC lateral chain from {}: {} node(s)", src_ip, len(chain))
    return chain

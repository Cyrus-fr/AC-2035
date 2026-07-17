"""Forensic Backtrace Engine — the orchestrator.

Given a honeytoken trigger, reconstructs the attacker's path from external
entry point to the stolen token by correlating the Neo4j graph on CF-Ray
and VPC Flow keys, scoring each hop, and tagging MITRE ATT&CK techniques.
Returns a single structured AttackObject.
"""

from __future__ import annotations

import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger
from neo4j.exceptions import AuthError, ServiceUnavailable

from backtrace import correlator, mitre_tagger, path_finder, scorer
from backtrace.correlator import _parse
from backtrace.mitre_tagger import MitreTechnique
from backtrace.path_finder import PathHop
from backtrace.scorer import ScoredPath
from collector.normalizer import load_timeline
from collector.pubsub_listener import TriggerEvent
from graph.ingestor import ingest_events
from graph.schema import get_driver


@dataclass
class AttackObject:
    token_id: str
    entry_point: Optional[str] = None
    movement_path: list[PathHop] = field(default_factory=list)
    dwell_time_seconds: int = 0
    blast_radius: list[str] = field(default_factory=list)
    confidence: str = "low"
    mitre_techniques: list[MitreTechnique] = field(default_factory=list)
    all_paths: list[ScoredPath] = field(default_factory=list)
    reconstructed_at: str = ""
    # U7 — first-class "we couldn't attribute this" state, distinct from a
    # low-confidence reconstruction.
    unattributed: bool = False

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "entry_point": self.entry_point,
            "movement_path": [h.to_dict() for h in self.movement_path],
            "dwell_time_seconds": self.dwell_time_seconds,
            "blast_radius": self.blast_radius,
            "confidence": self.confidence,
            "mitre_techniques": [t.to_dict() for t in self.mitre_techniques],
            "all_paths": [p.to_dict() for p in self.all_paths],
            "reconstructed_at": self.reconstructed_at,
            "unattributed": self.unattributed,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _blast_radius(timeline: list[dict]) -> list[str]:
    """Every pod that showed activity in the correlation window — a
    superset heuristic for the attack's blast radius."""
    return sorted({e["pod_name"] for e in timeline if e.get("pod_name")})


def _dwell_seconds(hops: list[PathHop], trigger_dt: Optional[datetime]) -> int:
    times = [t for t in (_parse(h.timestamp) for h in hops) if t]
    if not times or trigger_dt is None:
        return 0
    return max(0, int((trigger_dt - min(times)).total_seconds()))


def _empty(token_id: str, reconstructed_at: str, blast_radius: Optional[list[str]] = None) -> AttackObject:
    return AttackObject(
        token_id=token_id,
        entry_point=None,
        movement_path=[],
        dwell_time_seconds=0,
        blast_radius=blast_radius or [],
        confidence="low",
        mitre_techniques=[],
        all_paths=[],
        reconstructed_at=reconstructed_at,
    )


def run_backtrace(trigger_event, driver=None) -> AttackObject:
    """Reconstruct the attack behind `trigger_event`. Never raises on
    missing data or an unreachable graph — degrades to a low-confidence
    AttackObject with an empty movement path instead."""
    if isinstance(trigger_event, dict):
        trigger_event = TriggerEvent.from_dict(trigger_event)

    token_id = trigger_event.token_id
    trigger_dt = trigger_event.trigger_datetime
    reconstructed_at = _now_iso()
    driver = driver or get_driver()

    try:
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError) as e:
        logger.error("Neo4j unreachable — cannot backtrace token {}: {}", token_id, e)
        return _empty(token_id, reconstructed_at)

    # 1. Load timeline for this token (Phase 2 output).
    timeline = load_timeline(token_id)
    blast_radius = _blast_radius(timeline)
    if not timeline:
        logger.warning("No timeline for token {} — returning empty attack object", token_id)
        return _empty(token_id, reconstructed_at, blast_radius)

    # 2. Ingest into Neo4j (idempotent — MERGE on nodes).
    ingest_events(timeline, driver=driver, token_id=token_id, token_type=trigger_event.token_type)

    # 3-4. Correlate via the priority strategy chain (U7): CF-Ray -> VPC Flow ->
    # temporal clustering + process lineage -> unattributed. An unattributed
    # result short-circuits — we refuse to force a low-confidence path.
    result = correlator.correlate_entry(trigger_event, timeline, driver=driver)
    if result.unattributed:
        logger.warning("Token {} unattributed — no correlation strategy matched", token_id)
        attack = _empty(token_id, reconstructed_at, blast_radius)
        attack.unattributed = True
        return attack
    entry_ip = result.entry_ip
    if result.chain and len(result.chain) > 1:
        logger.info("VPC lateral chain ({}): {}", result.strategy, " -> ".join(result.chain))

    # 5. Candidate paths from the graph.
    paths = path_finder.find_paths(token_id, entry_ip, driver=driver)

    # 6. Score + rank.
    scored = scorer.score_paths(paths, timeline, trigger_time=trigger_dt)
    best = scored[0] if scored else None
    movement_path = best.hops if best else []

    # 7. MITRE tagging on the best path.
    techniques = mitre_tagger.tag_path(best, blast_radius=blast_radius)

    # 8. Assemble.
    entry_point = entry_ip or (movement_path[0].from_node if movement_path else None)
    attack = AttackObject(
        token_id=token_id,
        entry_point=entry_point,
        movement_path=movement_path,
        dwell_time_seconds=_dwell_seconds(movement_path, trigger_dt),
        blast_radius=blast_radius,
        confidence=best.overall_confidence if best else "low",
        mitre_techniques=techniques,
        all_paths=scored,
        reconstructed_at=reconstructed_at,
    )
    logger.info(
        "Backtrace for token {} complete: entry={}, {} hop(s), confidence={}",
        token_id, entry_point, len(movement_path), attack.confidence,
    )
    return attack

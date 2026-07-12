"""Confidence scoring for reconstructed paths.

Each hop is graded by the strength of the correlation evidence behind it:
a CF-Ray match *and* a corroborating VPC Flow entry is the gold standard
(HIGH); a VPC Flow (or bare CF-Ray) match alone is MEDIUM; mere temporal
proximity inside the 30-minute window is LOW. A path is only as trustworthy
as its weakest hop, so overall confidence is the minimum across hops.
"""

from __future__ import annotations

import sys
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from backtrace.correlator import _parse
from backtrace.path_finder import PathHop, extract_hops

_RANK = {"high": 3, "medium": 2, "low": 1}
TEMPORAL_WINDOW_MINUTES = 30


@dataclass
class ScoredPath:
    hops: list[PathHop] = field(default_factory=list)
    overall_confidence: str = "low"
    score_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "hops": [h.to_dict() for h in self.hops],
            "overall_confidence": self.overall_confidence,
            "score_reason": self.score_reason,
        }


def _cfray_match(hop: PathHop, timeline: list[dict]) -> bool:
    if not hop.cf_ray:
        return False
    return any(
        e.get("event_type") == "cloudflare_access" and e.get("cf_ray") == hop.cf_ray for e in timeline
    )


def _vpc_match(hop: PathHop, timeline: list[dict]) -> bool:
    endpoints = {hop.from_node, hop.to_node}
    for e in timeline:
        if e.get("event_type") != "vpc_flow":
            continue
        if e.get("src_ip") in endpoints or e.get("dst_ip") in endpoints:
            return True
    return False


def _temporal_match(hop: PathHop, trigger_dt) -> bool:
    ts = _parse(hop.timestamp)
    if ts is None or trigger_dt is None:
        return hop.timestamp is not None
    return (trigger_dt - timedelta(minutes=TEMPORAL_WINDOW_MINUTES)) <= ts <= trigger_dt


def _score_hop(hop: PathHop, timeline: list[dict], trigger_dt) -> str:
    cf = _cfray_match(hop, timeline)
    vpc = _vpc_match(hop, timeline)
    if cf and vpc:
        return "high"
    if vpc or cf:
        return "medium"
    if _temporal_match(hop, trigger_dt):
        return "low"
    return "low"


def _reason(hops: list[PathHop], overall: str) -> str:
    if not hops:
        return "No reconstructable hops; defaulting to low confidence."
    counts = {"high": 0, "medium": 0, "low": 0}
    for h in hops:
        counts[h.confidence] = counts.get(h.confidence, 0) + 1
    parts = [f"{counts[l]} {l}" for l in ("high", "medium", "low") if counts[l]]
    return (
        f"{len(hops)} hop(s): " + ", ".join(parts)
        + f". Overall = {overall} (bounded by the weakest hop)."
    )


def score_paths(paths, timeline: list[dict], trigger_time=None) -> list[ScoredPath]:
    """Score and rank candidate paths (HIGH first). `paths` are raw Neo4j
    paths straight from path_finder.find_paths; hops are extracted here."""
    scored: list[ScoredPath] = []
    for raw_path in paths:
        hops = extract_hops(raw_path)
        for hop in hops:
            hop.confidence = _score_hop(hop, timeline, trigger_time)
        overall = min((h.confidence for h in hops), key=lambda c: _RANK[c]) if hops else "low"
        scored.append(ScoredPath(hops=hops, overall_confidence=overall, score_reason=_reason(hops, overall)))

    scored.sort(key=lambda sp: _RANK[sp.overall_confidence], reverse=True)
    logger.info("Scored {} path(s): {}", len(scored), [sp.overall_confidence for sp in scored])
    return scored

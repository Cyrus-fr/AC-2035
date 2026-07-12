"""Backtrace-specific path reconstruction — a thin layer over
graph/queries.py that turns raw Neo4j paths into the PathHop objects the
scorer and MITRE tagger work with.
"""

from __future__ import annotations

import sys
from dataclasses import asdict, dataclass
from pathlib import Path as _Path
from typing import Optional

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from loguru import logger

from graph import queries
from graph.schema import get_driver


@dataclass
class PathHop:
    from_node: str
    to_node: str
    edge_type: str
    timestamp: Optional[str] = None
    confidence: Optional[str] = None
    cf_ray: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _node_name(node) -> str:
    """Human-facing identifier for a graph node, keyed off its label so an
    ExternalIP reads as its address, a Pod as its name, etc."""
    props = dict(node)
    labels = set(node.labels)
    if "ExternalIP" in labels:
        return props.get("address", "?")
    if "Pod" in labels:
        return props.get("name", "?")
    if "Honeytoken" in labels:
        return props.get("token_id", "?")
    if "Technique" in labels:
        return props.get("mitre_id", "?")
    # Identity / Service and anything else key on `name`.
    return props.get("name") or props.get("address") or props.get("token_id") or "?"


def extract_hops(neo4j_path) -> list[PathHop]:
    """Convert a raw Neo4j path into an ordered list of PathHop objects.
    path.nodes and path.relationships are traversal-ordered, so
    nodes[i]->nodes[i+1] are exactly the endpoints of relationships[i]."""
    nodes = list(neo4j_path.nodes)
    rels = list(neo4j_path.relationships)
    hops: list[PathHop] = []
    for i, rel in enumerate(rels):
        hops.append(
            PathHop(
                from_node=_node_name(nodes[i]),
                to_node=_node_name(nodes[i + 1]),
                edge_type=rel.type,
                timestamp=rel.get("timestamp"),
                cf_ray=rel.get("cf_ray"),
            )
        )
    return hops


def find_paths(token_id: str, entry_ip: Optional[str] = None, max_hops: int = 10, driver=None) -> list:
    """Return raw Neo4j paths from any ExternalIP to the honeytoken,
    optionally filtered to those that start at `entry_ip`. When entry_ip is
    None (CF-Ray correlation failed), every candidate path is returned for
    the scorer to rank on temporal proximity."""
    driver = driver or get_driver()
    paths = queries.find_paths_to_token(token_id, max_hops=max_hops, driver=driver)

    if not entry_ip:
        return paths

    filtered = []
    for p in paths:
        start = list(p.nodes)[0]
        if dict(start).get("address") == entry_ip:
            filtered.append(p)
    logger.info("find_paths: {} of {} candidate path(s) start from entry IP {}", len(filtered), len(paths), entry_ip)
    return filtered

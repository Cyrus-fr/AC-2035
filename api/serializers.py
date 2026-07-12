"""Neo4j → Cytoscape.js serialization for the dashboard.

`neo4j_to_cytoscape` reshapes graph/queries.get_full_graph() output into the
node/edge form Cytoscape.js consumes; `attack_object_to_cytoscape` renders a
single reconstructed attack path with every node/edge flagged
`attack_path: true` for highlighting.
"""

from __future__ import annotations

import re
from typing import Any

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _as_dict(obj: Any) -> dict:
    return obj.to_dict() if hasattr(obj, "to_dict") else obj


def _display_label(props: dict, node_type: str | None, node_id: str | None) -> str:
    return (
        props.get("name")
        or props.get("address")
        or props.get("token_id")
        or node_type
        or node_id
        or "?"
    )


def neo4j_to_cytoscape(neo4j_result: dict) -> dict:
    """Transform get_full_graph() output — whose node `data` carries `id`,
    `label` (the Neo4j label, i.e. the node type) and flattened properties —
    into typed Cytoscape node/edge elements."""
    nodes = []
    for node in neo4j_result.get("nodes", []):
        data = dict(node.get("data", {}))
        node_id = data.pop("id", None)
        node_type = data.pop("label", None)  # get_full_graph sets label = first Neo4j label
        properties = data  # whatever remains are the node's properties
        nodes.append({
            "data": {
                "id": node_id,
                "label": _display_label(properties, node_type, node_id),
                "type": node_type,
                "properties": properties,
            }
        })

    edges = []
    for edge in neo4j_result.get("edges", []):
        data = dict(edge.get("data", {}))
        edges.append({
            "data": {
                "id": data.get("id"),
                "source": data.get("source"),
                "target": data.get("target"),
                "type": data.get("type"),
                "timestamp": data.get("timestamp"),
                "confidence": data.get("confidence"),
                "cf_ray": data.get("cf_ray"),
            }
        })

    return {"nodes": nodes, "edges": edges}


def _infer_type(name: str) -> str:
    if not name:
        return "Unknown"
    if _IPV4_RE.match(name):
        return "ExternalIP"
    if _UUID_RE.match(name):
        return "Honeytoken"
    return "Pod"


def attack_object_to_cytoscape(attack_object: Any) -> dict:
    """Render an AttackObject's movement_path as a highlighted Cytoscape
    sub-graph (every element flagged attack_path=true)."""
    ao = _as_dict(attack_object)
    hops = ao.get("movement_path", []) or []

    nodes: dict[str, dict] = {}
    edges = []
    for i, hop in enumerate(hops):
        for name in (hop.get("from_node"), hop.get("to_node")):
            if name and name not in nodes:
                nodes[name] = {
                    "data": {
                        "id": name,
                        "label": name,
                        "type": _infer_type(name),
                        "attack_path": True,
                        "properties": {},
                    }
                }
        edges.append({
            "data": {
                "id": f"attack-{i}",
                "source": hop.get("from_node"),
                "target": hop.get("to_node"),
                "type": hop.get("edge_type"),
                "timestamp": hop.get("timestamp"),
                "confidence": hop.get("confidence"),
                "cf_ray": hop.get("cf_ray"),
                "attack_path": True,
            }
        })

    return {"nodes": list(nodes.values()), "edges": edges}

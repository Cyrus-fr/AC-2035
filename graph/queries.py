"""Cypher query library for the AC-2035 attribution graph. Phase 4 (the
Backtrace Engine) calls these directly instead of writing its own Cypher.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger
from neo4j import Driver

from graph.schema import get_driver

_CF_RAY_CHAIN = """
MATCH (ip:ExternalIP)-[r:CONNECTED_TO]->(pod:Pod)
WHERE r.cf_ray = $cf_ray
RETURN ip, r, pod
"""

_VPC_FLOW_CHAIN = """
MATCH (a)-[r:CONNECTED_TO]->(b)
WHERE r.timestamp >= $start_time AND r.timestamp <= $end_time
  AND (a.address = $src_ip OR b.address = $src_ip)
RETURN a, r, b
ORDER BY r.timestamp ASC
"""

_ALL_NODES = "MATCH (n) RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS props"

_ALL_EDGES = """
MATCH (a)-[r]->(b)
RETURN elementId(r) AS id, type(r) AS type, elementId(a) AS source,
       elementId(b) AS target, properties(r) AS props
"""

_CLEAR_GRAPH = "MATCH (n) DETACH DELETE n"


def find_paths_to_token(token_id: str, max_hops: int = 10, driver: Optional[Driver] = None) -> list:
    """Shortest-first paths from any ExternalIP to the given Honeytoken,
    walking CONNECTED_TO / ACCESSED / MOVED_TO edges (MOVED_TO isn't
    written by the current ingestor but is reserved for lateral-movement
    edges a later phase may add)."""
    driver = driver or get_driver()
    # Cypher variable-length relationship bounds must be literal integers,
    # not query parameters — max_hops is coerced to int first so nothing
    # but a number ever reaches the interpolated query string.
    max_hops = int(max_hops)
    query = (
        "MATCH p = (ip:ExternalIP)-[:CONNECTED_TO|ACCESSED|MOVED_TO*1.."
        f"{max_hops}]->(t:Honeytoken {{token_id: $token_id}}) "
        "RETURN p ORDER BY length(p) ASC LIMIT 10"
    )
    with driver.session() as session:
        paths = [record["p"] for record in session.run(query, token_id=token_id)]
    logger.info("find_paths_to_token({}): {} path(s) found", token_id, len(paths))
    return paths


def find_cf_ray_chain(cf_ray: str, driver: Optional[Driver] = None) -> list[dict]:
    driver = driver or get_driver()
    with driver.session() as session:
        rows = [dict(record) for record in session.run(_CF_RAY_CHAIN, cf_ray=cf_ray)]
    logger.info("find_cf_ray_chain({}): {} match(es)", cf_ray, len(rows))
    return rows


def find_vpc_flow_chain(
    src_ip: str, start_time: str, end_time: str, driver: Optional[Driver] = None
) -> list[dict]:
    driver = driver or get_driver()
    with driver.session() as session:
        rows = [
            dict(record)
            for record in session.run(_VPC_FLOW_CHAIN, src_ip=src_ip, start_time=start_time, end_time=end_time)
        ]
    logger.info("find_vpc_flow_chain({}): {} match(es)", src_ip, len(rows))
    return rows


def get_full_graph(driver: Optional[Driver] = None) -> dict:
    """Return the whole graph as {nodes: [...], edges: [...]}, shaped for
    the Cytoscape.js serializer Phase 7 will build."""
    driver = driver or get_driver()
    with driver.session() as session:
        nodes = [
            {"data": {"id": rec["id"], "label": (rec["labels"] or [None])[0], **rec["props"]}}
            for rec in session.run(_ALL_NODES)
        ]
        edges = [
            {
                "data": {
                    "id": rec["id"],
                    "type": rec["type"],
                    "source": rec["source"],
                    "target": rec["target"],
                    **rec["props"],
                }
            }
            for rec in session.run(_ALL_EDGES)
        ]
    logger.info("get_full_graph(): {} node(s), {} edge(s)", len(nodes), len(edges))
    return {"nodes": nodes, "edges": edges}


def clear_graph(driver: Optional[Driver] = None) -> None:
    """Delete every node and relationship. Used by tests and simulate
    scripts to reset state between runs."""
    driver = driver or get_driver()
    with driver.session() as session:
        session.run(_CLEAR_GRAPH)
    logger.info("Cleared all nodes and relationships from the graph")

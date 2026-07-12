"""Graph routes — full graph, per-token attack path, stats, and clear, all
in Cytoscape.js form."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException
from loguru import logger

from api import serializers
from api.models import ClearResponse, GraphResponse, GraphStats
from api.websocket import broadcast_alert, make_alert
from backtrace.path_finder import extract_hops
from graph import queries
from graph.schema import get_driver

router = APIRouter(prefix="/api/graph", tags=["graph"])


def _full_graph() -> dict:
    return queries.get_full_graph(get_driver())


@router.get("/full", response_model=GraphResponse)
async def full_graph() -> dict:
    try:
        raw = await asyncio.to_thread(_full_graph)
    except Exception as e:
        logger.warning("get_full_graph failed: {}", e)
        raise HTTPException(status_code=500, detail=f"Graph query failed: {e}")
    return serializers.neo4j_to_cytoscape(raw)


@router.get("/attack/{token_id}", response_model=GraphResponse)
async def attack_path(token_id: str) -> dict:
    try:
        paths = await asyncio.to_thread(queries.find_paths_to_token, token_id, 10, get_driver())
    except Exception as e:
        logger.warning("find_paths_to_token failed for {}: {}", token_id, e)
        raise HTTPException(status_code=500, detail=f"Attack path query failed: {e}")

    if not paths:
        raise HTTPException(status_code=404, detail=f"No attack path found for token {token_id}")

    # Shortest path first — render it as a highlighted movement path.
    hops = extract_hops(paths[0])
    attack_like = {"movement_path": [h.to_dict() for h in hops]}
    return serializers.attack_object_to_cytoscape(attack_like)


@router.get("/stats", response_model=GraphStats)
async def graph_stats() -> GraphStats:
    try:
        raw = await asyncio.to_thread(_full_graph)
    except Exception as e:
        logger.warning("graph stats query failed: {}", e)
        raise HTTPException(status_code=500, detail=f"Graph stats query failed: {e}")

    def _count(label: str) -> int:
        return sum(1 for n in raw.get("nodes", []) if n.get("data", {}).get("label") == label)

    return GraphStats(
        node_count=len(raw.get("nodes", [])),
        edge_count=len(raw.get("edges", [])),
        honeytoken_count=_count("Honeytoken"),
        external_ip_count=_count("ExternalIP"),
        pod_count=_count("Pod"),
    )


@router.post("/clear", response_model=ClearResponse)
async def clear_graph() -> ClearResponse:
    try:
        await asyncio.to_thread(queries.clear_graph, get_driver())
    except Exception as e:
        logger.warning("clear_graph failed: {}", e)
        raise HTTPException(status_code=500, detail=f"Clear graph failed: {e}")

    await broadcast_alert(make_alert("system_info", data={"message": "Graph cleared"}))
    return ClearResponse(cleared=True)

"""End-to-end Phase 3 demo: loads the most recently saved Phase 2 timeline,
applies the Neo4j schema, ingests the timeline as a graph, then runs a
path query and prints node/edge totals.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
from loguru import logger
from neo4j.exceptions import AuthError, ServiceUnavailable

from collector.normalizer import TIMELINES_DIR, load_timeline
from graph import queries
from graph.ingestor import ingest_events
from graph.schema import apply_schema, get_driver


def _latest_token_id() -> Optional[str]:
    files = sorted(TIMELINES_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not files:
        return None
    # Filenames are `{token_id}_{timestamp}.json`; token_id (uuid4) and the
    # timestamp suffix both contain no underscores, so the last
    # underscore-separated segment is always the timestamp.
    return files[-1].stem.rsplit("_", 1)[0]


def _lookup_token_type(token_id: str) -> str:
    """Best-effort cross-reference against the Phase 1 registry, which is
    the only place token_type is actually persisted — a saved timeline's
    events carry no token_id/token_type at all (see graph/ingestor.py)."""
    try:
        from deployer import registry

        for token in registry.get_all():
            if token.get("token_id") == token_id:
                return token.get("token_type", "unknown")
    except Exception as e:
        logger.debug("Could not look up token_type from deployer registry: {}", e)
    return "unknown"


def main() -> None:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")

    token_id = _latest_token_id()
    if not token_id:
        logger.error("No timelines found in {} — run collector/simulate_trigger.py first", TIMELINES_DIR)
        sys.exit(1)

    events = load_timeline(token_id)
    if not events:
        logger.error("Timeline for token {} is empty", token_id)
        sys.exit(1)
    logger.info("Loaded timeline for token {} ({} events)", token_id, len(events))

    driver = get_driver()
    try:
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError) as e:
        logger.error("Cannot reach Neo4j: {}", e)
        sys.exit(1)

    apply_schema(driver)

    token_type = _lookup_token_type(token_id)
    ingest_events(events, driver=driver, token_id=token_id, token_type=token_type)

    paths = queries.find_paths_to_token(token_id)
    logger.info("find_paths_to_token: {} path(s) found", len(paths))
    for path in paths:
        logger.info("  path: {} node(s), {} relationship(s)", len(path.nodes), len(path.relationships))

    graph = queries.get_full_graph(driver)
    logger.info("Graph totals: {} node(s), {} edge(s)", len(graph["nodes"]), len(graph["edges"]))


if __name__ == "__main__":
    main()

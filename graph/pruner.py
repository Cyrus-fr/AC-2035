"""U6 — graph pruning + runaway-size alerting.

Keeps the attribution graph bounded: deletes relationships (and the nodes they
orphan) older than a retention window, and raises a CRITICAL alert if the node
count runs away (a sign of buggy or hostile ingestion). Delete counts come from
the query summary counters, so we never RETURN a just-deleted variable.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger
from neo4j import Driver

from graph.schema import get_driver

DEFAULT_RETENTION_DAYS = 7
DEFAULT_NODE_THRESHOLD = 10_000

# Relationships carry an ISO-8601 `timestamp` (sorts lexicographically), so a
# string compare against the cutoff is a correct age filter.
_DELETE_OLD_RELS = "MATCH ()-[r]->() WHERE r.timestamp IS NOT NULL AND r.timestamp < $cutoff DELETE r"
_DELETE_ORPHANS = "MATCH (n) WHERE NOT (n)--() DELETE n"
_COUNT_NODES = "MATCH (n) RETURN count(n) AS c"


def prune_old(days: int = DEFAULT_RETENTION_DAYS, driver: Optional[Driver] = None) -> dict:
    """Delete relationships older than `days`, then delete any node left with no
    relationships. Returns {relationships_deleted, nodes_deleted}."""
    driver = driver or get_driver()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with driver.session() as session:
        rels = session.run(_DELETE_OLD_RELS, cutoff=cutoff).consume().counters.relationships_deleted
        nodes = session.run(_DELETE_ORPHANS).consume().counters.nodes_deleted
    logger.info("Pruned {} relationship(s) older than {} and {} orphan node(s)", rels, cutoff, nodes)
    return {"relationships_deleted": rels, "nodes_deleted": nodes}


def node_count(driver: Optional[Driver] = None) -> int:
    driver = driver or get_driver()
    with driver.session() as session:
        return session.run(_COUNT_NODES).single()["c"]


def check_node_count(threshold: int = DEFAULT_NODE_THRESHOLD, driver: Optional[Driver] = None) -> bool:
    """Alert (CRITICAL + best-effort notifier) if the graph exceeds `threshold`
    nodes — a sign of runaway ingestion. Returns True iff the alert fired."""
    count = node_count(driver)
    if count <= threshold:
        logger.info("Graph node count {} within threshold {}", count, threshold)
        return False
    logger.critical("Graph node count {} EXCEEDS threshold {} — possible runaway ingestion", count, threshold)
    try:
        import notifier

        notifier.notify(
            "graph_runaway", token_id="",
            summary=f"AC-2035 graph exceeded {threshold} nodes ({count})",
            fields={"node_count": count, "threshold": threshold},
        )
    except Exception as e:  # notifier is non-fatal
        logger.warning("Runaway notifier hook failed (non-fatal): {}", e)
    return True


def run(days: int = DEFAULT_RETENTION_DAYS, threshold: int = DEFAULT_NODE_THRESHOLD,
        driver: Optional[Driver] = None) -> dict:
    driver = driver or get_driver()
    result = prune_old(days, driver)
    result["node_count"] = node_count(driver)
    result["over_threshold"] = check_node_count(threshold, driver)
    return result


def main() -> int:
    import argparse

    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    parser = argparse.ArgumentParser(description="AC-2035 Neo4j graph pruner")
    parser.add_argument("--days", type=int,
                        default=int(os.getenv("PRUNE_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)))
    parser.add_argument("--threshold", type=int, default=DEFAULT_NODE_THRESHOLD)
    parser.add_argument("--schedule", action="store_true",
                        help="run every PRUNE_INTERVAL_HOURS via APScheduler instead of once")
    args = parser.parse_args()

    try:
        driver = get_driver()
        driver.verify_connectivity()
    except Exception as e:
        logger.error("Neo4j unreachable — cannot prune: {}", e)
        return 1

    if not args.schedule:
        logger.info("Prune result: {}", run(args.days, args.threshold, driver))
        return 0

    from apscheduler.schedulers.blocking import BlockingScheduler

    hours = float(os.getenv("PRUNE_INTERVAL_HOURS", "24"))
    sched = BlockingScheduler(timezone="UTC")
    sched.add_job(lambda: run(args.days, args.threshold), "interval", hours=hours,
                  next_run_time=datetime.now(timezone.utc))
    logger.info("Pruner scheduled every {}h; Ctrl+C to stop", hours)
    try:
        sched.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Pruner scheduler stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

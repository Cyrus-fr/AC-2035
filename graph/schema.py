"""Applies Neo4j schema constraints and indexes for the AC-2035
attribution graph, and owns the singleton driver every other graph/
module connects through.

Every statement uses IF NOT EXISTS — safe to run any number of times.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger
from neo4j import Driver, GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:ExternalIP) REQUIRE n.address IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Pod) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Service) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Identity) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Honeytoken) REQUIRE n.token_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Technique) REQUIRE n.mitre_id IS UNIQUE",
]

# Relationship-property indexes use Neo4j 5.x's `()-[e:TYPE]-()` syntax
# (the `(e:CONNECTED_TO)` node-pattern form isn't valid for a relationship).
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (n:ExternalIP) ON (n.address)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Pod) ON (n.name, n.namespace)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[e:CONNECTED_TO]-() ON (e.timestamp)",
]

_driver: Optional[Driver] = None


def get_driver() -> Driver:
    """Return a singleton Neo4j driver built from NEO4J_URI / NEO4J_USER /
    NEO4J_PASSWORD in the environment."""
    global _driver
    if _driver is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "")
        _driver = GraphDatabase.driver(uri, auth=(user, password))
    return _driver


def apply_schema(driver: Optional[Driver] = None) -> None:
    """Apply all constraints and indexes. Idempotent — safe to call on
    every startup."""
    driver = driver or get_driver()
    with driver.session() as session:
        for stmt in _CONSTRAINTS:
            session.run(stmt)
        for stmt in _INDEXES:
            session.run(stmt)
    logger.info("Applied {} constraints and {} indexes", len(_CONSTRAINTS), len(_INDEXES))


def main() -> None:
    driver = get_driver()
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    try:
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError) as e:
        logger.error("Cannot reach Neo4j at {}: {}", uri, e)
        sys.exit(1)

    apply_schema(driver)


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    main()

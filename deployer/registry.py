"""SQLite registry of deployed honeytokens.

Tracks every token's lifecycle (active -> triggered/rotated/expired). Never
touches token_value beyond storing/returning it verbatim — callers are
responsible for not logging it.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from loguru import logger

DB_PATH = Path(__file__).resolve().parent / "registry.db"

# rotator.py's APScheduler background thread and the Typer CLI can both hit
# this file at once (e.g. `status` reading while a scheduled rotation
# writes). A generous busy-timeout makes sqlite3 wait for the other side's
# lock to clear instead of raising `database is locked`.
_BUSY_TIMEOUT_SECS = 30.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token_id TEXT PRIMARY KEY,
    token_type TEXT NOT NULL,
    token_value TEXT NOT NULL,
    target_pod TEXT,
    target_namespace TEXT,
    secret_manager_path TEXT,
    injected_at TEXT,
    last_rotated_at TEXT,
    status TEXT NOT NULL DEFAULT 'active'
);
"""


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=_BUSY_TIMEOUT_SECS)
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def register(token: dict) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO tokens (
                token_id, token_type, token_value, target_pod, target_namespace,
                secret_manager_path, injected_at, last_rotated_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token["token_id"],
                token["token_type"],
                token["token_value"],
                token.get("target_pod"),
                token.get("target_namespace"),
                token.get("secret_manager_path"),
                token.get("injected_at") or datetime.now(timezone.utc).isoformat(),
                token.get("last_rotated_at"),
                token.get("status", "active"),
            ),
        )
    logger.info("Registered token {} (type={}) in registry", token["token_id"], token["token_type"])


def get_active_tokens() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM tokens WHERE status = 'active'").fetchall()
    return [dict(row) for row in rows]


def mark_triggered(token_id: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE tokens SET status = 'triggered' WHERE token_id = ?", (token_id,))
    logger.info("Token {} marked as triggered", token_id)


def mark_rotated(token_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        conn.execute(
            "UPDATE tokens SET status = 'rotated', last_rotated_at = ? WHERE token_id = ?",
            (now, token_id),
        )
    logger.info("Token {} marked as rotated", token_id)


def get_all() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM tokens ORDER BY injected_at").fetchall()
    return [dict(row) for row in rows]

"""Auto-rotation for active honeytokens.

Each rotation keeps the same target (pod/namespace) and the same Secret
Manager secret (a new version, not a new secret) and the same pod env var
key (keyed by token_type) — only the value changes, so the credential's
apparent identity stays stable while its content rotates, same as a real
rotated credential would look to anyone watching.
"""

from __future__ import annotations

import os

from apscheduler.schedulers.blocking import BlockingScheduler
from loguru import logger

from . import generator, injector, registry


def _rotate_token(old_token: dict) -> None:
    new_token = generator.generate(
        old_token["token_type"],
        target_pod=old_token.get("target_pod"),
        target_namespace=old_token.get("target_namespace"),
    )

    secret_manager_path = old_token.get("secret_manager_path")
    if secret_manager_path:
        injector.rotate_secret_manager(new_token, secret_manager_path)

    pod = old_token.get("target_pod")
    namespace = old_token.get("target_namespace")
    if pod and namespace:
        injector.inject_pod_env(pod, namespace, new_token)

    registry.mark_rotated(old_token["token_id"])

    new_token_dict = new_token.to_dict()
    new_token_dict["secret_manager_path"] = secret_manager_path
    registry.register(new_token_dict)

    logger.info("Rotated token {} -> {}", old_token["token_id"], new_token.token_id)


def rotate_all() -> int:
    """Rotate every active token. Returns the number successfully rotated."""
    active = registry.get_active_tokens()
    rotated = 0
    for token in active:
        try:
            _rotate_token(token)
            rotated += 1
        except Exception as e:
            logger.warning("Rotation failed for token {}: {}", token["token_id"], e)

    logger.info("Rotation cycle complete: {}/{} token(s) rotated", rotated, len(active))
    return rotated


def build_scheduler() -> BlockingScheduler:
    """Build (but do not start) a scheduler that runs rotate_all() on the
    ROTATION_INTERVAL_HOURS interval (default 24h)."""
    interval_hours = int(os.getenv("ROTATION_INTERVAL_HOURS", "24"))
    scheduler = BlockingScheduler()
    scheduler.add_job(rotate_all, "interval", hours=interval_hours, id="ac2035_rotation")
    logger.info("Rotation scheduler configured: every {}h", interval_hours)
    return scheduler

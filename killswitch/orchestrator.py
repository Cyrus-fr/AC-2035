"""Kill-switch coordinator.

`execute(attack_object, mode)` fires the three actions — GCP IAM revoke,
Cloudflare IP block, Zitadel session kill — in parallel (auto mode) or
stashes the attack for later `approve(pending_id)` (manual mode). Every
outcome is written to a JSON audit log.

Status semantics: all three succeed → executed; some succeed, some fail →
partial; all fail → failed. One failing action never sinks the others.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from killswitch import AUDIT_DIR, ActionResult, KillSwitchResult, _as_dict, make_action, now_iso
from killswitch import cloudflare, gcp_iam, zitadel

# (action_type, handler) in a fixed order so results are always reported
# GCP → Cloudflare → Zitadel regardless of which finishes first.
_HANDLERS = [
    ("gcp_iam_revoke", gcp_iam.revoke),
    ("cloudflare_ip_block", cloudflare.block_ip),
    ("zitadel_session_kill", zitadel.kill_sessions),
]

# Manual-mode attacks awaiting analyst approval, keyed by pending_id.
_PENDING: dict[str, dict] = {}


def pending_map() -> dict[str, dict]:
    """Snapshot of attacks awaiting approval (pending_id → attack dict).
    Read-only accessor for the API layer."""
    return dict(_PENDING)


def _invoke(action_type, handler, ao) -> ActionResult:
    """Run one handler, capturing its worker thread + duration for the
    parallel-dispatch audit trail. Defends against a handler raising even
    though each is meant to be graceful."""
    tname = threading.current_thread().name
    start = time.perf_counter()
    try:
        result = handler(ao)
    except Exception as e:  # pragma: no cover — handlers shouldn't raise
        logger.error("[{}] {} crashed: {}", tname, action_type, e)
        result = make_action(action_type, "", False, f"handler crashed: {e}")
    dur_ms = (time.perf_counter() - start) * 1000
    logger.info("[{}] {} -> success={} ({:.1f}ms)", tname, result.action_type, result.success, dur_ms)
    return result


def _fire_all(ao) -> list[ActionResult]:
    """Fire all three actions concurrently and return results in fixed
    handler order."""
    results: list[ActionResult] = [None] * len(_HANDLERS)  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=len(_HANDLERS), thread_name_prefix="killswitch") as pool:
        futures = {
            pool.submit(_invoke, action_type, handler, ao): idx
            for idx, (action_type, handler) in enumerate(_HANDLERS)
        }
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return results


def _status(actions: list[ActionResult]) -> str:
    succeeded = sum(1 for a in actions if a.success)
    if succeeded == len(actions):
        return "executed"
    if succeeded == 0:
        return "failed"
    return "partial"


def _save_audit(result: KillSwitchResult) -> Path:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    # Microsecond precision so several fires for one token in the same second
    # (e.g. an auto run plus a manual approve) never overwrite each other.
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = AUDIT_DIR / f"{result.attack_object_token_id}_{ts}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    logger.info("Audit log written: {}", path)
    return path


def _execute_now(ao: dict, pending_id: str, triggered_by: str) -> KillSwitchResult:
    token_id = ao.get("token_id", "")
    logger.info("Firing kill-switch for token {} ({} mode)", token_id, triggered_by)
    actions = _fire_all(ao)
    result = KillSwitchResult(
        pending_id=pending_id,
        status=_status(actions),
        attack_object_token_id=token_id,
        actions=actions,
        executed_at=now_iso(),
        triggered_by=triggered_by,
    )
    result.audit_path = str(_save_audit(result))
    logger.info(
        "Kill-switch for token {} → {} ({}/{} actions succeeded)",
        token_id, result.status, sum(1 for a in actions if a.success), len(actions),
    )
    return result


def execute(attack_object, mode: str = "auto") -> KillSwitchResult:
    """Auto mode fires all three actions in parallel immediately. Manual
    mode stores the attack and returns a pending result to be approved."""
    ao = _as_dict(attack_object)
    token_id = ao.get("token_id", "")
    pending_id = str(uuid.uuid4())

    if mode == "manual":
        _PENDING[pending_id] = ao
        logger.info("Kill-switch for token {} staged as pending ({})", token_id, pending_id)
        result = KillSwitchResult(
            pending_id=pending_id,
            status="pending",
            attack_object_token_id=token_id,
            actions=[],
            executed_at=None,
            triggered_by="analyst",
        )
        result.audit_path = str(_save_audit(result))
        return result

    return _execute_now(ao, pending_id, triggered_by="auto")


def approve(pending_id: str) -> KillSwitchResult:
    """Fire a previously staged (manual-mode) kill-switch."""
    ao = _PENDING.pop(pending_id, None)
    if ao is None:
        logger.warning("No pending kill-switch found for id {}", pending_id)
        return KillSwitchResult(
            pending_id=pending_id,
            status="failed",
            attack_object_token_id="",
            actions=[],
            executed_at=now_iso(),
            triggered_by="analyst",
        )
    return _execute_now(ao, pending_id, triggered_by="analyst")

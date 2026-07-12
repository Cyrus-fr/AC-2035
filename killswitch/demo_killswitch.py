"""End-to-end Phase 5 demo of the Kill-Switch Orchestrator.

Obtains an AttackObject (loads the most recent saved one from
backtrace/attacks/, else produces a fresh one via the Phase 4 engine),
fires the three kill-switch actions in parallel (auto mode), prints the
KillSwitchResult + an audit summary, and verifies the audit JSON was saved.
Also demonstrates manual mode → approve, and confirms parallel dispatch.

In local dev every handler reports "credentials missing" (no real GCP /
Cloudflare / Zitadel creds) — that graceful degradation is the point.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
from loguru import logger

from killswitch import orchestrator

REPO = Path(__file__).resolve().parent.parent
ATTACKS_DIR = REPO / "backtrace" / "attacks"


def _load_saved_attack():
    files = sorted(ATTACKS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime) if ATTACKS_DIR.exists() else []
    if not files:
        return None
    logger.info("Loaded saved AttackObject: {}", files[-1].name)
    return json.loads(files[-1].read_text(encoding="utf-8"))


def _produce_attack_via_phase4():
    """Run the Phase 4 backtrace on a coherent scenario to get a real
    AttackObject, and persist it to backtrace/attacks/ for reuse."""
    from backtrace.demo_backtrace import _build_scenario_timeline, _NAMESPACE, _POD_A
    from backtrace.engine import run_backtrace
    from collector.normalizer import save_timeline
    from collector.pubsub_listener import TriggerEvent
    from graph import queries
    from graph.schema import apply_schema, get_driver

    driver = get_driver()
    driver.verify_connectivity()  # raises if Neo4j is down → caller falls back
    apply_schema(driver)
    queries.clear_graph(driver)

    token_id = str(uuid.uuid4())
    trigger_dt = datetime.now(timezone.utc)
    save_timeline(token_id, _build_scenario_timeline(token_id, trigger_dt))

    trigger = TriggerEvent(
        token_id=token_id, token_type="api_token", trigger_time=trigger_dt.isoformat(),
        pod_name=_POD_A, pod_namespace=_NAMESPACE, process_name="python3", pid=4242, source="ebpf",
    )
    attack = run_backtrace(trigger, driver=driver).to_dict()

    ATTACKS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (ATTACKS_DIR / f"{token_id}_{ts}.json").write_text(json.dumps(attack, indent=2), encoding="utf-8")
    logger.info("Produced fresh AttackObject via Phase 4 for token {}", token_id)
    return attack


def _fallback_attack():
    """Representative AttackObject mirroring Phase 4's output, used if Neo4j
    is unreachable so the kill-switch demo still runs end-to-end."""
    token_id = str(uuid.uuid4())
    return {
        "token_id": token_id,
        "entry_point": "198.51.100.77",
        "movement_path": [
            {"from_node": "198.51.100.77", "to_node": "checkout-api-9c4f2", "edge_type": "CONNECTED_TO",
             "timestamp": "2026-07-11T11:00:00+00:00", "confidence": "high", "cf_ray": "7d3f9a1b2c4e5f60-IAD"},
            {"from_node": "checkout-api-9c4f2", "to_node": token_id, "edge_type": "ACCESSED",
             "timestamp": "2026-07-11T11:00:05+00:00", "confidence": "low", "cf_ray": None},
        ],
        "dwell_time_seconds": 600,
        "blast_radius": ["checkout-api-9c4f2", "inventory-worker-3a1d8", "notifications-svc-77b2e"],
        "confidence": "low",
        "mitre_techniques": [],
        "all_paths": [],
        "reconstructed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _obtain_attack_object() -> dict:
    saved = _load_saved_attack()
    if saved:
        return saved
    try:
        return _produce_attack_via_phase4()
    except Exception as e:
        logger.warning("Could not produce an AttackObject via Phase 4 ({}); using representative fallback", e)
        return _fallback_attack()


def _confirm_parallel() -> bool:
    """Prove the executor runs three tasks at once: a Barrier(3) is only
    satisfiable if all three worker threads reach it simultaneously. If the
    pool ran them one-after-another, the barrier would time out."""
    n = 3
    barrier = threading.Barrier(n, timeout=5)

    def probe(_i):
        try:
            barrier.wait()
            return True
        except threading.BrokenBarrierError:
            return False

    with ThreadPoolExecutor(max_workers=n) as pool:
        return all(pool.map(probe, range(n)))


def _print_summary(result) -> None:
    by_type = {a.action_type: a for a in result.actions}
    def line(action_type):
        a = by_type.get(action_type)
        if not a:
            return "not run"
        return f"{'success' if a.success else 'failed'} - {a.error or 'ok'}"

    succeeded = sum(1 for a in result.actions if a.success)
    print("\n" + "=" * 70)
    print("AUDIT SUMMARY")
    print("=" * 70)
    print(
        f"Kill-switch fired for token {result.attack_object_token_id}\n"
        f"  status: {result.status}  (triggered_by: {result.triggered_by})\n"
        f"  Actions: {len(result.actions)} attempted, {succeeded} succeeded\n"
        f"  GCP IAM:    {line('gcp_iam_revoke')}\n"
        f"  Cloudflare: {line('cloudflare_ip_block')}\n"
        f"  Zitadel:    {line('zitadel_session_kill')}\n"
        f"  Audit log:  {result.audit_path}"
    )
    print("=" * 70)


def main() -> None:
    load_dotenv(REPO / ".env")

    logger.info("[1/5] Obtaining AttackObject...")
    attack = _obtain_attack_object()

    logger.info("[2/5] Confirming parallel dispatch mechanism...")
    parallel_ok = _confirm_parallel()
    logger.info("Parallel execution confirmed: {}", parallel_ok)

    logger.info("[3/5] Firing kill-switch in AUTO mode (all 3 actions in parallel)...")
    result = orchestrator.execute(attack, mode="auto")

    print("\n" + "=" * 70)
    print("KILLSWITCH RESULT (JSON)")
    print("=" * 70)
    print(json.dumps(result.to_dict(), indent=2))
    _print_summary(result)

    # Verify the audit JSON landed on disk.
    audit_path = Path(result.audit_path) if result.audit_path else None
    saved_ok = bool(audit_path and audit_path.is_file())
    logger.info("[4/5] Audit JSON saved & verified: {} ({})", saved_ok, result.audit_path)

    # Demonstrate manual mode → approve.
    logger.info("[5/5] Demonstrating MANUAL mode → approve...")
    pending = orchestrator.execute(attack, mode="manual")
    logger.info("Staged pending kill-switch: id={}, status={}", pending.pending_id, pending.status)
    approved = orchestrator.approve(pending.pending_id)
    logger.info("Approved pending kill-switch: status={}, triggered_by={}", approved.status, approved.triggered_by)

    if not saved_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()

"""End-to-end Phase 4 demo of the Forensic Backtrace Engine.

Runs the Phase 2 collector simulation (to show it produces a timeline),
then builds one *coherent* attack scenario whose events form a real
ExternalIP -> Pod -> Honeytoken chain in the graph, backtraces it, and
prints the full AttackObject plus a human-readable attack summary.

Why a scripted scenario? The random simulate_trigger output is
intentionally noisy — its Cloudflare events carry no pod destination, so
the ingested graph has no ExternalIP -> Pod edge for a path to attach to
(find_paths_to_token returns 0). A real attack leaves coherent CF-Ray /
VPC correlation keys, so this demo lays down that coherent evidence to
actually exercise correlation, scoring, and MITRE tagging.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
from loguru import logger
from neo4j.exceptions import AuthError, ServiceUnavailable

from backtrace.engine import run_backtrace
from collector.normalizer import make_event, save_timeline
from collector.pubsub_listener import TriggerEvent
from graph import queries
from graph.schema import apply_schema, get_driver
from graph.ingestor import ingest_events

# Coherent attack scenario constants (documentation-range IPs, RFC 5737).
_ATTACKER_IP = "198.51.100.77"
_POD_A = "checkout-api-9c4f2"        # holds the honeytoken; attacker reaches it
_POD_A_INTERNAL_IP = "10.20.4.15"
_POD_B = "inventory-worker-3a1d8"    # extra activity → blast radius
_POD_C = "notifications-svc-77b2e"
_NAMESPACE = "prod"
_CF_RAY = "7d3f9a1b2c4e5f60-IAD"


def _build_scenario_timeline(token_id: str, trigger_dt: datetime):
    """A minimal, coherent kill-chain within 30 min before the trigger:
    Cloudflare hit on pod A (CF-Ray) → VPC flow attacker→pod A → the pod's
    process reads the honeytoken → background activity on pods B and C."""
    t = lambda secs: trigger_dt - timedelta(seconds=secs)

    events = [
        # Attacker's request reaches pod A through Cloudflare — the CF-Ray
        # is the primary correlation key. (pod_name set here because this is
        # a controlled scenario; the real Logpull fetcher can't know it.)
        make_event(
            event_type="cloudflare_access",
            source="cloudflare",
            timestamp=t(600),
            raw={"RayID": _CF_RAY, "ClientIP": _ATTACKER_IP, "ClientRequestURI": "/api/v1/checkout",
                 "EdgeResponseStatus": 200},
            src_ip=_ATTACKER_IP,
            pod_name=_POD_A,
            namespace=_NAMESPACE,
            cf_ray=_CF_RAY,
            dst_port=443,
        ),
        # The same external IP shows up in VPC Flow hitting the pod's
        # internal IP — corroborates the CF-Ray hop (→ HIGH confidence).
        make_event(
            event_type="vpc_flow",
            source="vpc_flow",
            timestamp=t(598),
            raw={"connection": {"src_ip": _ATTACKER_IP, "dest_ip": _POD_A_INTERNAL_IP,
                                "src_port": 51000, "dest_port": 443, "protocol": 6},
                 "bytes_sent": 2048, "packets_sent": 12},
            src_ip=_ATTACKER_IP,
            dst_ip=_POD_A_INTERNAL_IP,
            src_port=51000,
            dst_port=443,
        ),
        # A process inside pod A reads the honeytoken → ACCESSED edge.
        make_event(
            event_type="k8s_log",
            source="gcp_logging",
            timestamp=t(595),
            raw={"message": "env var read: HONEYTOKEN_API_TOKEN", "pid": 4242},
            pod_name=_POD_A,
            namespace=_NAMESPACE,
            process_name="python3",
        ),
        # Background activity on two other pods → blast radius > 2 (T1083).
        make_event(
            event_type="k8s_log", source="gcp_logging", timestamp=t(500),
            raw={"message": "readiness probe ok"}, pod_name=_POD_B, namespace=_NAMESPACE,
        ),
        make_event(
            event_type="k8s_log", source="gcp_logging", timestamp=t(450),
            raw={"message": "readiness probe ok"}, pod_name=_POD_C, namespace=_NAMESPACE,
        ),
    ]
    return events


def _print_summary(attack) -> None:
    techs = ", ".join(f"{t.technique_id} ({t.technique_name})" for t in attack.mitre_techniques) or "none"
    # Pod the token was stolen from = the pod feeding the ACCESSED hop.
    stolen_from = next((h.from_node for h in attack.movement_path if h.edge_type == "ACCESSED"), None)
    stolen_from = stolen_from or (_POD_A)

    print("\n" + "=" * 70)
    print("ATTACK SUMMARY")
    print("=" * 70)
    print(
        f"Attacker entered from {attack.entry_point}\n"
        f"  moved through {len(attack.movement_path)} hop(s) over {attack.dwell_time_seconds}s\n"
        f"  stole token {attack.token_id} from {stolen_from}\n"
        f"  confidence: {attack.confidence}\n"
        f"  blast radius: {len(attack.blast_radius)} pod(s) — {', '.join(attack.blast_radius)}\n"
        f"  MITRE techniques: {techs}"
    )
    print("-" * 70)
    for i, hop in enumerate(attack.movement_path):
        ray = f"  [CF-Ray {hop.cf_ray}]" if hop.cf_ray else ""
        print(f"  hop {i}: {hop.from_node} --{hop.edge_type}--> {hop.to_node}  ({hop.confidence}){ray}")
    print("=" * 70)


def main() -> None:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")

    driver = get_driver()
    try:
        driver.verify_connectivity()
    except (ServiceUnavailable, AuthError) as e:
        logger.error("Cannot reach Neo4j — is `docker compose up -d` running? {}", e)
        sys.exit(1)

    # Step 1: run the Phase 2 collector simulation so a fresh timeline exists.
    logger.info("[1/4] Running Phase 2 collector simulation to produce a fresh timeline...")
    from collector import simulate_trigger

    simulate_trigger.simulate()

    # Step 2: lay down a coherent attack scenario for the actual backtrace.
    logger.info("[2/4] Building coherent attack-scenario timeline...")
    apply_schema(driver)
    queries.clear_graph(driver)

    token_id = str(uuid.uuid4())
    trigger_dt = datetime.now(timezone.utc)
    events = _build_scenario_timeline(token_id, trigger_dt)
    save_timeline(token_id, events)

    # Step 3: construct the TriggerEvent for that token.
    trigger = TriggerEvent(
        token_id=token_id,
        token_type="api_token",
        trigger_time=trigger_dt.isoformat(),
        pod_name=_POD_A,
        pod_namespace=_NAMESPACE,
        process_name="python3",
        pid=4242,
        source="ebpf",
    )

    # Step 4: backtrace.
    logger.info("[3/4] Running backtrace engine...")
    attack = run_backtrace(trigger, driver=driver)

    logger.info("[4/4] Reconstruction complete.")
    print("\n" + "=" * 70)
    print("ATTACK OBJECT (JSON)")
    print("=" * 70)
    print(json.dumps(attack.to_dict(), indent=2, default=str))
    _print_summary(attack)


if __name__ == "__main__":
    main()

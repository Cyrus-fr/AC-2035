"""End-to-end Phase 6 demo of the custom eBPF honeytoken detector.

Two modes:

  --simulate (default)  works anywhere (Windows included): fabricates a
      honeytoken_event, runs it through the real decode → TriggerEvent →
      Pub/Sub pipeline, and prints the result. No root, no kernel.

  --real                Linux + root + kernel 5.7+ only: compiles the eBPF
      object, loads it, watches a test file's inode, touches the file to
      trigger detection, prints the captured event, then unloads.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
from loguru import logger

from collector.pubsub_listener import TriggerEvent
from detector.telemetry_agent.agent import TelemetryAgent

REPO = Path(__file__).resolve().parent.parent


def run_simulation() -> int:
    logger.info("=== Phase 6 detector demo — SIMULATION mode ===")
    agent = TelemetryAgent(bpf_handle=None, pubsub_topic=os.getenv("PUBSUB_TRIGGER_TOPIC", "honeytoken-triggers"))

    token_id = "demo-" + os.urandom(4).hex()
    logger.info("Simulating a honeytoken file access for token {}", token_id)

    trigger = agent.simulate_event(
        token_id=token_id, token_type=3, pod_name="checkout-api-9c4f2",
        namespace="prod", comm="python3", pid=4242,
    )

    print("\n" + "=" * 70)
    print("TRIGGER EVENT (what ships to Pub/Sub as JSON)")
    print("=" * 70)
    print(json.dumps(trigger, indent=2))

    # Verify it's a valid Phase 2 TriggerEvent (round-trips through the schema).
    parsed = TriggerEvent.from_dict(trigger)
    checks = {
        "source == ebpf": parsed.source == "ebpf",
        "token_id present": bool(parsed.token_id),
        "pid is int": isinstance(parsed.pid, int),
        "pod/namespace set": bool(parsed.pod_name) and bool(parsed.pod_namespace),
        "process_name set": bool(parsed.process_name),
        "no token_value field": "token_value" not in trigger,
    }
    print("\n" + "=" * 70)
    print("PIPELINE VERIFICATION (fake event -> TriggerEvent -> Pub/Sub format)")
    print("=" * 70)
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("=" * 70)

    all_ok = all(checks.values())
    logger.info("Simulation pipeline verification: {}", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


def run_real() -> int:
    logger.info("=== Phase 6 detector demo — REAL mode (Linux + root + kernel 5.7+) ===")
    if sys.platform != "linux":
        logger.error("Real mode requires Linux. On {} use: python detector/demo_detector.py --simulate",
                     sys.platform)
        return 1

    import subprocess
    import tempfile

    from detector.ebpf import loader

    ebpf_dir = REPO / "detector" / "ebpf"
    logger.info("[1/7] Compiling honeytoken_watch.c (make)...")
    subprocess.run(["make", "-C", str(ebpf_dir)], check=True)

    # A real deployed honeytoken would be a file inside the pod; here a temp file.
    test_file = Path(tempfile.gettempdir()) / "ac2035_honeytoken_test"
    test_file.write_text("FAKE-HONEYTOKEN-DO-NOT-USE\n")
    inode = os.stat(test_file).st_ino

    logger.info("[2/7] Loading eBPF program and watching inode {}...", inode)
    handle = loader.load_program({
        inode: {"token_id": "real-demo-token", "token_type": 3, "pod_id": "checkout-api-9c4f2",
                "namespace": "prod"},
    })

    agent = TelemetryAgent(bpf_handle=handle, pubsub_topic=os.getenv("PUBSUB_TRIGGER_TOPIC", "honeytoken-triggers"))
    logger.info("[3/7] Starting ring-buffer agent...")
    agent.start()

    logger.info("[4/7] Touching the watched file to trigger detection...")
    time.sleep(0.5)
    _ = test_file.read_text()  # open+read → fires the LSM hooks
    time.sleep(1.0)

    logger.info("[5/7] Captured events logged above.")
    logger.info("[6/7] Stopping agent + unloading eBPF...")
    agent.stop()
    test_file.unlink(missing_ok=True)
    logger.info("[7/7] Done.")
    return 0


def main() -> int:
    load_dotenv(REPO / ".env")
    parser = argparse.ArgumentParser(description="AC-2035 eBPF honeytoken detector demo")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--simulate", action="store_true", help="run in simulation mode (default, cross-platform)")
    group.add_argument("--real", action="store_true", help="load real eBPF (Linux + root + kernel 5.7+)")
    args = parser.parse_args()

    if args.real:
        return run_real()
    return run_simulation()


if __name__ == "__main__":
    sys.exit(main())

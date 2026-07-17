"""TelemetryAgent — reads honeytoken events off the eBPF ring buffer and
ships them to GCP Pub/Sub as Phase 2 TriggerEvents.

The decode → resolve-token_id → build-TriggerEvent → publish pipeline is
shared by the real ring-buffer path and simulate_event(), so the same code
is exercised whether or not a kernel program is loaded. Never logs or
carries token_value — only token_id and process context.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loguru import logger

from detector.telemetry_agent.struct_defs import (
    HONEYTOKEN_EVENT_SIZE,
    INT_TO_TOKEN_TYPE,
    PROCESS_EVENT_SIZE,
    decode_honeytoken_event,
    decode_process_event,
    encode_honeytoken_event,
    fnv1a_32,
)

_PLACEHOLDER_PREFIXES = ("your-", "change-me")


def _real_project_id() -> str:
    val = os.getenv("GCP_PROJECT_ID", "").strip()
    low = val.lower()
    if not val or any(low.startswith(p) for p in _PLACEHOLDER_PREFIXES):
        return ""
    return val


class TelemetryAgent:
    def __init__(self, bpf_handle=None, pubsub_topic: str = "honeytoken-triggers",
                 watchdog_interval: int = 30, inode_map: Optional[dict] = None):
        self.bpf_handle = bpf_handle
        self.pubsub_topic = pubsub_topic
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._watchdog_thread: Optional[threading.Thread] = None
        self._watchdog_interval = watchdog_interval
        self._inode_map = inode_map  # kept so a tamper-reload can re-populate (U4)
        self._stop_event = threading.Event()
        self._publisher = None
        self._topic_path = None
        # hash → token_id hints, so simulate_event resolves without a registry.
        self._known_hashes: dict[int, str] = {}
        self._init_publisher()

    def _init_publisher(self) -> None:
        project_id = _real_project_id()
        if not project_id:
            logger.info("No GCP_PROJECT_ID — Pub/Sub publishing disabled (events will be logged only)")
            return
        try:
            from google.cloud import pubsub_v1

            self._publisher = pubsub_v1.PublisherClient()
            self._topic_path = self._publisher.topic_path(project_id, self.pubsub_topic)
            logger.info("Pub/Sub publisher ready: {}", self._topic_path)
        except Exception as e:
            logger.warning("Could not init Pub/Sub publisher ({}) — events will be logged only", e)
            self._publisher = None

    # ── token_id resolution ────────────────────────────────────────────────
    def _resolve_token_id(self, token_id_hash: int) -> Optional[str]:
        """token_id_hash → token_id. Checks simulation hints first, then the
        deployer registry (recomputing FNV-1a for each known token_id)."""
        if token_id_hash in self._known_hashes:
            return self._known_hashes[token_id_hash]
        try:
            from deployer import registry

            for token in registry.get_all():
                tid = token.get("token_id")
                if tid and fnv1a_32(tid) == token_id_hash:
                    return tid
        except Exception as e:
            logger.debug("Registry lookup failed for hash {}: {}", token_id_hash, e)
        return None

    # ── event → TriggerEvent → publish ─────────────────────────────────────
    def _handle_honeytoken_event(self, raw: bytes) -> dict:
        ev = decode_honeytoken_event(raw)
        token_id = self._resolve_token_id(ev["token_id_hash"]) or f"unknown-{ev['token_id_hash']:08x}"
        token_type = INT_TO_TOKEN_TYPE.get(ev["token_type"], "unknown")

        trigger = {
            "token_id": token_id,
            "token_type": token_type,
            # ktime_get_ns is monotonic-since-boot, not wall clock — stamp the
            # TriggerEvent with the processing time (events are handled live).
            "trigger_time": datetime.now(timezone.utc).isoformat(),
            "pod_name": ev["pod_id"],
            "pod_namespace": ev["namespace"],
            "process_name": ev["comm"],
            "pid": ev["tgid"],  # userspace-visible PID
            "source": "ebpf",
        }

        logger.info(
            "Honeytoken {} triggered by {} (pid {}) in {}/{} — inode {}",
            token_id, ev["comm"], ev["tgid"], ev["namespace"], ev["pod_id"], ev["inode"],
        )
        self._publish(trigger)
        return trigger

    def _handle_process_event(self, raw: bytes) -> None:
        ev = decode_process_event(raw)
        kind = "exec" if ev["kind"] == 1 else "exit"
        logger.debug("process {} : {} (pid {}, ppid {})", kind, ev["comm"], ev["tgid"], ev["ppid"])

    def _dispatch(self, raw: bytes) -> None:
        """Ring-buffer sample handler — discriminates the two event types by
        sample size (honeytoken_event=160B, process_event=48B)."""
        if len(raw) == HONEYTOKEN_EVENT_SIZE:
            self._handle_honeytoken_event(raw)
        elif len(raw) == PROCESS_EVENT_SIZE:
            self._handle_process_event(raw)
        else:
            logger.warning("Unknown ring-buffer sample size {} — ignoring", len(raw))

    def _publish(self, trigger: dict) -> None:
        payload = json.dumps(trigger).encode("utf-8")
        if self._publisher is None or self._topic_path is None:
            logger.info("[dry-run] would publish to {}: {}", self.pubsub_topic, json.dumps(trigger))
            return
        try:
            future = self._publisher.publish(self._topic_path, payload)
            future.result(timeout=10)
            logger.info("Published TriggerEvent for token {} to {}", trigger["token_id"], self.pubsub_topic)
        except Exception as e:
            logger.warning("Pub/Sub publish failed for token {}: {}", trigger["token_id"], e)

    # ── U4 tamper watchdog ─────────────────────────────────────────────────
    def _publish_tamper(self, missing: list) -> None:
        """Publish a CRITICAL eBPF-tamper alert to Pub/Sub and (best-effort)
        the external notifier. Distinct from a TriggerEvent."""
        alert = {
            "type": "ebpf_tamper",
            "severity": "critical",
            "missing_hooks": list(missing),
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
        if self._publisher is None or self._topic_path is None:
            logger.critical("[dry-run] eBPF TAMPER — would publish {}", json.dumps(alert))
        else:
            try:
                self._publisher.publish(self._topic_path, json.dumps(alert).encode("utf-8")).result(timeout=10)
                logger.critical("Published eBPF tamper alert: missing {}", missing)
            except Exception as e:
                logger.critical("eBPF TAMPER (missing {}) but Pub/Sub publish failed: {}", missing, e)
        try:
            import notifier

            notifier.notify(
                "ebpf_tamper", token_id="",
                summary=f"eBPF hooks tampered: {', '.join(map(str, missing))}",
                fields={"missing_hooks": ", ".join(map(str, missing))},
            )
        except Exception as e:  # notifier is non-fatal
            logger.warning("Tamper notifier hook failed (non-fatal): {}", e)

    def _watchdog_tick(self) -> bool:
        """One tamper check. Returns True if healthy, False if tamper was
        detected (an alert was published + a reload attempted). Unit-testable
        without a kernel by monkeypatching loader.verify_attached."""
        from detector.ebpf import loader

        try:
            missing = loader.verify_attached(self.bpf_handle)
        except Exception as e:
            logger.warning("Watchdog verify failed: {}", e)
            return True  # a check error is not itself a tamper signal
        if not missing:
            return True
        logger.critical("eBPF TAMPER DETECTED — missing hooks/maps: {}", missing)
        self._publish_tamper(missing)
        try:
            self.bpf_handle = loader.reload_program(self.bpf_handle, self._inode_map)
            logger.info("eBPF program reloaded after tamper")
        except Exception as e:
            logger.error("eBPF reload after tamper failed: {}", e)
        return False

    def _watchdog_loop(self) -> None:
        logger.info("eBPF tamper watchdog started (every {}s)", self._watchdog_interval)
        while self._running:
            if self._stop_event.wait(self._watchdog_interval):
                break
            self._watchdog_tick()

    # ── lifecycle ──────────────────────────────────────────────────────────
    def start(self) -> None:
        """Start consuming the ring buffer in a background thread. Requires a
        loaded bpf_handle; in simulation there's no kernel ring buffer, so
        this is a no-op and callers use simulate_event()."""
        if self.bpf_handle is None:
            logger.warning("No eBPF handle — start() is a no-op; use simulate_event() instead")
            return

        from detector.ebpf import loader

        loader.open_ring_buffer(self.bpf_handle, self._dispatch)
        self._running = True

        def _loop():
            logger.info("TelemetryAgent ring-buffer loop started")
            while self._running:
                loader.poll_ring_buffer(self.bpf_handle, timeout_ms=200)

        self._thread = threading.Thread(target=_loop, name="telemetry-agent", daemon=True)
        self._thread.start()

        # U4 — start the tamper watchdog alongside the ring-buffer loop.
        self._stop_event.clear()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, name="ebpf-watchdog", daemon=True)
        self._watchdog_thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if self._watchdog_thread is not None:
            self._watchdog_thread.join(timeout=2)
            self._watchdog_thread = None
        if self.bpf_handle is not None:
            from detector.ebpf import loader

            loader.unload(self.bpf_handle)
        logger.info("TelemetryAgent stopped")

    # ── simulation ─────────────────────────────────────────────────────────
    def simulate_event(
        self, token_id: str, *, token_type: int = 3, pod_name: str = "checkout-api-9c4f2",
        namespace: str = "prod", comm: str = "python3", pid: int = 4242, inode: int = 424242,
    ) -> dict:
        """Build a fake honeytoken_event and run it through the exact same
        decode → TriggerEvent pipeline the kernel path uses — no root, no
        kernel, works on Windows."""
        token_hash = fnv1a_32(token_id)
        self._known_hashes[token_hash] = token_id  # so _resolve finds it
        raw = encode_honeytoken_event(
            inode=inode, pid=pid + 1, tgid=pid, uid=1000, gid=1000,
            token_id_hash=token_hash, token_type=token_type, comm=comm,
            pod_id=pod_name, namespace=namespace, timestamp_ns=time.monotonic_ns(),
        )
        logger.info("Simulated raw honeytoken_event: {} bytes", len(raw))
        return self._handle_honeytoken_event(raw)

"""U7 — correlation strategy chain + unattributed state (Windows, mocked
timelines, no Neo4j)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backtrace import correlator, engine
from collector.pubsub_listener import TriggerEvent

_WHEN = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)


def _trigger(pod="podA", pid=4242):
    return TriggerEvent(
        token_id="tok", token_type="api_token", trigger_time=_WHEN.isoformat(),
        pod_name=pod, pod_namespace="prod", process_name="python3", pid=pid, source="ebpf",
    )


def _ev(event_type, seconds_before, **kw):
    d = {"event_type": event_type, "timestamp": (_WHEN - timedelta(seconds=seconds_before)).isoformat()}
    d.update(kw)
    return d


def test_strategy_1_cf_ray():
    timeline = [_ev("cloudflare_access", 60, cf_ray="ray1", src_ip="1.1.1.1", pod_name="podA")]
    r = correlator.correlate_entry(_trigger(), timeline, driver=None)
    assert r.strategy == "cf_ray" and r.entry_ip == "1.1.1.1" and r.unattributed is False


def test_strategy_2_vpc_flow_when_no_cfray():
    timeline = [_ev("vpc_flow", 120, src_ip="2.2.2.2", dst_ip="10.0.0.5")]
    r = correlator.correlate_entry(_trigger(), timeline, driver=None)
    assert r.strategy == "vpc_flow" and r.entry_ip == "2.2.2.2"


def test_strategy_3_temporal_process_lineage():
    # No CF-Ray, no VPC — only eBPF process lineage: python3(100) <- sshd(50, src_ip)
    timeline = [
        _ev("process_exec", 60, pid=50, ppid=1, comm="sshd", src_ip="3.3.3.3"),
        _ev("process_exec", 30, pid=100, ppid=50, comm="python3"),
    ]
    r = correlator.correlate_entry(_trigger(pid=100), timeline, driver=None)
    assert r.strategy == "temporal_lineage" and r.entry_ip == "3.3.3.3"


def test_strategy_4_unattributed_when_no_evidence():
    timeline = [_ev("k8s_log", 60, pod_name="podA")]  # no src_ip / cf_ray / vpc / lineage
    r = correlator.correlate_entry(_trigger(), timeline, driver=None)
    assert r.unattributed is True and r.entry_ip is None and r.strategy == "unattributed"


def test_engine_unattributed_short_circuit(monkeypatch):
    class _FakeDriver:
        def verify_connectivity(self):
            return None

    timeline = [{"event_type": "k8s_log", "timestamp": _WHEN.isoformat(), "pod_name": "podA"}]
    monkeypatch.setattr(engine, "load_timeline", lambda tid: timeline)
    monkeypatch.setattr(engine, "ingest_events", lambda *a, **k: None)
    monkeypatch.setattr(engine.correlator, "correlate_entry",
                        lambda t, tl, driver=None: correlator.CorrelationResult(None, "unattributed", True, []))

    attack = engine.run_backtrace(_trigger(), driver=_FakeDriver())

    assert attack.unattributed is True
    assert attack.entry_point is None and attack.movement_path == []
    assert attack.to_dict()["unattributed"] is True
    assert attack.blast_radius == ["podA"]  # blast radius still populated

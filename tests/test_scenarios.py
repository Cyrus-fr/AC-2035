"""U8 — the five reproducible APT scenarios (Windows, no cloud/kernel).

Verifies each scenario returns the right structure and ground truth, is fully
deterministic, and that its telemetry actually drives the real (driver-free)
correlator to the ground-truth strategy.
"""

from __future__ import annotations

from backtrace import correlator
from collector.normalizer import NormalizedEvent
from collector.pubsub_listener import TriggerEvent
from tests.scenarios import GroundTruth, all_scenarios
from tests.scenarios.apt_scenarios import (
    scenario_1_basic_entry,
    scenario_2_lateral_movement,
    scenario_3_ebpf_evasion,
    scenario_4_insider,
    scenario_5_credential_harvest,
)


def test_registry_has_five():
    names = [n for n, _ in all_scenarios()]
    assert len(names) == 5
    assert names[0] == "scenario_1_basic_entry"
    assert names[-1] == "scenario_5_credential_harvest"


def test_each_scenario_structure():
    for name, build in all_scenarios():
        trigger, events, gt = build()
        assert isinstance(trigger, TriggerEvent), name
        assert isinstance(events, list) and events, name
        assert all(isinstance(e, NormalizedEvent) for e in events), name
        assert isinstance(gt, GroundTruth), name
        # Ground truth is fully populated.
        assert gt.token_id == trigger.token_id, name
        assert gt.strategy in ("cf_ray", "vpc_flow", "temporal_lineage", "unattributed"), name
        assert gt.path_nodes, name
        # to_dict round-trips.
        assert gt.to_dict()["token_id"] == gt.token_id, name


def test_events_sorted_and_ids_deterministic():
    for name, build in all_scenarios():
        trigger, events, _ = build()
        stamps = [e.timestamp for e in events]
        assert stamps == sorted(stamps), name
        expected_ids = [f"{trigger.token_id}-evt-{i:02d}" for i in range(len(events))]
        assert [e.event_id for e in events] == expected_ids, name


def test_determinism_repeated_calls_identical():
    for name, build in all_scenarios():
        t1, e1, g1 = build()
        t2, e2, g2 = build()
        assert t1.to_dict() == t2.to_dict(), name
        assert [e.to_dict() for e in e1] == [e.to_dict() for e in e2], name
        assert g1.to_dict() == g2.to_dict(), name


def test_scenario_1_basic():
    trigger, events, gt = scenario_1_basic_entry()
    assert gt.entry_ip == "198.51.100.77"
    assert gt.path_nodes == ["198.51.100.77", "checkout-api-9c4f2"]
    assert len(gt.path_nodes) == 2  # entry + one pod
    r = correlator.correlate_entry(trigger, [e.to_dict() for e in events], driver=None)
    assert r.strategy == "cf_ray" and r.entry_ip == gt.entry_ip


def test_scenario_2_three_hops():
    trigger, events, gt = scenario_2_lateral_movement()
    assert gt.path_nodes[0] == "198.51.100.77"
    assert len(gt.path_nodes) == 4  # entry + three pods
    # Token pod != entry pod, so attribution falls to the VPC-flow chain.
    r = correlator.correlate_entry(trigger, [e.to_dict() for e in events], driver=None)
    assert r.strategy == "vpc_flow" and r.entry_ip == gt.entry_ip


def test_scenario_3_tamper_flagged():
    trigger, events, gt = scenario_3_ebpf_evasion()
    assert gt.tamper_detected is True
    assert any(e.event_type == "ebpf_tamper" for e in events)
    r = correlator.correlate_entry(trigger, [e.to_dict() for e in events], driver=None)
    assert r.strategy == "cf_ray"  # attribution still succeeds despite tamper


def test_scenario_4_insider_vpc_fallback():
    trigger, events, gt = scenario_4_insider()
    assert gt.strategy == "vpc_flow"
    assert gt.entry_ip.startswith("10.20.")  # internal insider IP
    assert gt.unattributed is False
    assert not any(e.event_type == "cloudflare_access" for e in events)
    r = correlator.correlate_entry(trigger, [e.to_dict() for e in events], driver=None)
    assert r.strategy == "vpc_flow" and r.entry_ip == gt.entry_ip


def test_scenario_5_long_dwell_five_hops():
    trigger, events, gt = scenario_5_credential_harvest()
    assert gt.dwell_time_seconds > 1200
    assert len(gt.path_nodes) == 6  # entry + five pods
    # 25-min dwell exceeds the CF-Ray window -> VPC-flow fallback recovers entry.
    r = correlator.correlate_entry(trigger, [e.to_dict() for e in events], driver=None)
    assert r.strategy == "vpc_flow" and r.entry_ip == gt.entry_ip

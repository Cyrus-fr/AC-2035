"""U8 — five reproducible APT attack scenarios.

Each function is self-contained and deterministic, returning
``(TriggerEvent, list[NormalizedEvent], GroundTruth)``. The telemetry is laid
out chronologically (earliest hop furthest in the past) so a timeline-ordered
walk reconstructs the true attacker path, and each scenario ships the ground
truth U9 measures against.

A note on correlation strategy (why not everything is CF-Ray): the engine only
correlates a CF-Ray that reached the *trigger* pod within a 5-minute window
(`correlator.CFRAY_WINDOW_MINUTES`). A single-pod, short-dwell theft (S1, S3)
therefore attributes via CF-Ray; lateral movement whose token pod differs from
the entry pod (S2), an insider with no Cloudflare (S4), and a long-dwell attack
whose entry predates the 5-minute window (S5) all fall through to the 30-minute
VPC-flow strategy — the entry IP is still recovered, which is the point.

Scenario coverage:
  1. Basic external entry            — CF-Ray -> one pod -> token (short dwell).
  2. Lateral movement                — external entry, three-hop pod chain.
  3. eBPF evasion attempt            — CF-Ray entry + a tamper event, one pod.
  4. Insider threat                  — no external IP / CF-Ray; VPC fallback.
  5. Multi-stage credential harvest  — five pods over 25 min (long dwell).
"""

from __future__ import annotations

from collector.normalizer import NormalizedEvent
from collector.pubsub_listener import TriggerEvent

from tests.scenarios.base_scenario import (
    ATTACKER_IP,
    INSIDER_IP,
    PODS,
    POD_NAMES,
    TOKEN_READ_MSG,
    GroundTruth,
    cf_event,
    cf_ray,
    finalize,
    k8s_event,
    make_trigger,
    tamper_event,
    vpc_event,
)

_Scenario = tuple[TriggerEvent, list[NormalizedEvent], GroundTruth]


def scenario_1_basic_entry() -> _Scenario:
    """External attacker enters via Cloudflare, moves to one pod, touches the
    token — a short engagement, so the CF-Ray is still inside the 5-minute
    correlation window. Ground truth: entry_ip, one-hop path, token_id."""
    token_id = "scn1-basic-entry"
    pod = POD_NAMES[0]
    pod_ip = PODS[pod]
    ray = cf_ray(seq=1)

    events = [
        cf_event(240, ATTACKER_IP, pod, ray),
        vpc_event(238, ATTACKER_IP, pod_ip),
        k8s_event(235, pod, TOKEN_READ_MSG),
    ]
    trigger = make_trigger(token_id, pod)
    gt = GroundTruth(
        token_id=token_id,
        entry_ip=ATTACKER_IP,
        path_nodes=[ATTACKER_IP, pod],
        strategy="cf_ray",
        dwell_time_seconds=240,
        expected_confidence="high",  # CF-Ray corroborated by VPC flow
    )
    return trigger, finalize(token_id, events), gt


def scenario_2_lateral_movement() -> _Scenario:
    """External attacker moves laterally across three pods before touching the
    token. The token pod differs from the entry pod, so attribution resolves via
    the VPC-flow chain (entry IP still recovered). Ground truth: entry_ip,
    three-hop ordered path, token_id."""
    token_id = "scn2-lateral"
    pod_a, pod_b, pod_c = POD_NAMES[0], POD_NAMES[1], POD_NAMES[2]
    ip_a, ip_b, ip_c = PODS[pod_a], PODS[pod_b], PODS[pod_c]
    ray = cf_ray(seq=2)

    events = [
        # Entry on pod A (Cloudflare evidence present, but pod A != trigger pod).
        cf_event(900, ATTACKER_IP, pod_a, ray),
        vpc_event(898, ATTACKER_IP, ip_a),
        # Lateral A -> B -> C (internal VPC edges), chronologically ordered.
        vpc_event(700, ip_a, ip_b),
        k8s_event(698, pod_b, "process exec: /bin/sh"),
        vpc_event(500, ip_b, ip_c),
        # Token read on pod C.
        k8s_event(495, pod_c, TOKEN_READ_MSG),
    ]
    trigger = make_trigger(token_id, pod_c)
    gt = GroundTruth(
        token_id=token_id,
        entry_ip=ATTACKER_IP,
        path_nodes=[ATTACKER_IP, pod_a, pod_b, pod_c],
        strategy="vpc_flow",
        dwell_time_seconds=900,
        expected_confidence="medium",  # VPC-flow chain, no CF-Ray on the trigger pod
    )
    return trigger, finalize(token_id, events), gt


def scenario_3_ebpf_evasion() -> _Scenario:
    """Attacker tries to unload the eBPF hooks (a tamper event in the timeline)
    before touching the token, all on one pod within the CF-Ray window. Ground
    truth: entry_ip, path, tamper_detected=True."""
    token_id = "scn3-evasion"
    pod = POD_NAMES[0]
    pod_ip = PODS[pod]
    ray = cf_ray(seq=3)

    events = [
        cf_event(280, ATTACKER_IP, pod, ray),
        vpc_event(278, ATTACKER_IP, pod_ip),
        # The attacker attempts to blind the sensor just before the theft.
        tamper_event(150, pod, missing=("ac2035_file_open", "ac2035_bprm")),
        k8s_event(120, pod, TOKEN_READ_MSG),
    ]
    trigger = make_trigger(token_id, pod)
    gt = GroundTruth(
        token_id=token_id,
        entry_ip=ATTACKER_IP,
        path_nodes=[ATTACKER_IP, pod],
        strategy="cf_ray",
        tamper_detected=True,
        dwell_time_seconds=280,
        expected_confidence="high",
    )
    return trigger, finalize(token_id, events), gt


def scenario_4_insider() -> _Scenario:
    """Insider threat: no external IP, no CF-Ray, internal movement only. Tests
    the U7 VPC-flow fallback. Ground truth: an internal entry IP resolved by the
    VPC-flow strategy (external attribution is impossible)."""
    token_id = "scn4-insider"
    pod_a, pod_b = POD_NAMES[0], POD_NAMES[1]
    ip_a, ip_b = PODS[pod_a], PODS[pod_b]

    events = [
        # Internal principal reaches pod A, then moves to pod B. No Cloudflare.
        vpc_event(600, INSIDER_IP, ip_a),
        k8s_event(598, pod_a, "process exec: /bin/sh"),
        vpc_event(400, ip_a, ip_b),
        k8s_event(395, pod_b, TOKEN_READ_MSG),
    ]
    trigger = make_trigger(token_id, pod_b)
    gt = GroundTruth(
        token_id=token_id,
        entry_ip=INSIDER_IP,     # VPC fallback resolves the earliest internal src
        path_nodes=[INSIDER_IP, pod_a, pod_b],
        strategy="vpc_flow",
        unattributed=False,      # attributed to an insider, not external
        dwell_time_seconds=600,
        expected_confidence="medium",  # VPC flow alone, no CF-Ray corroboration
    )
    return trigger, finalize(token_id, events), gt


def scenario_5_credential_harvest() -> _Scenario:
    """Multi-stage credential harvesting: attacker moves across five pods over
    25 minutes before reaching the token. The 25-minute dwell exceeds the
    CF-Ray window, so attribution falls back to the 30-minute VPC-flow strategy.
    Ground truth: entry_ip, five-hop path, dwell_time > 1200s."""
    token_id = "scn5-harvest"
    pods = POD_NAMES[:5]
    ips = [PODS[p] for p in pods]
    ray = cf_ray(seq=5)

    events = [
        # Entry on pod 0 at 25 minutes (1500s) before the trigger.
        cf_event(1500, ATTACKER_IP, pods[0], ray),
        vpc_event(1498, ATTACKER_IP, ips[0]),
    ]
    # Lateral hops every ~5 minutes across the remaining four pods.
    hop_times = [1200, 900, 600, 300]
    for i, secs in enumerate(hop_times):
        events.append(vpc_event(secs, ips[i], ips[i + 1]))
        events.append(k8s_event(secs - 2, pods[i + 1], "process exec: /bin/sh"))
    # Token read on the fifth pod.
    events.append(k8s_event(295, pods[4], TOKEN_READ_MSG))

    trigger = make_trigger(token_id, pods[4])
    gt = GroundTruth(
        token_id=token_id,
        entry_ip=ATTACKER_IP,
        path_nodes=[ATTACKER_IP, *pods],
        strategy="vpc_flow",
        dwell_time_seconds=1500,   # > 1200s long dwell
        expected_confidence="medium",
    )
    return trigger, finalize(token_id, events), gt


ALL_SCENARIOS = [
    scenario_1_basic_entry,
    scenario_2_lateral_movement,
    scenario_3_ebpf_evasion,
    scenario_4_insider,
    scenario_5_credential_harvest,
]


def all_scenarios() -> list[tuple[str, callable]]:
    """(name, builder) for every scenario, so U9 iterates without hardcoding."""
    return [(fn.__name__, fn) for fn in ALL_SCENARIOS]

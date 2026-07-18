"""U9 — evaluator metric math (Windows, mocked engine).

The engine is injected as a scripted `engine_fn`, so accuracy / FP-rate /
unattributed-rate / confidence-precision are checked against known outputs with
no Neo4j.
"""

from __future__ import annotations

from research import evaluator
from research.evaluator import (
    EvaluationReport,
    _false_positive_rate,
    _hop_accuracy,
    run_evaluation,
)
from tests.scenarios.base_scenario import GroundTruth


def _attack(entry, nodes, confidence, unattributed=False):
    hops = [{"from_node": nodes[i], "to_node": nodes[i + 1], "edge_type": "CONNECTED_TO"}
            for i in range(len(nodes) - 1)]
    return {"entry_point": entry, "movement_path": hops, "confidence": confidence,
            "unattributed": unattributed}


def _scenario(name, token, entry, nodes, strategy="cf_ray", unattributed=False):
    def build():
        trigger = type("T", (), {"token_id": token, "trigger_datetime": None})()
        gt = GroundTruth(token_id=token, entry_ip=entry, path_nodes=nodes,
                         strategy=strategy, unattributed=unattributed)
        return trigger, [], gt
    return (name, build)


# ── unit-level metric helpers ────────────────────────────────────────────────
def test_hop_accuracy_full_and_partial():
    assert _hop_accuracy(["a", "b", "c"], ["a", "b", "c"]) == 1.0
    # first hop right, second wrong -> 1 of 2.
    assert _hop_accuracy(["a", "b", "x"], ["a", "b", "c"]) == 0.5
    assert _hop_accuracy([], ["a", "b"]) == 0.0


def test_false_positive_rate():
    assert _false_positive_rate(["a", "b"], ["a", "b"]) == 0.0
    # one of two reconstructed nodes is noise.
    assert _false_positive_rate(["a", "z"], ["a", "b"]) == 0.5
    assert _false_positive_rate([], ["a"]) == 0.0


# ── full evaluation with a scripted engine ───────────────────────────────────
def test_run_evaluation_perfect_engine():
    scenarios = [
        _scenario("s1", "t1", "1.1.1.1", ["1.1.1.1", "podA"], strategy="cf_ray"),
        _scenario("s2", "t2", "2.2.2.2", ["2.2.2.2", "podA", "podB"], strategy="vpc_flow"),
    ]
    outcomes = {
        "t1": _attack("1.1.1.1", ["1.1.1.1", "podA"], "high"),
        "t2": _attack("2.2.2.2", ["2.2.2.2", "podA", "podB"], "medium"),
    }
    report = run_evaluation(scenarios, engine_fn=lambda trig, ev: outcomes[trig.token_id])

    assert report.count == 2
    assert report.backtrace_accuracy == 1.0
    assert report.false_positive_rate == 0.0
    assert report.unattributed_rate == 0.0
    assert all(m.detection_latency_ms >= 0.0 for m in report.scenarios)
    # Confidence precision: HIGH and MEDIUM each have one correct prediction.
    assert report.confidence_precision["high"] == 1.0
    assert report.confidence_precision["medium"] == 1.0
    assert report.confidence_precision["low"] is None  # no support


def test_run_evaluation_wrong_and_unattributed():
    scenarios = [
        _scenario("wrong", "tw", "9.9.9.9", ["9.9.9.9", "podA", "podB"], strategy="cf_ray"),
        _scenario("unattr", "tu", None, [], strategy="unattributed", unattributed=True),
    ]
    outcomes = {
        # entry right, but second hop reconstructed to the wrong pod -> 0.5 accuracy,
        # and "podX" is a false positive.
        "tw": _attack("9.9.9.9", ["9.9.9.9", "podA", "podX"], "high"),
        "tu": _attack(None, [], "low", unattributed=True),
    }
    report = run_evaluation(scenarios, engine_fn=lambda trig, ev: outcomes[trig.token_id])

    wrong = next(m for m in report.scenarios if m.name == "wrong")
    assert wrong.backtrace_accuracy == 0.5
    assert wrong.false_positive_rate == 1 / 3  # podX of {9.9.9.9, podA, podX}

    unattr = next(m for m in report.scenarios if m.name == "unattr")
    assert unattr.unattributed is True and unattr.backtrace_accuracy == 1.0
    assert report.unattributed_rate == 0.5
    # HIGH has one prediction that was wrong -> precision 0.0.
    assert report.confidence_precision["high"] == 0.0


def test_report_render_json_and_markdown():
    scenarios = [_scenario("s1", "t1", "1.1.1.1", ["1.1.1.1", "podA"])]
    outcomes = {"t1": _attack("1.1.1.1", ["1.1.1.1", "podA"], "high")}
    report = run_evaluation(scenarios, engine_fn=lambda trig, ev: outcomes[trig.token_id])

    md = report.to_markdown()
    assert "Backtrace Evaluation" in md and "aggregate" in md and "Confidence precision" in md
    js = report.to_json()
    assert '"backtrace_accuracy": 1.0' in js and '"count": 1' in js


def test_reference_engine_on_real_scenarios():
    """The default offline reference engine reconstructs the real scenarios
    to their ground truth (entry via the real correlator, path via telemetry)."""
    from tests.scenarios import all_scenarios

    report = run_evaluation(all_scenarios(), engine_fn=evaluator._reference_engine)
    assert report.count == 5
    assert report.backtrace_accuracy == 1.0
    assert report.false_positive_rate == 0.0
    # S3 carries a tamper event; every scenario's tamper flag matches ground truth.
    assert all(m.tamper_correct for m in report.scenarios)
    assert any(m.tamper_detected for m in report.scenarios)

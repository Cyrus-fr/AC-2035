"""U9 — metrics collection + paper evaluation report.

Runs the five U8 scenarios (tests/scenarios/) through the backtrace engine and
measures, per scenario and in aggregate:

  detection_latency_ms   engine wall-clock from trigger to AttackObject.
  backtrace_accuracy     share of ground-truth hops reconstructed in order.
  false_positive_rate    reconstructed path nodes that aren't in the truth.
  confidence_precision   per-tier HIGH/MEDIUM/LOW correctness (reuses U5's
                         backtrace.calibrator).
  unattributed_rate      share of scenarios the engine returns unattributed.

Output:
  research/evaluation_results.json   full metrics.
  research/evaluation_report.md      paper-ready markdown (one row per scenario
                                     + an aggregate row).

The engine is injectable (`engine_fn`), so the metric math is fully testable on
Windows with a mocked engine (no Neo4j). The default offline engine
(`_reference_engine`) attributes the entry with the REAL driver-free correlator
(`backtrace.correlator.correlate_entry`) and reconstructs the path from the
telemetry's pod-activity order — so offline numbers reflect the real correlation
logic. `--real` (or an auto-detected Neo4j) swaps in the full graph engine.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from backtrace import correlator

REPO = Path(__file__).resolve().parent.parent
_TIERS = ("high", "medium", "low")
_RESULTS_JSON = REPO / "research" / "evaluation_results.json"
_REPORT_MD = REPO / "research" / "evaluation_report.md"


# ── attack-object accessors (works on a dict or an engine AttackObject) ──────
def _get(attack, name: str, default=None):
    if isinstance(attack, dict):
        return attack.get(name, default)
    return getattr(attack, name, default)


def _hops_as_dicts(attack) -> list[dict]:
    hops = _get(attack, "movement_path") or []
    return [h if isinstance(h, dict) else h.to_dict() for h in hops]


def _path_nodes(hops: list[dict]) -> list[str]:
    """Ordered node names across a movement path: each hop's from_node plus the
    final to_node (same convention as backtrace.calibrator)."""
    if not hops:
        return []
    return [h["from_node"] for h in hops] + [hops[-1]["to_node"]]


# ── the offline reference engine (default when Neo4j is absent) ──────────────
def _reference_engine(trigger, events) -> dict:
    """Driver-free reconstruction for Windows/offline evaluation.

    Entry IP / strategy / unattributed come from the REAL correlator; the
    movement path is the timeline's pods ordered by first observed activity
    (every cloudflare/k8s/tamper event carries pod_name). Confidence mirrors
    the scorer: CF-Ray corroborated by a matching VPC flow -> high, VPC-flow
    alone -> medium, temporal -> low.
    """
    timeline = [e.to_dict() if hasattr(e, "to_dict") else e for e in events]
    token_id = _get(trigger, "token_id") or getattr(trigger, "token_id", "")
    result = correlator.correlate_entry(trigger, timeline, driver=None)

    if result.unattributed:
        return {"token_id": token_id, "entry_point": None, "movement_path": [],
                "confidence": "low", "unattributed": True, "dwell_time_seconds": 0}

    # Pods in order of first observed activity (pod_name-bearing events only).
    first_seen: dict[str, str] = {}
    for e in timeline:
        pod = e.get("pod_name")
        ts = e.get("timestamp")
        if pod and ts and (pod not in first_seen or ts < first_seen[pod]):
            first_seen[pod] = ts
    ordered_pods = [p for p, _ in sorted(first_seen.items(), key=lambda kv: kv[1])]

    path_nodes = [result.entry_ip, *ordered_pods]
    hops = [{"from_node": path_nodes[i], "to_node": path_nodes[i + 1],
             "edge_type": "CONNECTED_TO"} for i in range(len(path_nodes) - 1)]

    corroborated = any(e.get("event_type") == "vpc_flow" and e.get("src_ip") == result.entry_ip
                       for e in timeline)
    confidence = {"cf_ray": "high" if corroborated else "medium",
                  "vpc_flow": "medium",
                  "temporal_lineage": "low"}.get(result.strategy, "low")

    trigger_dt = getattr(trigger, "trigger_datetime", None)
    dwell = 0
    if trigger_dt is not None:
        stamps = [correlator._parse(e.get("timestamp")) for e in timeline]
        stamps = [s for s in stamps if s is not None and s <= trigger_dt]
        if stamps:
            dwell = max(0, int((trigger_dt - min(stamps)).total_seconds()))

    return {"token_id": token_id, "entry_point": result.entry_ip, "movement_path": hops,
            "confidence": confidence, "unattributed": False, "dwell_time_seconds": dwell,
            "strategy": result.strategy}


def _real_engine(trigger, events) -> object:
    """Full graph engine: persist the timeline, then run_backtrace (needs Neo4j)."""
    from backtrace.engine import run_backtrace
    from collector.normalizer import save_timeline

    save_timeline(trigger.token_id, list(events))
    return run_backtrace(trigger)


# ── metrics ──────────────────────────────────────────────────────────────────
@dataclass
class ScenarioMetrics:
    name: str
    token_id: str
    detection_latency_ms: float
    backtrace_accuracy: float
    false_positive_rate: float
    confidence: str
    unattributed: bool
    tamper_detected: bool
    tamper_correct: bool
    expected_strategy: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "token_id": self.token_id,
            "detection_latency_ms": round(self.detection_latency_ms, 3),
            "backtrace_accuracy": round(self.backtrace_accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "confidence": self.confidence,
            "unattributed": self.unattributed,
            "tamper_detected": self.tamper_detected,
            "tamper_correct": self.tamper_correct,
            "expected_strategy": self.expected_strategy,
        }


@dataclass
class EvaluationReport:
    scenarios: list = field(default_factory=list)          # list[ScenarioMetrics]
    confidence_precision: dict = field(default_factory=dict)  # tier -> precision|None

    @property
    def count(self) -> int:
        return len(self.scenarios)

    @property
    def mean_latency_ms(self) -> float:
        return _mean(m.detection_latency_ms for m in self.scenarios)

    @property
    def backtrace_accuracy(self) -> float:
        return _mean(m.backtrace_accuracy for m in self.scenarios)

    @property
    def false_positive_rate(self) -> float:
        return _mean(m.false_positive_rate for m in self.scenarios)

    @property
    def unattributed_rate(self) -> float:
        return _mean(1.0 if m.unattributed else 0.0 for m in self.scenarios)

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "aggregate": {
                "mean_detection_latency_ms": round(self.mean_latency_ms, 3),
                "backtrace_accuracy": round(self.backtrace_accuracy, 4),
                "false_positive_rate": round(self.false_positive_rate, 4),
                "unattributed_rate": round(self.unattributed_rate, 4),
            },
            "confidence_precision": {
                t: (round(p, 4) if p is not None else None)
                for t, p in self.confidence_precision.items()
            },
            "scenarios": [m.to_dict() for m in self.scenarios],
        }

    def to_json(self, path: Optional[str] = None) -> str:
        import json

        text = json.dumps(self.to_dict(), indent=2)
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(text, encoding="utf-8")
            logger.info("Evaluation results written: {}", path)
        return text

    def to_markdown(self) -> str:
        rows = [
            "# AC-2035 Backtrace Evaluation",
            "",
            "| Scenario | Latency (ms) | Accuracy | FP rate | Confidence | Unattributed |",
            "|---|---|---|---|---|---|",
        ]
        for m in self.scenarios:
            rows.append(
                f"| {m.name} | {m.detection_latency_ms:.2f} | {m.backtrace_accuracy:.2f} | "
                f"{m.false_positive_rate:.2f} | {m.confidence} | {'yes' if m.unattributed else 'no'} |"
            )
        rows.append(
            f"| **aggregate ({self.count})** | **{self.mean_latency_ms:.2f}** | "
            f"**{self.backtrace_accuracy:.2f}** | **{self.false_positive_rate:.2f}** | - | "
            f"**{self.unattributed_rate:.2f}** |"
        )
        rows += ["", "## Confidence precision (per tier)", "",
                 "| Tier | Precision |", "|---|---|"]
        for t in _TIERS:
            p = self.confidence_precision.get(t)
            rows.append(f"| {t} | {p:.2f} |" if p is not None else f"| {t} | - |")
        rows += ["",
                 f"_Detection latency is engine wall-clock. Accuracy is the share of "
                 f"ground-truth hops reconstructed in order; FP rate is reconstructed path "
                 f"nodes absent from ground truth. Over {self.count} scenario(s)._"]
        return "\n".join(rows)


def _mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def _hop_accuracy(reconstructed_nodes: list[str], truth_nodes: list[str]) -> float:
    """Share of ground-truth hops (consecutive node pairs) reconstructed at the
    correct position."""
    truth_hops = list(zip(truth_nodes, truth_nodes[1:]))
    recon_hops = list(zip(reconstructed_nodes, reconstructed_nodes[1:]))
    if not truth_hops:
        return 1.0 if not recon_hops else 0.0
    matched = sum(1 for i, hop in enumerate(truth_hops)
                  if i < len(recon_hops) and recon_hops[i] == hop)
    return matched / len(truth_hops)


def _false_positive_rate(reconstructed_nodes: list[str], truth_nodes: list[str]) -> float:
    if not reconstructed_nodes:
        return 0.0
    truth = set(truth_nodes)
    fp = sum(1 for n in reconstructed_nodes if n not in truth)
    return fp / len(reconstructed_nodes)


def run_evaluation(scenarios=None, engine_fn: Optional[Callable] = None) -> EvaluationReport:
    """Run each scenario through `engine_fn(trigger, events)` and score it
    against the scenario's ground truth. `engine_fn` defaults to the offline
    reference engine."""
    if scenarios is None:
        from tests.scenarios import all_scenarios

        scenarios = all_scenarios()
    if engine_fn is None:
        engine_fn = _reference_engine

    metrics: list[ScenarioMetrics] = []
    attacks_by_token: dict[str, object] = {}
    truth_by_token: dict[str, object] = {}

    for name, build in scenarios:
        trigger, events, gt = build()
        start = time.perf_counter()
        attack = engine_fn(trigger, events)
        latency_ms = (time.perf_counter() - start) * 1000.0

        attacks_by_token[gt.token_id] = attack
        truth_by_token[gt.token_id] = gt

        recon_nodes = _path_nodes(_hops_as_dicts(attack))
        unattributed = bool(_get(attack, "unattributed", False))
        if gt.unattributed:
            accuracy = 1.0 if unattributed else 0.0
            fpr = _false_positive_rate(recon_nodes, [])
        else:
            accuracy = _hop_accuracy(recon_nodes, gt.path_nodes)
            fpr = _false_positive_rate(recon_nodes, gt.path_nodes)

        tamper_detected = any(
            (e.to_dict() if hasattr(e, "to_dict") else e).get("event_type") == "ebpf_tamper"
            for e in events
        )
        metrics.append(ScenarioMetrics(
            name=name,
            token_id=gt.token_id,
            detection_latency_ms=latency_ms,
            backtrace_accuracy=accuracy,
            false_positive_rate=fpr,
            confidence=str(_get(attack, "confidence", "low")),
            unattributed=unattributed,
            tamper_detected=tamper_detected,
            tamper_correct=(tamper_detected == gt.tamper_detected),
            expected_strategy=gt.strategy,
        ))
        logger.info("Evaluated [{}]: accuracy={:.2f} fpr={:.2f} latency={:.2f}ms",
                    name, accuracy, fpr, latency_ms)

    report = EvaluationReport(
        scenarios=metrics,
        confidence_precision=_confidence_precision(attacks_by_token, truth_by_token),
    )
    logger.info("Evaluation complete: {} scenario(s), accuracy={:.2f}, unattributed_rate={:.2f}",
                report.count, report.backtrace_accuracy, report.unattributed_rate)
    return report


def _confidence_precision(attacks_by_token: dict, truth_by_token: dict) -> dict:
    """Per-tier precision, reusing U5's calibrator over the already-computed
    attack objects (keyed on token_id, so no second engine run)."""
    from backtrace.calibrator import CalibrationCase, run_calibration

    cases = [
        CalibrationCase(name=tid, trigger={"token_id": tid},
                        expected_entry=gt.entry_ip, ground_truth_nodes=gt.path_nodes)
        for tid, gt in truth_by_token.items()
    ]
    report = run_calibration(cases, engine_fn=lambda trig: attacks_by_token[trig["token_id"]])
    return {t: s.precision for t, s in report.tiers.items()}


def _print_summary(report: EvaluationReport) -> None:
    print("\n" + "=" * 66)
    print("AC-2035 BACKTRACE EVALUATION")
    print("=" * 66)
    for m in report.scenarios:
        print(f"  {m.name:32} acc={m.backtrace_accuracy:.2f} fpr={m.false_positive_rate:.2f} "
              f"conf={m.confidence:6} lat={m.detection_latency_ms:6.2f}ms "
              f"{'UNATTR' if m.unattributed else ''}")
    print("-" * 66)
    print(f"  aggregate: accuracy={report.backtrace_accuracy:.2f}  "
          f"fp_rate={report.false_positive_rate:.2f}  "
          f"unattributed_rate={report.unattributed_rate:.2f}  "
          f"mean_latency={report.mean_latency_ms:.2f}ms")
    prec = ", ".join(f"{t}={p:.2f}" for t, p in report.confidence_precision.items() if p is not None)
    print(f"  confidence precision: {prec or 'n/a'}")
    print("=" * 66)


def _neo4j_up() -> bool:
    try:
        from graph.schema import get_driver

        get_driver().verify_connectivity()
        return True
    except Exception as e:
        logger.info("Neo4j not reachable ({}) - using the offline reference engine.", e)
        return False


def main() -> int:
    import argparse

    from dotenv import load_dotenv

    load_dotenv(REPO / ".env")
    parser = argparse.ArgumentParser(description="AC-2035 backtrace evaluation (U9)")
    parser.add_argument("--scenarios", default="all",
                        help="which scenarios to run (only 'all' is supported today)")
    parser.add_argument("--assert-accuracy", type=float, default=None, dest="assert_accuracy",
                        help="exit non-zero if aggregate backtrace accuracy is below this")
    parser.add_argument("--real", action="store_true",
                        help="force the full Neo4j graph engine (default: auto-detect)")
    args = parser.parse_args()

    use_real = args.real or _neo4j_up()
    engine_fn = _real_engine if use_real else _reference_engine
    logger.info("Running evaluation with the {} engine.", "real (Neo4j)" if use_real else "offline reference")

    report = run_evaluation(engine_fn=engine_fn)
    _print_summary(report)
    report.to_json(_RESULTS_JSON)
    _REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    _REPORT_MD.write_text(report.to_markdown(), encoding="utf-8")
    logger.info("Evaluation report written: {}", _REPORT_MD)

    if args.assert_accuracy is not None and report.backtrace_accuracy < args.assert_accuracy:
        logger.error("Backtrace accuracy {:.2f} is below the required {:.2f} - failing.",
                     report.backtrace_accuracy, args.assert_accuracy)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

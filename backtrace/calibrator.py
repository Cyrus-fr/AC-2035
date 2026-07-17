"""U5 — Backtrace confidence calibration.

Runs labeled attack scenarios through the backtrace engine and measures whether
the HIGH / MEDIUM / LOW confidence labels are *meaningful*:

  precision(tier) = correct-in-tier / predicted-in-tier
                    "when the engine says HIGH, how often is it right?"
  recall(tier)    = correct-in-tier / total-correct
                    "of all correct reconstructions, what share carried HIGH?"

plus overall accuracy. Uncalibrated confidence scores are scientifically
meaningless, so this report is required for the research paper.

The engine is injectable (`engine_fn`), so the calibration math is fully
testable on Windows with a mocked engine (no Neo4j). Richer labeled scenarios
arrive with U8; a small self-contained set ships here.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

REPO = Path(__file__).resolve().parent.parent
_TIERS = ("high", "medium", "low")


@dataclass
class CalibrationCase:
    name: str
    trigger: dict                     # TriggerEvent-shaped dict passed to the engine
    expected_entry: Optional[str]     # ground-truth entry point
    ground_truth_nodes: list[str]     # ground-truth ordered movement-path node names


@dataclass
class TierStats:
    tier: str
    predicted: int = 0                # cases the engine labeled this tier
    correct: int = 0                  # of those, reconstructions matching ground truth

    @property
    def precision(self) -> Optional[float]:
        return (self.correct / self.predicted) if self.predicted else None

    def recall(self, total_correct: int) -> Optional[float]:
        return (self.correct / total_correct) if total_correct else None


@dataclass
class CalibrationReport:
    tiers: dict = field(default_factory=dict)  # tier -> TierStats
    total: int = 0
    total_correct: int = 0

    @property
    def accuracy(self) -> Optional[float]:
        return (self.total_correct / self.total) if self.total else None

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "total_correct": self.total_correct,
            "accuracy": self.accuracy,
            "tiers": {
                t: {
                    "predicted": s.predicted,
                    "correct": s.correct,
                    "precision": s.precision,
                    "recall": s.recall(self.total_correct),
                }
                for t, s in self.tiers.items()
            },
        }

    def to_json(self, path: Optional[str] = None) -> str:
        text = json.dumps(self.to_dict(), indent=2)
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(text, encoding="utf-8")
            logger.info("Calibration report written: {}", path)
        return text

    def to_markdown(self) -> str:
        rows = ["| Confidence | Predicted | Correct | Precision | Recall |",
                "|---|---|---|---|---|"]
        for t in _TIERS:
            s = self.tiers.get(t, TierStats(tier=t))
            prec = f"{s.precision:.2f}" if s.precision is not None else "-"
            rec = s.recall(self.total_correct)
            rec_s = f"{rec:.2f}" if rec is not None else "-"
            rows.append(f"| {t} | {s.predicted} | {s.correct} | {prec} | {rec_s} |")
        acc = f"{self.accuracy:.2f}" if self.accuracy is not None else "-"
        rows.append(f"\n**Overall accuracy:** {acc} over {self.total} case(s).")
        return "\n".join(rows)


def _get(attack, name: str):
    return attack.get(name) if isinstance(attack, dict) else getattr(attack, name)


def _path_nodes(hops: list) -> list[str]:
    """Ordered node names across a movement path: each hop's from_node plus the
    final to_node."""
    if not hops:
        return []
    nodes = [h["from_node"] for h in hops]
    nodes.append(hops[-1]["to_node"])
    return nodes


def _tier_of(attack) -> str:
    conf = _get(attack, "confidence")
    return conf if conf in _TIERS else "low"


def _reconstruction_correct(attack, case: CalibrationCase) -> bool:
    """Correct iff the entry point matches AND the ordered movement-path node
    names equal the ground truth. An unattributed object is never correct."""
    if _get(attack, "unattributed") if _has(attack, "unattributed") else False:
        return False
    hops = _get(attack, "movement_path") or []
    hops = [h if isinstance(h, dict) else h.to_dict() for h in hops]
    return _get(attack, "entry_point") == case.expected_entry and _path_nodes(hops) == case.ground_truth_nodes


def _has(attack, name: str) -> bool:
    return (name in attack) if isinstance(attack, dict) else hasattr(attack, name)


def run_calibration(cases, engine_fn: Optional[Callable] = None) -> CalibrationReport:
    """Run each case through `engine_fn` (default: the real backtrace engine) and
    bin by predicted confidence tier vs ground-truth correctness."""
    if engine_fn is None:
        from backtrace.engine import run_backtrace

        engine_fn = run_backtrace

    tiers = {t: TierStats(tier=t) for t in _TIERS}
    total = total_correct = 0
    for case in cases:
        attack = engine_fn(case.trigger)
        tier = _tier_of(attack)
        correct = _reconstruction_correct(attack, case)
        tiers[tier].predicted += 1
        total += 1
        if correct:
            tiers[tier].correct += 1
            total_correct += 1
        logger.info("Calibration [{}]: tier={} correct={}", case.name, tier, correct)

    report = CalibrationReport(tiers=tiers, total=total, total_correct=total_correct)
    logger.info("Calibration complete: accuracy={} over {} case(s)", report.accuracy, total)
    return report


# ── self-contained demonstration (mock engine — always runnable) ────────────
def _mock_cases() -> list[CalibrationCase]:
    """Six labeled cases whose scripted engine output is stashed on the trigger
    (under `_mock`), so the report format is demonstrable on any box."""
    def attack(entry, nodes, confidence, unattributed=False):
        hops = [{"from_node": nodes[i], "to_node": nodes[i + 1]} for i in range(len(nodes) - 1)]
        return {"entry_point": entry, "movement_path": hops, "confidence": confidence,
                "unattributed": unattributed}

    specs = [
        ("high-correct-1", "1.1.1.1", ["1.1.1.1", "podA", "tok"], "high", True),
        ("high-correct-2", "1.1.1.2", ["1.1.1.2", "podB", "tok"], "high", True),
        ("high-wrong", "1.1.1.3", ["1.1.1.3", "podC", "tok"], "high", False),
        ("medium-correct", "2.2.2.1", ["2.2.2.1", "podD", "tok"], "medium", True),
        ("low-correct", "3.3.3.1", ["3.3.3.1", "podE", "tok"], "low", True),
        ("unattributed", "4.4.4.1", ["4.4.4.1", "podF", "tok"], "low", False),
    ]
    cases = []
    for name, entry, nodes, conf, correct in specs:
        out = attack(entry if correct else "WRONG-IP", nodes if correct else ["WRONG-IP"], conf,
                     unattributed=(name == "unattributed"))
        cases.append(CalibrationCase(name=name, trigger={"_mock": out},
                                     expected_entry=entry, ground_truth_nodes=nodes))
    return cases


def _mock_engine(trigger: dict):
    return trigger["_mock"]


def main() -> int:
    import argparse

    from dotenv import load_dotenv

    load_dotenv(REPO / ".env")
    parser = argparse.ArgumentParser(description="AC-2035 backtrace confidence calibration")
    parser.add_argument("--real", action="store_true",
                        help="run scenarios through the real backtrace engine (needs Neo4j)")
    args = parser.parse_args()

    if args.real:
        try:
            from backtrace.engine import run_backtrace
            from graph.schema import get_driver

            get_driver().verify_connectivity()
        except Exception as e:
            logger.error("Neo4j required for --real calibration ({}); run without --real for a mock demo.", e)
            return 1
        # NOTE: laying down coherent labeled timelines is U8's job; until then
        # --real reconstructs whatever timelines already exist for the cases.
        report = run_calibration(_mock_cases(), engine_fn=run_backtrace)
    else:
        logger.info("Mock calibration (use --real to run through the engine).")
        report = run_calibration(_mock_cases(), engine_fn=_mock_engine)

    print("\n" + report.to_markdown() + "\n")
    report.to_json(REPO / "research" / "calibration_report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

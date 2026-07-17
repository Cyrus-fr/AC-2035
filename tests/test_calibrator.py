"""U5 — calibration math tests (Windows, mocked engine).

Verifies precision / recall / accuracy per confidence tier against a scripted
engine, with no Neo4j.
"""

from __future__ import annotations

from backtrace.calibrator import CalibrationCase, run_calibration


def _attack(entry, nodes, confidence):
    hops = [{"from_node": nodes[i], "to_node": nodes[i + 1]} for i in range(len(nodes) - 1)]
    return {"entry_point": entry, "movement_path": hops, "confidence": confidence}


def test_precision_recall_per_tier():
    cases = [
        CalibrationCase("c1", {"k": "1"}, "1.1.1.1", ["1.1.1.1", "podA", "tok"]),
        CalibrationCase("c2", {"k": "2"}, "2.2.2.2", ["2.2.2.2", "podB", "tok"]),
        CalibrationCase("c3", {"k": "3"}, "3.3.3.3", ["3.3.3.3", "podC", "tok"]),
        CalibrationCase("c4", {"k": "4"}, "4.4.4.4", ["4.4.4.4", "podD", "tok"]),
    ]
    outcomes = {
        "1": _attack("1.1.1.1", ["1.1.1.1", "podA", "tok"], "high"),   # high, correct
        "2": _attack("2.2.2.2", ["2.2.2.2", "podB", "tok"], "high"),   # high, correct
        "3": _attack("WRONG", ["WRONG", "podC", "tok"], "high"),       # high, INCORRECT
        "4": _attack("4.4.4.4", ["4.4.4.4", "podD", "tok"], "low"),    # low, correct
    }
    report = run_calibration(cases, engine_fn=lambda trig: outcomes[trig["k"]])

    assert report.total == 4
    assert report.total_correct == 3
    assert report.accuracy == 0.75

    high = report.tiers["high"]
    assert high.predicted == 3 and high.correct == 2
    assert high.precision == 2 / 3
    assert high.recall(report.total_correct) == 2 / 3

    low = report.tiers["low"]
    assert low.predicted == 1 and low.correct == 1
    assert low.precision == 1.0
    assert low.recall(report.total_correct) == 1 / 3

    medium = report.tiers["medium"]
    assert medium.predicted == 0
    assert medium.precision is None  # no support -> undefined, not 0


def test_unattributed_never_correct():
    case = CalibrationCase("u", {"k": "u"}, "9.9.9.9", ["9.9.9.9", "podZ", "tok"])
    # engine returns the right-looking path but flags it unattributed -> not correct
    attack = {**_attack("9.9.9.9", ["9.9.9.9", "podZ", "tok"], "low"), "unattributed": True}
    report = run_calibration([case], engine_fn=lambda trig: attack)
    assert report.total_correct == 0


def test_markdown_and_json_render():
    cases = [CalibrationCase("c1", {"k": "1"}, "1.1.1.1", ["1.1.1.1", "tok"])]
    outcomes = {"1": _attack("1.1.1.1", ["1.1.1.1", "tok"], "high")}
    report = run_calibration(cases, engine_fn=lambda trig: outcomes[trig["k"]])
    md = report.to_markdown()
    assert "Precision" in md and "Overall accuracy" in md
    assert '"accuracy": 1.0' in report.to_json()

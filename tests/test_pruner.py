"""U6 — graph pruner tests (Windows, mocked Neo4j driver)."""

from __future__ import annotations

from graph import pruner


class _Counters:
    def __init__(self, rels=0, nodes=0):
        self.relationships_deleted = rels
        self.nodes_deleted = nodes


class _Summary:
    def __init__(self, counters):
        self.counters = counters


class _Result:
    def __init__(self, summary=None, single=None):
        self._summary = summary
        self._single = single

    def consume(self):
        return self._summary

    def single(self):
        return self._single


class _Session:
    def __init__(self, results):
        self._results = list(results)
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.queries.append((query, params))
        return self._results.pop(0)


class _Driver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


def test_prune_old_filters_by_cutoff_and_returns_counters():
    session = _Session([
        _Result(summary=_Summary(_Counters(rels=5))),   # delete old relationships
        _Result(summary=_Summary(_Counters(nodes=3))),  # delete orphan nodes
    ])
    result = pruner.prune_old(days=7, driver=_Driver(session))

    assert result == {"relationships_deleted": 5, "nodes_deleted": 3}
    q0, p0 = session.queries[0]
    assert "r.timestamp < $cutoff" in q0 and "cutoff" in p0
    q1, _ = session.queries[1]
    assert "NOT (n)--()" in q1  # orphan cleanup


def test_node_count():
    session = _Session([_Result(single={"c": 42})])
    assert pruner.node_count(driver=_Driver(session)) == 42


def test_check_node_count_alerts_over_threshold():
    session = _Session([_Result(single={"c": 10_001})])
    assert pruner.check_node_count(threshold=10_000, driver=_Driver(session)) is True


def test_check_node_count_silent_under_threshold():
    session = _Session([_Result(single={"c": 500})])
    assert pruner.check_node_count(threshold=10_000, driver=_Driver(session)) is False

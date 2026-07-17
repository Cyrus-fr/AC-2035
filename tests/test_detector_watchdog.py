"""U4 eBPF tamper-watchdog tests (Windows — no kernel).

Exercises the watchdog LOGIC by mocking loader.verify_attached / reload_program:
a detected tamper must publish a CRITICAL alert and attempt a reload; a healthy
check must do neither. Also unit-tests loader.verify_attached's missing-hook /
missing-pin detection on plain paths.
"""

from __future__ import annotations

from detector.ebpf import loader
from detector.ebpf.loader import LoadedProgram
from detector.telemetry_agent.agent import TelemetryAgent


class _FakeFuture:
    def result(self, timeout=None):
        return "msg-id"


class _FakePublisher:
    def __init__(self):
        self.published: list[bytes] = []

    def publish(self, topic, payload):
        self.published.append(payload)
        return _FakeFuture()


def _agent_with_publisher() -> tuple[TelemetryAgent, _FakePublisher]:
    agent = TelemetryAgent(bpf_handle=object(), watchdog_interval=1, inode_map={1: {"token_id": "t"}})
    pub = _FakePublisher()
    agent._publisher = pub
    agent._topic_path = "projects/x/topics/honeytoken-triggers"
    return agent, pub


def test_watchdog_tick_detects_tamper(monkeypatch):
    agent, pub = _agent_with_publisher()
    monkeypatch.setattr(loader, "verify_attached", lambda h: ["ac2035_file_open", "map:events"])
    reloaded = {"called": False}

    def _fake_reload(h, inode_map):
        reloaded["called"] = True
        return object()

    monkeypatch.setattr(loader, "reload_program", _fake_reload)

    healthy = agent._watchdog_tick()

    assert healthy is False
    assert pub.published, "a CRITICAL tamper alert must be published to Pub/Sub"
    assert reloaded["called"] is True, "a reload must be attempted after tamper"


def test_watchdog_tick_healthy(monkeypatch):
    agent, pub = _agent_with_publisher()
    monkeypatch.setattr(loader, "verify_attached", lambda h: [])
    reloaded = {"called": False}
    monkeypatch.setattr(loader, "reload_program", lambda h, im: reloaded.__setitem__("called", True))

    assert agent._watchdog_tick() is True
    assert not pub.published
    assert reloaded["called"] is False


def test_verify_attached_reports_missing(tmp_path):
    handle = LoadedProgram(
        lib=None, obj=0, watched_inodes_fd=0, events_fd=0,
        attached=["ac2035_file_open", "ac2035_file_permission"],
        pin_dir=str(tmp_path),
    )
    missing = loader.verify_attached(handle)
    assert "ac2035_execve" in missing and "ac2035_process_exit" in missing
    assert "map:watched_inodes" in missing and "map:events" in missing

    # Fully attached + both maps pinned -> healthy.
    handle.attached = list(loader._PROGRAMS)
    (tmp_path / "watched_inodes").write_text("x")
    (tmp_path / "events").write_text("x")
    assert loader.verify_attached(handle) == []

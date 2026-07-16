"""U0 notifier tests — circuit breaker, .alert fallback, and the non-blocking
best-effort contract.

Asserts (per the approved plan): an unreachable webhook -> breaker trips ->
logger.critical emitted -> .alert file written -> dispatch() returns without
raising or blocking.
"""

from __future__ import annotations

import threading
import time

import httpx
from loguru import logger

import notifier
from notifier.base import CircuitBreaker, Notifier


class _UnreachableNotifier(Notifier):
    name = "unreachable"

    def __init__(self):
        super().__init__(CircuitBreaker(threshold=1))  # one failure opens it
        self.timeout_s = 0.5

    def configured(self) -> bool:
        return True

    def post(self, event: dict) -> None:
        # Port 1 -> connection refused (near-instant, offline-safe).
        resp = httpx.post("http://127.0.0.1:1/webhook", json=event, timeout=self.timeout_s)
        resp.raise_for_status()


class _OkNotifier(Notifier):
    name = "ok"

    def configured(self) -> bool:
        return True

    def post(self, event: dict) -> None:
        return None  # success


class _UnconfiguredNotifier(Notifier):
    name = "noop"

    def configured(self) -> bool:
        return False

    def post(self, event: dict) -> None:  # pragma: no cover — must not be called
        raise AssertionError("post() called on an unconfigured channel")


def test_unreachable_trips_breaker_and_writes_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(notifier.fallback, "FALLBACK_DIR", tmp_path / "fb")
    crit: list = []
    sink = logger.add(crit.append, level="CRITICAL")

    ch = _UnreachableNotifier()
    event = notifier.build_event("test", "tok", "boom", {"x": 1})

    start = time.monotonic()
    t = notifier.dispatch(event, channels=[ch])
    returned_in = time.monotonic() - start

    assert isinstance(t, threading.Thread)   # returns a thread handle
    assert returned_in < 0.3                  # non-blocking: didn't wait on the webhook
    t.join(timeout=5)
    logger.remove(sink)

    assert not t.is_alive()                   # dispatch finished cleanly
    assert ch.breaker.is_open                 # breaker tripped (threshold=1)
    assert list((tmp_path / "fb").glob("*.alert"))          # .alert fallback written
    assert any("FAILED" in str(m) for m in crit)            # logger.critical emitted


def test_no_configured_channel_still_writes_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(notifier.fallback, "FALLBACK_DIR", tmp_path / "fb")
    t = notifier.dispatch(notifier.build_event("t", "tok", "s"), channels=[_UnconfiguredNotifier()])
    t.join(timeout=5)
    assert list((tmp_path / "fb").glob("*.alert"))


def test_success_writes_no_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(notifier.fallback, "FALLBACK_DIR", tmp_path / "fb")
    ch = _OkNotifier()
    t = notifier.dispatch(notifier.build_event("t", "tok", "s"), channels=[ch])
    t.join(timeout=5)
    assert not (tmp_path / "fb").exists() or not list((tmp_path / "fb").glob("*.alert"))
    assert not ch.breaker.is_open

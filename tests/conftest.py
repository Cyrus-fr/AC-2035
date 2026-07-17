"""Shared pytest fixtures. Isolates module-level state so each test runs
against a temp config.yaml and writes audit / .alert files under tmp_path
(never into the repo), and neutralises the orchestrator's fire-and-forget
notifier hook for tests that aren't exercising the notifier itself."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import notifier  # noqa: E402
import research.immutable_sink as _immutable_sink  # noqa: E402
from killswitch import orchestrator  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    orig_cfg = orchestrator._CONFIG_PATH
    monkeypatch.setattr(orchestrator, "AUDIT_DIR", tmp_path / "audit")
    monkeypatch.setattr(notifier.fallback, "FALLBACK_DIR", tmp_path / "notifier_alerts")
    # Kill-switch tests shouldn't spawn the fire-and-forget notifier thread;
    # the notifier has its own tests that call dispatch() directly.
    monkeypatch.setattr(notifier, "notify", lambda *a, **k: None)
    # U11 — kill-switch tests shouldn't write to the immutable sink's local
    # mirror; the sink has its own tests using ImmutableSink directly.
    monkeypatch.setattr(_immutable_sink, "write_audit", lambda *a, **k: None)
    monkeypatch.setattr(_immutable_sink, "write_raw_telemetry", lambda *a, **k: None)
    yield
    orchestrator._CONFIG_PATH = orig_cfg
    orchestrator.reload_providers()

"""Notifier core (U0): the Notifier interface, a per-channel circuit breaker,
and a placeholder-aware env reader.

Channel implementations live in slack.py / discord.py / pagerduty.py; the
fan-out (dispatch/notify) lives in __init__.py. This module imports nothing
from killswitch (the orchestrator imports notifier, so the reverse would be a
cycle) — hence its own env() helper.
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from typing import Optional

# Values shipped in .env.example are placeholders, not real webhooks — treat
# them as absent so a channel with a placeholder URL is simply disabled.
_PLACEHOLDER_PREFIXES = ("your-", "change-me")


def env(name: str) -> str:
    """Return an env value, or "" if it's unset or a known placeholder."""
    val = os.getenv(name, "").strip()
    if not val or any(val.lower().startswith(p) for p in _PLACEHOLDER_PREFIXES):
        return ""
    return val


class CircuitBreaker:
    """Opens after `threshold` consecutive failures; half-opens after
    `cooldown_s` to allow a single retry. Keeps a dead/misconfigured webhook
    from being hammered on every alert."""

    def __init__(self, threshold: int = 3, cooldown_s: float = 60.0):
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self._failures = 0
        self._opened_at: Optional[float] = None

    def allow(self) -> bool:
        """True if a send may be attempted (closed, or half-open after cooldown)."""
        if self._opened_at is None:
            return True
        return (time.monotonic() - self._opened_at) >= self.cooldown_s

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.threshold:
            self._opened_at = time.monotonic()

    @property
    def is_open(self) -> bool:
        return self._opened_at is not None and (time.monotonic() - self._opened_at) < self.cooldown_s


class Notifier(ABC):
    """One external alert channel."""

    name: str = "notifier"
    timeout_s: float = 5.0

    def __init__(self, breaker: Optional[CircuitBreaker] = None):
        self.breaker = breaker or CircuitBreaker()

    @abstractmethod
    def configured(self) -> bool:
        """True if this channel has a webhook URL / routing key set."""

    @abstractmethod
    def post(self, event: dict) -> None:
        """Send the event. MUST raise on any failure (non-2xx, timeout,
        connection error) so the caller can trip the breaker + write a
        fallback."""

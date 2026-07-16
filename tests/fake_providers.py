"""In-memory fake kill-switch providers for the U2/U3 unit tests.

They record every lifecycle call into the module-level CALLS list (the
orchestrator instantiates providers itself, so instance state is not visible to
tests — a module registry is). Referenced by dotted path from a temp
config.yaml to prove dynamic loading needs no orchestrator change.
"""

from __future__ import annotations

from killswitch import ActionResult, make_action
from killswitch.providers.base import Provider

CALLS: list[tuple[str, str]] = []


class FakeSuccessProvider(Provider):
    action_type = "fake_success"

    def available(self) -> tuple[bool, str]:
        return (True, "")

    def execute(self, attack) -> ActionResult:
        CALLS.append(("execute", self.action_type))
        return make_action(self.action_type, "target", True, None, rollback_state={"undo": True})

    def verify(self, attack, result) -> bool:
        CALLS.append(("verify", self.action_type))
        return True

    def rollback(self, attack, result) -> ActionResult:
        CALLS.append(("rollback", self.action_type))
        return make_action(f"{self.action_type}_rollback", "target", True, None)


class FakeFailProvider(Provider):
    action_type = "fake_fail"

    def available(self) -> tuple[bool, str]:
        return (True, "")

    def execute(self, attack) -> ActionResult:
        CALLS.append(("execute", self.action_type))
        return make_action(self.action_type, "target", False, "boom")

    def rollback(self, attack, result) -> ActionResult:  # should never be called (execute failed)
        CALLS.append(("rollback", self.action_type))
        return make_action(f"{self.action_type}_rollback", "target", True, None)


class FakeVerifyFailProvider(Provider):
    action_type = "fake_verify_fail"

    def available(self) -> tuple[bool, str]:
        return (True, "")

    def execute(self, attack) -> ActionResult:
        CALLS.append(("execute", self.action_type))
        return make_action(self.action_type, "target", True, None, rollback_state={"undo": True})

    def verify(self, attack, result) -> bool:
        CALLS.append(("verify", self.action_type))
        return False

    def rollback(self, attack, result) -> ActionResult:
        CALLS.append(("rollback", self.action_type))
        return make_action(f"{self.action_type}_rollback", "target", True, None)

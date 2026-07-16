"""Abstract kill-switch provider interface (U2).

A Provider wraps one containment action against one external control plane
(GCP IAM, Cloudflare, Zitadel, ...). The orchestrator discovers providers
dynamically from killswitch/config.yaml, so adding a control plane is a YAML
line plus a subclass here — no orchestrator edit.

Lifecycle per provider, all graceful (a method must never raise to the
orchestrator — return a failed ActionResult instead):

    available()               -> (usable, reason)   creds present & usable?
    execute(attack)           -> ActionResult       fire the action; on success
                                                     populate result.rollback_state
    verify(attack, result)    -> bool               re-fetch & confirm effect (U3)
    rollback(attack, result)  -> ActionResult       undo via result.rollback_state (U2)
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from killswitch import ActionResult, make_action


class Provider(ABC):
    """Base class for a kill-switch action provider."""

    #: Stable action identifier, e.g. "gcp_iam_revoke". Surfaces in audit logs
    #: and is how the demo/UI group action results.
    action_type: str = "provider"

    @abstractmethod
    def available(self) -> tuple[bool, str]:
        """Return ``(usable, reason)``.

        ``usable`` is False when required credentials/config are absent;
        ``reason`` is a short actionable explanation in that case.
        """

    @abstractmethod
    def execute(self, attack: dict) -> ActionResult:
        """Fire the containment action.

        Must never raise — return a failed ``ActionResult`` instead. On
        success, set ``result.rollback_state`` to the minimum information
        needed to undo the action later (see rollback()).
        """

    def verify(self, attack: dict, result: ActionResult) -> bool:
        """Re-fetch the control plane and confirm the action took effect.

        Default: no verification available -> assume verified (True).
        Providers that can verify override this (U3).
        """
        return True

    def rollback(self, attack: dict, result: ActionResult) -> ActionResult:
        """Undo a previously successful execute(), using result.rollback_state.

        Default: the action cannot be undone. Providers that can roll back
        override this (U2).
        """
        return make_action(
            self.action_type,
            result.target,
            False,
            "rollback not supported for this provider",
        )

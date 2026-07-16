"""Shared types and helpers for the kill-switch package.

Lives in __init__ (not orchestrator.py) so the three action handlers
(gcp_iam / cloudflare / zitadel) can import ActionResult without importing
the orchestrator that imports *them* — which would be circular.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

AUDIT_DIR = Path(__file__).resolve().parent / "audit"

# Values shipped in .env.example are placeholders, not real secrets — treat
# them as absent so local dev reports "credentials missing" cleanly instead
# of firing doomed API calls at real endpoints with junk tokens.
_PLACEHOLDER_PREFIXES = ("your-", "change-me")

# An Identity node reads like a GCP service account or an email/principal;
# Pod names, IPs and token UUIDs never match these.
_IDENTITY_RE = re.compile(r"@|serviceaccount|:iam\.|\.gserviceaccount\.com", re.IGNORECASE)


def env_secret(name: str) -> str:
    """Return an env value, or "" if it's unset or a known placeholder."""
    val = os.getenv(name, "").strip()
    low = val.lower()
    if not val or any(low.startswith(p) for p in _PLACEHOLDER_PREFIXES):
        return ""
    return val


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_dict(attack_object) -> dict:
    """Accept either an AttackObject dataclass (has .to_dict) or a plain
    dict loaded from JSON."""
    if hasattr(attack_object, "to_dict"):
        return attack_object.to_dict()
    return attack_object


def extract_identity(attack_object) -> Optional[str]:
    """First identity-looking node name in the reconstructed movement path,
    or None. The AttackObject carries node *names* (not Neo4j labels), so we
    match on the shape of the name rather than a stored type."""
    ao = _as_dict(attack_object)
    for hop in ao.get("movement_path", []):
        for node in (hop.get("from_node"), hop.get("to_node")):
            if node and _IDENTITY_RE.search(node):
                return node
    return None


@dataclass
class ActionResult:
    action_type: str  # gcp_iam_revoke / cloudflare_ip_block / zitadel_session_kill
    target: str
    success: bool
    error: Optional[str]
    timestamp: str
    # Undo info captured by a provider's execute() so the orchestrator can
    # later rollback() the action (U2). Providers populate this on success.
    rollback_state: Optional[dict] = None
    # Set by the orchestrator after re-fetching the provider to confirm the
    # action took effect (U3). None = not verified; False = verification failed.
    verified: Optional[bool] = None
    # Set by the orchestrator if a compensating rollback was attempted (U2).
    rolled_back: Optional[bool] = None

    def to_dict(self) -> dict:
        return asdict(self)


def make_action(
    action_type: str,
    target: str,
    success: bool,
    error: Optional[str],
    rollback_state: Optional[dict] = None,
) -> ActionResult:
    return ActionResult(
        action_type=action_type,
        target=target,
        success=success,
        error=error,
        timestamp=now_iso(),
        rollback_state=rollback_state,
    )


@dataclass
class KillSwitchResult:
    pending_id: str
    status: str  # executed / pending / partial / failed
    attack_object_token_id: str
    actions: list = field(default_factory=list)
    executed_at: Optional[str] = None
    triggered_by: str = "auto"  # auto / analyst
    # Not part of the on-disk schema — a convenience pointer for callers.
    audit_path: Optional[str] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "pending_id": self.pending_id,
            "status": self.status,
            "attack_object_token_id": self.attack_object_token_id,
            "actions": [a.to_dict() for a in self.actions],
            "executed_at": self.executed_at,
            "triggered_by": self.triggered_by,
        }

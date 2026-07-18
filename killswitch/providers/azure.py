"""Azure kill-switch provider (U10): remove every role assignment held by the
compromised principal in the subscription scope.

Mirrors the GCP/AWS providers' contract — self-guards inside execute() (never
raises to the orchestrator), records the removed assignments in rollback_state
so the action is reversible (U2) and re-verifiable (U3), and degrades gracefully
when the Azure SDKs or credentials are absent. The authorization client is
injectable (`auth_client=`) so the execute/verify/rollback logic is unit-testable
without Azure.

Live role revocation is ARTIFACT-ONLY here (needs real Azure credentials). Ships
disabled in killswitch/config.yaml; enable it once creds are present.
"""

from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loguru import logger

from killswitch import ActionResult, env_secret, extract_identity, make_action
from killswitch.providers.base import Provider

# An Azure AD principal (object) id is a GUID; that's what a role assignment is
# keyed on, so it's the identity we look for in the reconstructed path.
_GUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def _extract_principal(attack) -> Optional[str]:
    """First Azure principal (GUID) in the reconstructed movement path, or None.

    Provider-local so the shared killswitch.extract_identity (GCP/email-shaped)
    stays unchanged. Falls back to extract_identity for a principal name."""
    ao = attack.to_dict() if hasattr(attack, "to_dict") else attack
    for hop in ao.get("movement_path", []):
        for node in (hop.get("from_node"), hop.get("to_node")):
            if node:
                m = _GUID_RE.search(node)
                if m:
                    return m.group(0)
    return extract_identity(attack)


class AzureProvider(Provider):
    action_type = "azure_ad_revoke"

    def __init__(self, auth_client=None):
        # Injected by tests; None in production -> built lazily from the SDKs.
        self._auth_client = auth_client

    def available(self) -> tuple[bool, str]:
        try:
            import azure.identity  # noqa: F401
            import azure.mgmt.authorization  # noqa: F401
        except ImportError:
            return (False, "azure-identity / azure-mgmt-authorization not installed")
        for var in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
                    "AZURE_SUBSCRIPTION_ID"):
            if not env_secret(var):
                return (False, f"{var} missing")
        return (True, "")

    def _client(self):
        """Return an AuthorizationManagementClient (injected or built), or None
        when the provider is unavailable."""
        if self._auth_client is not None:
            return self._auth_client
        usable, reason = self.available()
        if not usable:
            logger.error("Azure provider unavailable: {}", reason)
            return None
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.authorization import AuthorizationManagementClient

            credential = ClientSecretCredential(
                tenant_id=env_secret("AZURE_TENANT_ID"),
                client_id=env_secret("AZURE_CLIENT_ID"),
                client_secret=env_secret("AZURE_CLIENT_SECRET"),
            )
            return AuthorizationManagementClient(credential, env_secret("AZURE_SUBSCRIPTION_ID"))
        except Exception as e:  # pragma: no cover - needs the Azure SDKs present
            logger.error("Failed to build Azure authorization client: {}", e)
            return None

    def _scope(self) -> str:
        return f"/subscriptions/{env_secret('AZURE_SUBSCRIPTION_ID')}"

    def _list_for_principal(self, client, principal: str) -> list:
        return list(client.role_assignments.list_for_subscription(
            filter=f"principalId eq '{principal}'"))

    def execute(self, attack) -> ActionResult:
        client = self._client()
        if client is None:
            _, reason = self.available()
            return make_action(self.action_type, "", False, reason or "Azure provider unavailable")

        principal = _extract_principal(attack)
        if not principal:
            logger.warning("No Azure principal in attack path - skipping role revoke")
            return make_action(self.action_type, "", False, "No Azure principal in path")

        try:
            assignments = self._list_for_principal(client, principal)
            captured: list[dict] = []
            for a in assignments:
                client.role_assignments.delete_by_id(a.id)
                captured.append({
                    "id": a.id,
                    "name": getattr(a, "name", None),
                    "scope": getattr(a, "scope", None) or self._scope(),
                    "role_definition_id": getattr(a, "role_definition_id", None),
                })
            if not captured:
                logger.info("Azure principal {} had no role assignments to revoke", principal)
                return make_action(self.action_type, principal, False,
                                   f"No role assignments for {principal}")

            logger.info("Revoked {} Azure role assignment(s) for principal {}",
                        len(captured), principal)
            return make_action(
                self.action_type,
                principal,
                True,
                None,
                rollback_state={"principal_id": principal, "role_assignments": captured},
            )
        except Exception as e:
            logger.warning("Azure role revoke failed for {}: {}", principal, e)
            return make_action(self.action_type, principal, False, str(e))

    def verify(self, attack, result: ActionResult) -> bool:
        """Re-list the principal's role assignments and confirm none remain (U3)."""
        state = result.rollback_state or {}
        principal = state.get("principal_id") or _extract_principal(attack)
        client = self._client()
        if not principal or client is None:
            return False
        try:
            remaining = self._list_for_principal(client, principal)
            if remaining:
                logger.warning("Verify: Azure principal {} still has {} role assignment(s)",
                               principal, len(remaining))
                return False
            logger.info("Verify: Azure principal {} has no remaining role assignments", principal)
            return True
        except Exception as e:
            logger.warning("Azure role verify failed for {}: {}", principal, e)
            return False

    def rollback(self, attack, result: ActionResult) -> ActionResult:
        """Re-create the role assignments execute() removed (U2). Reversible."""
        state = result.rollback_state or {}
        principal = state.get("principal_id")
        assignments = state.get("role_assignments") or []
        action = f"{self.action_type}_rollback"
        if not principal or not assignments:
            return make_action(action, principal or "", False, "nothing to roll back")
        client = self._client()
        if client is None:
            return make_action(action, principal, False, "Azure provider unavailable")
        try:
            for a in assignments:
                client.role_assignments.create(
                    a.get("scope") or self._scope(),
                    str(uuid.uuid4()),  # a fresh role-assignment GUID
                    {"role_definition_id": a.get("role_definition_id"), "principal_id": principal},
                )
            logger.warning("ROLLBACK: re-created {} Azure role assignment(s) for principal {}",
                           len(assignments), principal)
            return make_action(action, principal, True, None)
        except Exception as e:
            logger.error("Azure role rollback failed for {}: {}", principal, e)
            return make_action(action, principal, False, str(e))

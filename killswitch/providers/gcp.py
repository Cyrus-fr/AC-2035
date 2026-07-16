"""GCP IAM kill-switch provider (U2): revoke every project IAM role bound to
the compromised identity.

Uses google-auth (present transitively via the google-cloud-* deps) to mint a
token, then the Cloud Resource Manager REST API over httpx to get -> strip ->
set the project IAM policy. Degrades gracefully — never raises to the
orchestrator. On success it records the roles it removed in rollback_state so
the action can be undone (U2) and re-verified (U3).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import httpx
from loguru import logger

from killswitch import ActionResult, env_secret, extract_identity, make_action
from killswitch.providers.base import Provider

_TIMEOUT = 30.0
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def _as_member(identity: str) -> str:
    """Best-effort IAM member string for an identity name."""
    if identity.startswith(("serviceAccount:", "user:", "group:", "domain:")):
        return identity
    if identity.endswith(".gserviceaccount.com"):
        return f"serviceAccount:{identity}"
    if "@" in identity:
        return f"user:{identity}"
    return identity


class GCPProvider(Provider):
    action_type = "gcp_iam_revoke"

    def available(self) -> tuple[bool, str]:
        if not env_secret("GCP_PROJECT_ID"):
            return (False, "GCP_PROJECT_ID missing")
        return (True, "")

    def execute(self, attack) -> ActionResult:
        project_id = env_secret("GCP_PROJECT_ID")
        if not project_id:
            logger.error(
                "GCP_PROJECT_ID missing - cannot revoke IAM. Set GCP_PROJECT_ID "
                "in .env, or disable the gcp provider in killswitch/config.yaml."
            )
            return make_action(self.action_type, "", False, "GCP credentials missing")

        identity = extract_identity(attack)
        if not identity:
            logger.warning("No Identity node in attack path — skipping IAM revoke")
            return make_action(self.action_type, "", False, "No identity in path")

        member = _as_member(identity)

        try:
            import google.auth
            from google.auth.exceptions import DefaultCredentialsError
            from google.auth.transport.requests import Request
        except ImportError:
            logger.error("google-auth unavailable — cannot revoke IAM (pip install google-auth)")
            return make_action(self.action_type, member, False, "GCP credentials missing")

        try:
            creds, _ = google.auth.default(scopes=_SCOPES)
            creds.refresh(Request())
            headers = {"Authorization": f"Bearer {creds.token}"}
            base = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"

            resp = httpx.post(f"{base}:getIamPolicy", headers=headers, timeout=_TIMEOUT)
            resp.raise_for_status()
            policy = resp.json()

            bindings = policy.get("bindings", [])
            removed_roles: list[str] = []
            for binding in bindings:
                if member in binding.get("members", []):
                    binding["members"].remove(member)
                    if binding.get("role"):
                        removed_roles.append(binding["role"])
            # Drop any binding left with no members.
            policy["bindings"] = [b for b in bindings if b.get("members")]

            if not removed_roles:
                logger.info("Identity {} had no role bindings to revoke", member)
                return make_action(self.action_type, member, False, f"No role bindings for {member}")

            set_resp = httpx.post(
                f"{base}:setIamPolicy", headers=headers, json={"policy": policy}, timeout=_TIMEOUT
            )
            set_resp.raise_for_status()
            logger.info("Revoked {} IAM role(s) for {}", len(removed_roles), member)
            return make_action(
                self.action_type,
                member,
                True,
                None,
                rollback_state={"project_id": project_id, "member": member, "roles": removed_roles},
            )
        except DefaultCredentialsError:
            logger.error(
                "No GCP application-default credentials - cannot revoke IAM. Run "
                "`gcloud auth application-default login` or mount a service-account key."
            )
            return make_action(self.action_type, member, False, "GCP credentials missing")
        except Exception as e:
            logger.warning("GCP IAM revoke failed for {}: {}", member, e)
            return make_action(self.action_type, member, False, str(e))

    def verify(self, attack, result: ActionResult) -> bool:
        """Re-fetch the project IAM policy and confirm the member is absent
        from every binding (U3)."""
        state = result.rollback_state or {}
        project_id = state.get("project_id") or env_secret("GCP_PROJECT_ID")
        member = state.get("member")
        if not project_id or not member:
            return False
        try:
            import google.auth
            from google.auth.transport.requests import Request

            creds, _ = google.auth.default(scopes=_SCOPES)
            creds.refresh(Request())
            headers = {"Authorization": f"Bearer {creds.token}"}
            base = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
            resp = httpx.post(f"{base}:getIamPolicy", headers=headers, timeout=_TIMEOUT)
            resp.raise_for_status()
            for binding in resp.json().get("bindings", []):
                if member in binding.get("members", []):
                    logger.warning("Verify: {} still bound to {}", member, binding.get("role"))
                    return False
            logger.info("Verify: {} absent from all IAM bindings", member)
            return True
        except Exception as e:
            logger.warning("GCP IAM verify failed for {}: {}", member, e)
            return False

    def rollback(self, attack, result: ActionResult) -> ActionResult:
        """Undo a revoke by re-adding the member to the roles it was removed
        from (U2). Reversible."""
        state = result.rollback_state or {}
        project_id = state.get("project_id") or env_secret("GCP_PROJECT_ID")
        member = state.get("member")
        roles = state.get("roles") or []
        action = f"{self.action_type}_rollback"
        if not project_id or not member or not roles:
            return make_action(action, member or "", False, "nothing to roll back")
        try:
            import google.auth
            from google.auth.transport.requests import Request

            creds, _ = google.auth.default(scopes=_SCOPES)
            creds.refresh(Request())
            headers = {"Authorization": f"Bearer {creds.token}"}
            base = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
            resp = httpx.post(f"{base}:getIamPolicy", headers=headers, timeout=_TIMEOUT)
            resp.raise_for_status()
            policy = resp.json()
            bindings = policy.setdefault("bindings", [])
            by_role = {b.get("role"): b for b in bindings}
            for role in roles:
                b = by_role.get(role)
                if b is None:
                    b = {"role": role, "members": []}
                    bindings.append(b)
                    by_role[role] = b
                if member not in b.setdefault("members", []):
                    b["members"].append(member)
            set_resp = httpx.post(f"{base}:setIamPolicy", headers=headers, json={"policy": policy}, timeout=_TIMEOUT)
            set_resp.raise_for_status()
            logger.warning("ROLLBACK: re-added {} to {} role(s)", member, len(roles))
            return make_action(action, member, True, None)
        except Exception as e:
            logger.error("GCP IAM rollback failed for {}: {}", member, e)
            return make_action(action, member, False, str(e))

"""Kill-switch action: revoke all GCP IAM roles bound to the compromised
identity on the project.

Uses google-auth (already present transitively via the google-cloud-*
deps) to mint a token, then the Cloud Resource Manager REST API over httpx
to get → strip → set the project IAM policy. Degrades gracefully — never
raises to the orchestrator.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from loguru import logger

from killswitch import ActionResult, env_secret, extract_identity, make_action

_ACTION = "gcp_iam_revoke"
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


def revoke(attack_object) -> ActionResult:
    project_id = env_secret("GCP_PROJECT_ID")
    if not project_id:
        logger.warning("GCP_PROJECT_ID missing — skipping IAM revoke")
        return make_action(_ACTION, "", False, "GCP credentials missing")

    identity = extract_identity(attack_object)
    if not identity:
        logger.warning("No Identity node in attack path — skipping IAM revoke")
        return make_action(_ACTION, "", False, "No identity in path")

    member = _as_member(identity)

    try:
        import google.auth
        from google.auth.exceptions import DefaultCredentialsError
        from google.auth.transport.requests import Request
    except ImportError:
        logger.warning("google-auth unavailable — skipping IAM revoke")
        return make_action(_ACTION, member, False, "GCP credentials missing")

    try:
        creds, _ = google.auth.default(scopes=_SCOPES)
        creds.refresh(Request())
        headers = {"Authorization": f"Bearer {creds.token}"}
        base = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"

        resp = httpx.post(f"{base}:getIamPolicy", headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        policy = resp.json()

        bindings = policy.get("bindings", [])
        removed = False
        for binding in bindings:
            if member in binding.get("members", []):
                binding["members"].remove(member)
                removed = True
        # Drop any binding left with no members.
        policy["bindings"] = [b for b in bindings if b.get("members")]

        if not removed:
            logger.info("Identity {} had no role bindings to revoke", member)
            return make_action(_ACTION, member, False, f"No role bindings for {member}")

        set_resp = httpx.post(f"{base}:setIamPolicy", headers=headers, json={"policy": policy}, timeout=_TIMEOUT)
        set_resp.raise_for_status()
        logger.info("Revoked all IAM roles for {}", member)
        return make_action(_ACTION, member, True, None)
    except DefaultCredentialsError:
        logger.warning("No GCP application-default credentials — skipping IAM revoke")
        return make_action(_ACTION, member, False, "GCP credentials missing")
    except Exception as e:
        logger.warning("GCP IAM revoke failed for {}: {}", member, e)
        return make_action(_ACTION, member, False, str(e))

"""Zitadel kill-switch provider (U2): terminate active sessions for the
compromised identity via the Management API.

Degrades gracefully — never raises to the orchestrator. Note: session
termination is IRREVERSIBLE, so rollback() is a documented best-effort no-op
(see U2 rollback step). rollback_state records what was killed for the audit
trail only.
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


def _base_url() -> str:
    domain = env_secret("ZITADEL_DOMAIN") or "localhost"
    if domain.startswith(("http://", "https://")):
        return domain.rstrip("/")
    # ZITADEL_DOMAIN is a bare host in .env (e.g. "localhost") — the local
    # container publishes on :8081.
    return f"http://{domain}:8081"


class ZitadelProvider(Provider):
    action_type = "zitadel_session_kill"

    def available(self) -> tuple[bool, str]:
        if not env_secret("ZITADEL_SERVICE_ACCOUNT_TOKEN"):
            return (False, "ZITADEL_SERVICE_ACCOUNT_TOKEN missing")
        return (True, "")

    def execute(self, attack) -> ActionResult:
        token = env_secret("ZITADEL_SERVICE_ACCOUNT_TOKEN")
        if not token:
            logger.error(
                "Zitadel credentials missing - cannot kill sessions. Set "
                "ZITADEL_SERVICE_ACCOUNT_TOKEN in .env, or disable the zitadel "
                "provider in killswitch/config.yaml."
            )
            return make_action(self.action_type, "", False, "Zitadel credentials missing")

        identity = extract_identity(attack)
        if not identity:
            logger.warning("No Identity node in attack path — skipping Zitadel session kill")
            return make_action(self.action_type, "", False, "No identity in path")

        base = _base_url()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        try:
            with httpx.Client(base_url=base, headers=headers, timeout=_TIMEOUT) as client:
                resp = client.get("/v1/users", params={"query": identity})
                resp.raise_for_status()
                users = resp.json().get("result") or resp.json().get("users") or []
                if not users:
                    logger.info("No Zitadel user found for identity {}", identity)
                    return make_action(self.action_type, identity, True, "No active sessions found")

                user_id = users[0].get("id") or users[0].get("userId")
                sess_resp = client.get(f"/v1/users/{user_id}/sessions")
                sess_resp.raise_for_status()
                sessions = sess_resp.json().get("result") or sess_resp.json().get("sessions") or []
                if not sessions:
                    logger.info("No active sessions for Zitadel user {}", identity)
                    return make_action(self.action_type, identity, True, "No active sessions found")

                killed = 0
                for session in sessions:
                    sid = session.get("id") or session.get("sessionId")
                    if not sid:
                        continue
                    del_resp = client.delete(f"/v1/sessions/{sid}")
                    del_resp.raise_for_status()
                    killed += 1

                logger.info("Terminated {} Zitadel session(s) for {}", killed, identity)
                return make_action(
                    self.action_type,
                    identity,
                    True,
                    None,
                    rollback_state={"user_id": user_id, "killed_sessions": killed, "irreversible": True},
                )
        except httpx.HTTPError as e:
            logger.warning("Zitadel session kill failed for {}: {}", identity, e)
            return make_action(self.action_type, identity, False, str(e))
        except Exception as e:
            logger.warning("Unexpected error during Zitadel session kill for {}: {}", identity, e)
            return make_action(self.action_type, identity, False, str(e))

    def verify(self, attack, result: ActionResult) -> bool:
        """Re-fetch the user's sessions and confirm none remain active (U3).
        A success with no user/sessions (no user_id captured) is trivially
        verified."""
        token = env_secret("ZITADEL_SERVICE_ACCOUNT_TOKEN")
        if not token:
            return False
        user_id = (result.rollback_state or {}).get("user_id")
        if not user_id:
            return True  # execute reported "no active sessions" — nothing to verify
        base = _base_url()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        try:
            with httpx.Client(base_url=base, headers=headers, timeout=_TIMEOUT) as client:
                resp = client.get(f"/v1/users/{user_id}/sessions")
                resp.raise_for_status()
                sessions = resp.json().get("result") or resp.json().get("sessions") or []
                if sessions:
                    logger.warning("Verify: {} Zitadel session(s) still active for user {}", len(sessions), user_id)
                    return False
                logger.info("Verify: no active Zitadel sessions for user {}", user_id)
                return True
        except Exception as e:
            logger.warning("Zitadel verify failed for user {}: {}", user_id, e)
            return False

    def rollback(self, attack, result: ActionResult) -> ActionResult:
        """Session termination is IRREVERSIBLE — a killed session cannot be
        restored. Best-effort no-op that records the limitation (U2)."""
        action = f"{self.action_type}_rollback"
        logger.warning(
            "ROLLBACK: Zitadel session termination is IRREVERSIBLE - cannot "
            "restore killed sessions for {}",
            result.target,
        )
        return make_action(action, result.target, False, "session kill is irreversible - no rollback possible")

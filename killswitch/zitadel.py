"""Kill-switch action: terminate active Zitadel sessions for the
compromised identity via the Management API.

Endpoints follow the Phase 5 spec's shape; the real Zitadel management API
may differ in exact paths. Degrades gracefully — never raises.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from loguru import logger

from killswitch import ActionResult, env_secret, extract_identity, make_action

_ACTION = "zitadel_session_kill"
_TIMEOUT = 30.0


def _base_url() -> str:
    domain = env_secret("ZITADEL_DOMAIN") or "localhost"
    if domain.startswith(("http://", "https://")):
        return domain.rstrip("/")
    # ZITADEL_DOMAIN is a bare host in .env (e.g. "localhost") — the local
    # container publishes on :8081.
    return f"http://{domain}:8081"


def kill_sessions(attack_object) -> ActionResult:
    token = env_secret("ZITADEL_SERVICE_ACCOUNT_TOKEN")
    if not token:
        logger.warning("Zitadel credentials missing — skipping session kill")
        return make_action(_ACTION, "", False, "Zitadel credentials missing")

    identity = extract_identity(attack_object)
    if not identity:
        logger.warning("No Identity node in attack path — skipping Zitadel session kill")
        return make_action(_ACTION, "", False, "No identity in path")

    base = _base_url()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    try:
        with httpx.Client(base_url=base, headers=headers, timeout=_TIMEOUT) as client:
            resp = client.get("/v1/users", params={"query": identity})
            resp.raise_for_status()
            users = resp.json().get("result") or resp.json().get("users") or []
            if not users:
                logger.info("No Zitadel user found for identity {}", identity)
                return make_action(_ACTION, identity, True, "No active sessions found")

            user_id = users[0].get("id") or users[0].get("userId")
            sess_resp = client.get(f"/v1/users/{user_id}/sessions")
            sess_resp.raise_for_status()
            sessions = sess_resp.json().get("result") or sess_resp.json().get("sessions") or []
            if not sessions:
                logger.info("No active sessions for Zitadel user {}", identity)
                return make_action(_ACTION, identity, True, "No active sessions found")

            killed = 0
            for session in sessions:
                sid = session.get("id") or session.get("sessionId")
                if not sid:
                    continue
                del_resp = client.delete(f"/v1/sessions/{sid}")
                del_resp.raise_for_status()
                killed += 1

            logger.info("Terminated {} Zitadel session(s) for {}", killed, identity)
            return make_action(_ACTION, identity, True, None)
    except httpx.HTTPError as e:
        logger.warning("Zitadel session kill failed for {}: {}", identity, e)
        return make_action(_ACTION, identity, False, str(e))
    except Exception as e:
        logger.warning("Unexpected error during Zitadel session kill for {}: {}", identity, e)
        return make_action(_ACTION, identity, False, str(e))

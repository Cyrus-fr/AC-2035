"""Cloudflare kill-switch provider (U2): block the attacker's entry IP with a
zone firewall rule.

Degrades gracefully — never raises to the orchestrator. On success it records
the created firewall-rule id in rollback_state so the block can be lifted (U2)
and re-verified (U3).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import httpx
from loguru import logger

from killswitch import ActionResult, _as_dict, env_secret, make_action, now_iso
from killswitch.providers.base import Provider

_TIMEOUT = 30.0
_API = "https://api.cloudflare.com/client/v4"


class CloudflareProvider(Provider):
    action_type = "cloudflare_ip_block"

    def available(self) -> tuple[bool, str]:
        if not env_secret("CLOUDFLARE_API_TOKEN") or not env_secret("CLOUDFLARE_ZONE_ID"):
            return (False, "CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID missing")
        return (True, "")

    def execute(self, attack) -> ActionResult:
        ao = _as_dict(attack)
        api_token = env_secret("CLOUDFLARE_API_TOKEN")
        zone_id = env_secret("CLOUDFLARE_ZONE_ID")

        if not api_token or not zone_id:
            logger.error(
                "Cloudflare credentials missing - cannot block IP. Set "
                "CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID in .env, or disable "
                "the cloudflare provider in killswitch/config.yaml."
            )
            return make_action(self.action_type, ao.get("entry_point") or "", False, "Cloudflare credentials missing")

        entry_ip = ao.get("entry_point")
        if not entry_ip:
            logger.warning("No entry IP in attack path — skipping Cloudflare block")
            return make_action(self.action_type, "", False, "No entry IP in path")

        description = f"AC-2035 auto-block: {ao.get('token_id')} {now_iso()}"
        url = f"{_API}/zones/{zone_id}/firewall/rules"
        payload = [{
            "action": "block",
            "description": description,
            "filter": {"expression": f"(ip.src eq {entry_ip})"},
        }]
        headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

        try:
            resp = httpx.post(url, headers=headers, json=payload, timeout=_TIMEOUT)
            resp.raise_for_status()
            result = resp.json().get("result")
            rule_id = filter_id = None
            if isinstance(result, list) and result:
                rule_id = result[0].get("id")
                filter_id = (result[0].get("filter") or {}).get("id")
            logger.info("Cloudflare block rule created for {} (rule {})", entry_ip, rule_id)
            return make_action(
                self.action_type,
                entry_ip,
                True,
                None,
                rollback_state={"zone_id": zone_id, "rule_id": rule_id, "filter_id": filter_id},
            )
        except httpx.HTTPError as e:
            logger.warning("Cloudflare IP block failed for {}: {}", entry_ip, e)
            return make_action(self.action_type, entry_ip, False, str(e))
        except Exception as e:
            logger.warning("Unexpected error during Cloudflare IP block for {}: {}", entry_ip, e)
            return make_action(self.action_type, entry_ip, False, str(e))

    def verify(self, attack, result: ActionResult) -> bool:
        """Re-fetch the firewall rule created by execute() and confirm it still
        exists (U3)."""
        state = result.rollback_state or {}
        zone_id = state.get("zone_id") or env_secret("CLOUDFLARE_ZONE_ID")
        rule_id = state.get("rule_id")
        api_token = env_secret("CLOUDFLARE_API_TOKEN")
        if not zone_id or not rule_id or not api_token:
            return False
        headers = {"Authorization": f"Bearer {api_token}"}
        try:
            resp = httpx.get(f"{_API}/zones/{zone_id}/firewall/rules/{rule_id}", headers=headers, timeout=_TIMEOUT)
            if resp.status_code == 200:
                logger.info("Verify: Cloudflare block rule {} present", rule_id)
                return True
            logger.warning("Verify: Cloudflare block rule {} missing ({})", rule_id, resp.status_code)
            return False
        except Exception as e:
            logger.warning("Cloudflare verify failed for rule {}: {}", rule_id, e)
            return False

    def rollback(self, attack, result: ActionResult) -> ActionResult:
        """Undo a block by deleting the firewall rule execute() created (U2).
        Reversible."""
        state = result.rollback_state or {}
        zone_id = state.get("zone_id") or env_secret("CLOUDFLARE_ZONE_ID")
        rule_id = state.get("rule_id")
        api_token = env_secret("CLOUDFLARE_API_TOKEN")
        action = f"{self.action_type}_rollback"
        if not zone_id or not rule_id or not api_token:
            return make_action(action, result.target, False, "nothing to roll back")
        headers = {"Authorization": f"Bearer {api_token}"}
        try:
            resp = httpx.delete(f"{_API}/zones/{zone_id}/firewall/rules/{rule_id}", headers=headers, timeout=_TIMEOUT)
            resp.raise_for_status()
            logger.warning("ROLLBACK: deleted Cloudflare block rule {}", rule_id)
            return make_action(action, result.target, True, None)
        except Exception as e:
            logger.error("Cloudflare rollback failed for rule {}: {}", rule_id, e)
            return make_action(action, result.target, False, str(e))

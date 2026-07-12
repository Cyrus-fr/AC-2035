"""Kill-switch action: block the attacker's entry IP at the Cloudflare edge
via the Firewall Rules API.

Degrades gracefully when creds or the entry IP are missing — never raises.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from loguru import logger

from killswitch import ActionResult, _as_dict, env_secret, make_action, now_iso

_ACTION = "cloudflare_ip_block"
_TIMEOUT = 30.0


def block_ip(attack_object) -> ActionResult:
    ao = _as_dict(attack_object)
    api_token = env_secret("CLOUDFLARE_API_TOKEN")
    zone_id = env_secret("CLOUDFLARE_ZONE_ID")

    if not api_token or not zone_id:
        logger.warning("Cloudflare credentials missing — skipping IP block")
        return make_action(_ACTION, ao.get("entry_point") or "", False, "Cloudflare credentials missing")

    entry_ip = ao.get("entry_point")
    if not entry_ip:
        logger.warning("No entry IP in attack path — skipping Cloudflare block")
        return make_action(_ACTION, "", False, "No entry IP in path")

    description = f"AC-2035 auto-block: {ao.get('token_id')} {now_iso()}"
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    # The Firewall Rules endpoint takes a list; an inline filter creates both
    # the filter and the blocking rule in one call.
    payload = [{
        "action": "block",
        "description": description,
        "filter": {"expression": f"(ip.src eq {entry_ip})"},
    }]
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    try:
        resp = httpx.post(url, headers=headers, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        logger.info("Cloudflare block rule created for {}", entry_ip)
        return make_action(_ACTION, entry_ip, True, None)
    except httpx.HTTPError as e:
        logger.warning("Cloudflare IP block failed for {}: {}", entry_ip, e)
        return make_action(_ACTION, entry_ip, False, str(e))
    except Exception as e:
        logger.warning("Unexpected error during Cloudflare IP block for {}: {}", entry_ip, e)
        return make_action(_ACTION, entry_ip, False, str(e))

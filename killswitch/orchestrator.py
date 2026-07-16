"""Kill-switch coordinator.

`execute(attack_object, mode)` fires every configured containment provider —
GCP IAM revoke, Cloudflare IP block, Zitadel session kill by default — in
parallel (auto mode) or stashes the attack for later `approve(pending_id)`
(manual mode). Every outcome is written to a JSON audit log.

Providers are loaded dynamically from killswitch/config.yaml (U2): adding a
control plane is a YAML line plus a Provider subclass, no edit here. After each
action fires it is optionally re-verified against the control plane (U3), and a
partial outcome can optionally trigger a compensating rollback (U2, default
OFF — see config.yaml).

Status semantics: every action fully ok -> executed; some ok, some not ->
partial; none ok -> failed. One failing provider never sinks the others.
"""

from __future__ import annotations

import importlib
import json
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from loguru import logger

from killswitch import AUDIT_DIR, ActionResult, KillSwitchResult, _as_dict, make_action, now_iso
from killswitch.providers.base import Provider

_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

# Fallback if config.yaml is missing/unreadable: the three built-in providers,
# verification on, rollback off (sticky containment).
_DEFAULT_CONFIG = {
    "providers": [
        {"name": "gcp", "class": "killswitch.providers.gcp:GCPProvider", "enabled": True},
        {"name": "cloudflare", "class": "killswitch.providers.cloudflare:CloudflareProvider", "enabled": True},
        {"name": "zitadel", "class": "killswitch.providers.zitadel:ZitadelProvider", "enabled": True},
    ],
    "verify_actions": True,
    "rollback_on_partial": False,
}

_config_cache: dict | None = None
_providers_cache: list[Provider] | None = None

# Manual-mode attacks awaiting analyst approval, keyed by pending_id.
_PENDING: dict[str, dict] = {}


def _load_config() -> dict:
    """Read killswitch/config.yaml once (cached). Falls back to built-in
    defaults, never crashing, if the file is missing or malformed."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache
    try:
        data = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "providers" not in data:
            raise ValueError("config.yaml missing a 'providers' list")
        _config_cache = data
    except Exception as e:
        logger.warning("Could not load {} ({}); using built-in defaults", _CONFIG_PATH.name, e)
        _config_cache = _DEFAULT_CONFIG
    return _config_cache


def _load_providers() -> list[Provider]:
    """Instantiate every enabled provider from config (cached, in config
    order). A provider that fails to import is logged and skipped, not fatal."""
    global _providers_cache
    if _providers_cache is not None:
        return _providers_cache
    providers: list[Provider] = []
    for entry in _load_config().get("providers", []):
        if not entry.get("enabled"):
            continue
        spec = entry.get("class", "")
        try:
            module_name, cls_name = spec.split(":")
            cls = getattr(importlib.import_module(module_name), cls_name)
            providers.append(cls())
        except Exception as e:
            logger.error("Failed to load kill-switch provider '{}' ({}): {}", entry.get("name"), spec, e)
    if not providers:
        logger.error("No kill-switch providers loaded — check killswitch/config.yaml")
    _providers_cache = providers
    return providers


def reload_providers() -> list[Provider]:
    """Clear the config/provider caches and reload. Lets tests swap
    config.yaml at runtime and prove dynamic loading needs no code change."""
    global _config_cache, _providers_cache
    _config_cache = None
    _providers_cache = None
    return _load_providers()


def pending_map() -> dict[str, dict]:
    """Snapshot of attacks awaiting approval (pending_id -> attack dict).
    Read-only accessor for the API layer."""
    return dict(_PENDING)


def _invoke(provider: Provider, ao) -> ActionResult:
    """Run one provider's execute(), capturing its worker thread + duration for
    the parallel-dispatch audit trail. Defends against a provider raising even
    though each is meant to be graceful."""
    tname = threading.current_thread().name
    start = time.perf_counter()
    try:
        result = provider.execute(ao)
    except Exception as e:  # pragma: no cover — providers shouldn't raise
        logger.error("[{}] {} crashed: {}", tname, provider.action_type, e)
        result = make_action(provider.action_type, "", False, f"handler crashed: {e}")
    dur_ms = (time.perf_counter() - start) * 1000
    logger.info("[{}] {} -> success={} ({:.1f}ms)", tname, result.action_type, result.success, dur_ms)
    return result


def _fire_all(providers: list[Provider], ao) -> list[ActionResult]:
    """Fire every provider concurrently and return results in config order."""
    results: list[ActionResult] = [None] * len(providers)  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=max(1, len(providers)), thread_name_prefix="killswitch") as pool:
        futures = {pool.submit(_invoke, provider, ao): idx for idx, provider in enumerate(providers)}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return results


def _fully_ok(a: ActionResult) -> bool:
    """An action is a full success only if it fired AND (when we verified)
    verification confirmed it. verified is None when verification is off or not
    applicable, which still counts as ok (U3)."""
    return bool(a.success) and a.verified is not False


def _status(actions: list[ActionResult]) -> str:
    ok = sum(1 for a in actions if _fully_ok(a))
    if actions and ok == len(actions):
        return "executed"
    if ok == 0:
        return "failed"
    return "partial"


def _save_audit(result: KillSwitchResult) -> Path:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    # Microsecond precision so several fires for one token in the same second
    # (e.g. an auto run plus a manual approve) never overwrite each other.
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = AUDIT_DIR / f"{result.attack_object_token_id}_{ts}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    logger.info("Audit log written: {}", path)
    return path


def _rollback(providers: list[Provider], ao: dict, actions: list[ActionResult]) -> None:
    """Compensating transaction (U2): undo the actions that succeeded, in-place
    recording the attempt on each action for the audit trail.

    SECURITY NOTE: this rolls back *successful* containment (e.g. un-blocks the
    attacker's IP) to restore an all-or-nothing state. That can re-expose the
    attacker, which is why the caller only invokes this when the operator has
    explicitly opted in via rollback_on_partial (default OFF)."""
    logger.warning("rollback_on_partial=true and status=partial -> rolling back succeeded actions")
    for provider, action in zip(providers, actions):
        if not action.success:
            continue
        try:
            rb = provider.rollback(ao, action)
        except Exception as e:  # pragma: no cover — rollback shouldn't raise
            logger.error("rollback() crashed for {}: {}", provider.action_type, e)
            rb = make_action(f"{provider.action_type}_rollback", action.target, False, f"rollback crashed: {e}")
        action.rolled_back = bool(rb.success)
        # Fold the rollback outcome into the action's audit record.
        action.rollback_state = {**(action.rollback_state or {}), "rollback": rb.to_dict()}
        logger.warning("ROLLBACK {} -> success={} ({})", action.action_type, rb.success, rb.error or "ok")


def _notify_killswitch(result: KillSwitchResult, actions: list[ActionResult]) -> None:
    """Best-effort external alert on every kill-switch fire (U0). Path-
    independent (auto / approve / API all funnel through here). Never blocks or
    breaks the pipeline — the notifier itself dispatches on a daemon thread."""
    try:
        import notifier

        notifier.notify(
            "killswitch_fired",
            token_id=result.attack_object_token_id,
            summary=f"AC-2035 kill-switch {result.status} for token {result.attack_object_token_id}",
            fields={
                "status": result.status,
                "triggered_by": result.triggered_by,
                "actions": f"{sum(1 for a in actions if a.success)}/{len(actions)} succeeded",
            },
            severity="warning" if result.status == "executed" else "critical",
        )
    except Exception as e:  # pragma: no cover — notifier is non-fatal
        logger.warning("Notifier hook failed (non-fatal): {}", e)


def _execute_now(ao: dict, pending_id: str, triggered_by: str) -> KillSwitchResult:
    token_id = ao.get("token_id", "")
    providers = _load_providers()
    logger.info("Firing kill-switch for token {} ({} mode, {} providers)", token_id, triggered_by, len(providers))
    actions = _fire_all(providers, ao)

    # U3 — re-fetch each control plane and confirm the action took effect. A
    # fired-but-unverified action has verified=False, which _status treats as
    # not-fully-ok, dropping the run to "partial".
    cfg = _load_config()
    if cfg.get("verify_actions", True):
        for provider, action in zip(providers, actions):
            if not action.success:
                continue
            try:
                action.verified = provider.verify(ao, action)
            except Exception as e:  # pragma: no cover — verify shouldn't raise
                logger.error("verify() crashed for {}: {}", provider.action_type, e)
                action.verified = False
            if action.verified is False:
                logger.warning("Action {} fired but VERIFICATION FAILED -> partial", action.action_type)

    # U2 — compensating rollback. DEFAULT OFF (sticky containment). Only when
    # explicitly enabled AND the run is partial do we undo the actions that DID
    # succeed. Rolling back successful containment can re-expose the attacker,
    # which is exactly why this is opt-in (see killswitch/config.yaml).
    status = _status(actions)
    if cfg.get("rollback_on_partial", False) and status == "partial":
        _rollback(providers, ao, actions)

    result = KillSwitchResult(
        pending_id=pending_id,
        status=status,
        attack_object_token_id=token_id,
        actions=actions,
        executed_at=now_iso(),
        triggered_by=triggered_by,
    )
    result.audit_path = str(_save_audit(result))
    logger.info(
        "Kill-switch for token {} -> {} ({}/{} actions succeeded)",
        token_id, result.status, sum(1 for a in actions if a.success), len(actions),
    )
    _notify_killswitch(result, actions)
    return result


def execute(attack_object, mode: str = "auto") -> KillSwitchResult:
    """Auto mode fires all configured actions in parallel immediately. Manual
    mode stores the attack and returns a pending result to be approved."""
    ao = _as_dict(attack_object)
    token_id = ao.get("token_id", "")
    pending_id = str(uuid.uuid4())

    if mode == "manual":
        _PENDING[pending_id] = ao
        logger.info("Kill-switch for token {} staged as pending ({})", token_id, pending_id)
        result = KillSwitchResult(
            pending_id=pending_id,
            status="pending",
            attack_object_token_id=token_id,
            actions=[],
            executed_at=None,
            triggered_by="analyst",
        )
        result.audit_path = str(_save_audit(result))
        return result

    return _execute_now(ao, pending_id, triggered_by="auto")


def approve(pending_id: str) -> KillSwitchResult:
    """Fire a previously staged (manual-mode) kill-switch."""
    ao = _PENDING.pop(pending_id, None)
    if ao is None:
        logger.warning("No pending kill-switch found for id {}", pending_id)
        return KillSwitchResult(
            pending_id=pending_id,
            status="failed",
            attack_object_token_id="",
            actions=[],
            executed_at=now_iso(),
            triggered_by="analyst",
        )
    return _execute_now(ao, pending_id, triggered_by="analyst")

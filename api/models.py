"""Pydantic response (and request) models for the AC-2035 API.

Complex nested payloads that originate as dataclasses (AttackObject,
KillSwitchResult) or dynamic graph elements are typed as open dicts — the
routes hand back their `.to_dict()` form — while scalar/among summary
responses are fully typed.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str


# ── graph ──────────────────────────────────────────────────────────────────
class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)


class GraphStats(BaseModel):
    node_count: int
    edge_count: int
    honeytoken_count: int
    external_ip_count: int
    pod_count: int


class ClearResponse(BaseModel):
    cleared: bool


# ── alerts ─────────────────────────────────────────────────────────────────
class TriggerEventBody(BaseModel):
    token_id: str
    token_type: str
    trigger_time: str
    pod_name: str
    pod_namespace: str
    process_name: str
    pid: int
    source: str = "ebpf"


class TriggerResponse(BaseModel):
    attack_object: dict[str, Any]
    killswitch_result: dict[str, Any]


# ── tokens ─────────────────────────────────────────────────────────────────
class TokenItem(BaseModel):
    token_id: str
    token_type: str
    target_pod: Optional[str] = None
    target_namespace: Optional[str] = None
    secret_manager_path: Optional[str] = None
    injected_at: Optional[str] = None
    last_rotated_at: Optional[str] = None
    status: str
    # token_value is intentionally NOT exposed by the API.


class RotateResponse(BaseModel):
    rotated: int


# ── kill-switch ────────────────────────────────────────────────────────────
class PendingItem(BaseModel):
    pending_id: str
    token_id: Optional[str] = None
    entry_point: Optional[str] = None
    confidence: Optional[str] = None


class KillSwitchActionModel(BaseModel):
    action_type: str
    target: str
    success: bool
    error: Optional[str] = None
    timestamp: str


class KillSwitchResultResponse(BaseModel):
    pending_id: str
    status: str
    attack_object_token_id: str
    actions: list[KillSwitchActionModel] = Field(default_factory=list)
    executed_at: Optional[str] = None
    triggered_by: str


class MessageResponse(BaseModel):
    message: str

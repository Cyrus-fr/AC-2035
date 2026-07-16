"""U2/U3 kill-switch tests — provider abstraction, dynamic loading,
verification-aware status, and compensating rollback (default off).

Asserts (per the approved plan):
  - FakeProvider partial -> status==partial, rollback NOT called
    (rollback_on_partial=false), audit JSON reflects partial.
  - Verify-fail -> action counted not-ok -> status==partial.
  - Dynamic provider load from a temp config.yaml works with no code change.
"""

from __future__ import annotations

import json
from pathlib import Path

from killswitch import orchestrator
from tests import fake_providers

ATTACK = {
    "token_id": "test-token",
    "entry_point": "198.51.100.77",
    "movement_path": [
        {"from_node": "198.51.100.77", "to_node": "svc@proj.iam.gserviceaccount.com",
         "edge_type": "CONNECTED_TO"},
    ],
}


def _use_config(tmp_path: Path, yaml_text: str) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml_text, encoding="utf-8")
    orchestrator._CONFIG_PATH = cfg
    orchestrator.reload_providers()


_TWO_MIXED = """
providers:
  - {name: s, class: "tests.fake_providers:FakeSuccessProvider", enabled: true}
  - {name: f, class: "tests.fake_providers:FakeFailProvider", enabled: true}
verify_actions: true
rollback_on_partial: false
"""


def test_partial_no_rollback(tmp_path):
    fake_providers.CALLS.clear()
    _use_config(tmp_path, _TWO_MIXED)

    result = orchestrator.execute(ATTACK, mode="auto")

    assert result.status == "partial"
    # rollback_on_partial=false -> the succeeded action stays contained.
    assert not any(c[0] == "rollback" for c in fake_providers.CALLS)
    succeeded = next(a for a in result.actions if a.action_type == "fake_success")
    assert succeeded.rolled_back is None
    # Audit JSON on disk reflects the partial outcome.
    audit = json.loads(Path(result.audit_path).read_text(encoding="utf-8"))
    assert audit["status"] == "partial"


def test_verify_fail_is_partial(tmp_path):
    fake_providers.CALLS.clear()
    _use_config(tmp_path, """
providers:
  - {name: s, class: "tests.fake_providers:FakeSuccessProvider", enabled: true}
  - {name: v, class: "tests.fake_providers:FakeVerifyFailProvider", enabled: true}
verify_actions: true
rollback_on_partial: false
""")

    result = orchestrator.execute(ATTACK, mode="auto")

    assert result.status == "partial"
    vf = next(a for a in result.actions if a.action_type == "fake_verify_fail")
    assert vf.success is True and vf.verified is False


def test_all_verified_is_executed(tmp_path):
    _use_config(tmp_path, """
providers:
  - {name: s, class: "tests.fake_providers:FakeSuccessProvider", enabled: true}
verify_actions: true
rollback_on_partial: false
""")

    result = orchestrator.execute(ATTACK, mode="auto")

    assert result.status == "executed"
    assert result.actions[0].verified is True


def test_dynamic_provider_load_no_code_change(tmp_path):
    # A provider the orchestrator has never heard of, wired purely via YAML.
    _use_config(tmp_path, """
providers:
  - {name: s, class: "tests.fake_providers:FakeSuccessProvider", enabled: true}
  - {name: v, class: "tests.fake_providers:FakeVerifyFailProvider", enabled: false}
verify_actions: true
rollback_on_partial: false
""")

    providers = orchestrator.reload_providers()
    # Only the enabled one loads; disabled entry is skipped — no code touched.
    assert [p.action_type for p in providers] == ["fake_success"]


def test_rollback_when_explicitly_enabled(tmp_path):
    fake_providers.CALLS.clear()
    _use_config(tmp_path, """
providers:
  - {name: s, class: "tests.fake_providers:FakeSuccessProvider", enabled: true}
  - {name: f, class: "tests.fake_providers:FakeFailProvider", enabled: true}
verify_actions: true
rollback_on_partial: true
""")

    result = orchestrator.execute(ATTACK, mode="auto")

    assert result.status == "partial"
    # Now the succeeded action IS rolled back (opt-in).
    assert ("rollback", "fake_success") in fake_providers.CALLS
    succeeded = next(a for a in result.actions if a.action_type == "fake_success")
    assert succeeded.rolled_back is True
    # The failed action was never rolled back.
    assert ("rollback", "fake_fail") not in fake_providers.CALLS

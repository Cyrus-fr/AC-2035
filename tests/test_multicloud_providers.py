"""U10 — AWS + Azure provider tests (Windows, injected fake SDK clients).

Covers graceful degradation when the SDK/creds are absent, and the full
execute/verify/rollback lifecycle against in-memory fakes (no AWS/Azure).
"""

from __future__ import annotations

from killswitch.providers.aws import AWSProvider, _extract_aws_user
from killswitch.providers.azure import AzureProvider, _extract_principal

# ── attack fixtures with provider-shaped identity nodes ──────────────────────
AWS_ATTACK = {
    "token_id": "tok",
    "movement_path": [
        {"from_node": "198.51.100.5",
         "to_node": "arn:aws:iam::123456789012:user/compromised-svc",
         "edge_type": "CONNECTED_TO"},
    ],
}
_PRINCIPAL = "11111111-2222-3333-4444-555555555555"
AZURE_ATTACK = {
    "token_id": "tok",
    "movement_path": [
        {"from_node": "198.51.100.5", "to_node": _PRINCIPAL, "edge_type": "CONNECTED_TO"},
    ],
}


# ── fake boto3 IAM client ────────────────────────────────────────────────────
class FakeIam:
    def __init__(self, user, attached, inline):
        self.users = {user: {"attached": list(attached), "inline": dict(inline)}}
        self.calls: list = []

    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": list(self.users[UserName]["attached"])}

    def detach_user_policy(self, UserName, PolicyArn):
        self.calls.append(("detach", PolicyArn))
        self.users[UserName]["attached"] = [
            p for p in self.users[UserName]["attached"] if p["PolicyArn"] != PolicyArn]

    def list_user_policies(self, UserName):
        return {"PolicyNames": list(self.users[UserName]["inline"].keys())}

    def get_user_policy(self, UserName, PolicyName):
        return {"PolicyName": PolicyName, "PolicyDocument": self.users[UserName]["inline"][PolicyName]}

    def delete_user_policy(self, UserName, PolicyName):
        self.calls.append(("delete_inline", PolicyName))
        self.users[UserName]["inline"].pop(PolicyName, None)

    def attach_user_policy(self, UserName, PolicyArn):
        self.calls.append(("attach", PolicyArn))
        self.users[UserName]["attached"].append(
            {"PolicyArn": PolicyArn, "PolicyName": PolicyArn.split("/")[-1]})

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        self.calls.append(("put_inline", PolicyName, PolicyDocument))
        self.users[UserName]["inline"][PolicyName] = PolicyDocument


def _fake_iam():
    return FakeIam(
        "compromised-svc",
        attached=[{"PolicyName": "AdminAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                  {"PolicyName": "S3", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}],
        inline={"inline-exfil": {"Version": "2012-10-17", "Statement": []}},
    )


# ── fake Azure authorization client ──────────────────────────────────────────
class _RoleAssignment:
    def __init__(self, id, name, scope, role_definition_id):
        self.id = id
        self.name = name
        self.scope = scope
        self.role_definition_id = role_definition_id


class FakeRoleAssignments:
    def __init__(self, assignments):
        self._assignments = list(assignments)
        self.calls: list = []

    def list_for_subscription(self, filter=None):
        return list(self._assignments)

    def delete_by_id(self, id):
        self.calls.append(("delete", id))
        self._assignments = [a for a in self._assignments if a.id != id]

    def create(self, scope, name, params):
        self.calls.append(("create", scope, params))
        self._assignments.append(_RoleAssignment(
            id=f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            name=name, scope=scope, role_definition_id=params.get("role_definition_id")))


class FakeAuthClient:
    def __init__(self, assignments):
        self.role_assignments = FakeRoleAssignments(assignments)


def _fake_auth():
    scope = "/subscriptions/sub-123"
    return FakeAuthClient([
        _RoleAssignment(id=f"{scope}/.../ra-1", name="ra-1", scope=scope,
                        role_definition_id="/rd/Owner"),
        _RoleAssignment(id=f"{scope}/.../ra-2", name="ra-2", scope=scope,
                        role_definition_id="/rd/Contributor"),
    ])


# ── identity extraction ──────────────────────────────────────────────────────
def test_extract_aws_user_from_arn():
    assert _extract_aws_user(AWS_ATTACK) == "compromised-svc"


def test_extract_azure_principal_guid():
    assert _extract_principal(AZURE_ATTACK) == _PRINCIPAL


# ── graceful degradation (no SDK / creds on the test box) ────────────────────
def test_aws_available_false_without_sdk_or_creds():
    usable, reason = AWSProvider().available()
    assert usable is False and reason


def test_azure_available_false_without_sdk_or_creds():
    usable, reason = AzureProvider().available()
    assert usable is False and reason


def test_aws_execute_failed_when_unavailable():
    result = AWSProvider().execute(AWS_ATTACK)  # no injected client
    assert result.success is False and result.error


def test_azure_execute_failed_when_unavailable():
    result = AzureProvider().execute(AZURE_ATTACK)
    assert result.success is False and result.error


# ── AWS lifecycle with an injected fake client ───────────────────────────────
def test_aws_execute_strips_and_captures():
    iam = _fake_iam()
    result = AWSProvider(iam_client=iam).execute(AWS_ATTACK)

    assert result.success is True
    assert result.target == "compromised-svc"
    state = result.rollback_state
    assert len(state["attached_policies"]) == 2
    assert "inline-exfil" in state["inline_policies"]
    # Both managed policies detached + the inline policy deleted.
    assert sum(1 for c in iam.calls if c[0] == "detach") == 2
    assert ("delete_inline", "inline-exfil") in iam.calls
    # And the user is actually stripped now.
    assert iam.list_attached_user_policies(UserName="compromised-svc")["AttachedPolicies"] == []


def test_aws_verify_and_rollback():
    iam = _fake_iam()
    provider = AWSProvider(iam_client=iam)
    result = provider.execute(AWS_ATTACK)
    # After stripping, verify sees an empty user.
    assert provider.verify(AWS_ATTACK, result) is True
    # Roll back: policies restored.
    rb = provider.rollback(AWS_ATTACK, result)
    assert rb.success is True
    assert sum(1 for c in iam.calls if c[0] == "attach") == 2
    assert any(c[0] == "put_inline" for c in iam.calls)
    assert provider.verify(AWS_ATTACK, result) is False  # policies are back


def test_aws_execute_no_user_in_path():
    iam = _fake_iam()
    result = AWSProvider(iam_client=iam).execute({"token_id": "t", "movement_path": []})
    assert result.success is False and "No AWS IAM user" in result.error


# ── Azure lifecycle with an injected fake client ─────────────────────────────
def test_azure_execute_revokes_and_captures():
    client = _fake_auth()
    result = AzureProvider(auth_client=client).execute(AZURE_ATTACK)

    assert result.success is True
    assert result.target == _PRINCIPAL
    assert len(result.rollback_state["role_assignments"]) == 2
    assert sum(1 for c in client.role_assignments.calls if c[0] == "delete") == 2


def test_azure_verify_and_rollback():
    client = _fake_auth()
    provider = AzureProvider(auth_client=client)
    result = provider.execute(AZURE_ATTACK)
    # All assignments gone -> verified.
    assert provider.verify(AZURE_ATTACK, result) is True
    # Roll back re-creates them.
    rb = provider.rollback(AZURE_ATTACK, result)
    assert rb.success is True
    assert sum(1 for c in client.role_assignments.calls if c[0] == "create") == 2
    assert provider.verify(AZURE_ATTACK, result) is False  # assignments restored


def test_azure_execute_no_principal_in_path():
    client = _fake_auth()
    result = AzureProvider(auth_client=client).execute({"token_id": "t", "movement_path": []})
    assert result.success is False and "No Azure principal" in result.error

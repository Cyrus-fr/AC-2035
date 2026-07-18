"""AWS IAM kill-switch provider (U10): strip every managed + inline policy from
the compromised IAM user.

Mirrors the GCP provider's contract — self-guards inside execute() (never raises
to the orchestrator), records what it removed in rollback_state so the action is
reversible (U2) and re-verifiable (U3), and degrades gracefully when boto3 or AWS
credentials are absent. The boto3 client is injectable (`iam_client=`) so the
execute/verify/rollback logic is unit-testable without AWS.

Live IAM revocation is ARTIFACT-ONLY here (needs real AWS credentials). Ships
disabled in killswitch/config.yaml; enable it once creds are present.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loguru import logger

from killswitch import ActionResult, env_secret, extract_identity, make_action
from killswitch.providers.base import Provider

# Compromised-user ARN in the reconstructed movement path, e.g.
# arn:aws:iam::123456789012:user/compromised-svc
_ARN_USER_RE = re.compile(r"arn:aws:iam::\d+:user/(?P<name>[\w+=,.@-]+)")


def _extract_aws_user(attack) -> Optional[str]:
    """First AWS IAM user name in the reconstructed movement path, or None.

    Provider-local (the shared killswitch.extract_identity regex targets GCP
    service accounts / emails and would not match an AWS ARN), so the public
    helper stays unchanged. Falls back to extract_identity for an email-shaped
    principal that also happens to be an IAM user name.
    """
    ao = attack.to_dict() if hasattr(attack, "to_dict") else attack
    for hop in ao.get("movement_path", []):
        for node in (hop.get("from_node"), hop.get("to_node")):
            if node:
                m = _ARN_USER_RE.search(node)
                if m:
                    return m.group("name")
    # Fall back to the shared extractor (e.g. an email-shaped IAM user name).
    return extract_identity(attack)


class AWSProvider(Provider):
    action_type = "aws_iam_revoke"

    def __init__(self, iam_client=None):
        # Injected by tests; None in production -> built lazily from boto3.
        self._iam_client = iam_client

    def available(self) -> tuple[bool, str]:
        try:
            import boto3  # noqa: F401
        except ImportError:
            return (False, "boto3 not installed (pip install boto3)")
        if not env_secret("AWS_ACCESS_KEY_ID"):
            return (False, "AWS_ACCESS_KEY_ID missing")
        if not env_secret("AWS_REGION"):
            return (False, "AWS_REGION missing")
        return (True, "")

    def _iam(self):
        """Return an IAM client (injected or freshly built), or None when the
        provider is unavailable."""
        if self._iam_client is not None:
            return self._iam_client
        usable, reason = self.available()
        if not usable:
            logger.error("AWS provider unavailable: {}", reason)
            return None
        try:
            import boto3

            return boto3.client("iam", region_name=env_secret("AWS_REGION"))
        except Exception as e:  # pragma: no cover - needs boto3 present
            logger.error("Failed to build AWS IAM client: {}", e)
            return None

    def execute(self, attack) -> ActionResult:
        iam = self._iam()
        if iam is None:
            _, reason = self.available()
            return make_action(self.action_type, "", False, reason or "AWS provider unavailable")

        user = _extract_aws_user(attack)
        if not user:
            logger.warning("No AWS IAM user in attack path - skipping IAM revoke")
            return make_action(self.action_type, "", False, "No AWS IAM user in path")

        try:
            attached = iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", [])
            removed_arns: list[str] = []
            for policy in attached:
                arn = policy.get("PolicyArn")
                if arn:
                    iam.detach_user_policy(UserName=user, PolicyArn=arn)
                    removed_arns.append(arn)

            inline_names = iam.list_user_policies(UserName=user).get("PolicyNames", [])
            inline_policies: dict[str, object] = {}
            for name in inline_names:
                doc = iam.get_user_policy(UserName=user, PolicyName=name).get("PolicyDocument")
                inline_policies[name] = doc
                iam.delete_user_policy(UserName=user, PolicyName=name)

            if not removed_arns and not inline_policies:
                logger.info("AWS user {} had no policies to strip", user)
                return make_action(self.action_type, user, False, f"No policies for {user}")

            logger.info("Stripped {} managed + {} inline policy(ies) from AWS user {}",
                        len(removed_arns), len(inline_policies), user)
            return make_action(
                self.action_type,
                user,
                True,
                None,
                rollback_state={
                    "user_name": user,
                    "attached_policies": removed_arns,
                    # Enriched beyond {inline_policy_names}: the documents are
                    # captured so inline policies can actually be re-created.
                    "inline_policies": inline_policies,
                },
            )
        except Exception as e:
            logger.warning("AWS IAM revoke failed for {}: {}", user, e)
            return make_action(self.action_type, user, False, str(e))

    def verify(self, attack, result: ActionResult) -> bool:
        """Re-fetch the user's policies and confirm they're all gone (U3)."""
        state = result.rollback_state or {}
        user = state.get("user_name") or _extract_aws_user(attack)
        iam = self._iam()
        if not user or iam is None:
            return False
        try:
            attached = iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", [])
            inline = iam.list_user_policies(UserName=user).get("PolicyNames", [])
            if attached or inline:
                logger.warning("Verify: AWS user {} still has {} managed / {} inline policy(ies)",
                               user, len(attached), len(inline))
                return False
            logger.info("Verify: AWS user {} has no remaining policies", user)
            return True
        except Exception as e:
            logger.warning("AWS IAM verify failed for {}: {}", user, e)
            return False

    def rollback(self, attack, result: ActionResult) -> ActionResult:
        """Re-attach the managed policies and re-create the inline policies that
        execute() removed (U2). Reversible."""
        state = result.rollback_state or {}
        user = state.get("user_name")
        attached = state.get("attached_policies") or []
        inline = state.get("inline_policies") or {}
        action = f"{self.action_type}_rollback"
        if not user or (not attached and not inline):
            return make_action(action, user or "", False, "nothing to roll back")
        iam = self._iam()
        if iam is None:
            return make_action(action, user, False, "AWS provider unavailable")
        try:
            for arn in attached:
                iam.attach_user_policy(UserName=user, PolicyArn=arn)
            for name, doc in inline.items():
                body = doc if isinstance(doc, str) else json.dumps(doc)
                iam.put_user_policy(UserName=user, PolicyName=name, PolicyDocument=body)
            logger.warning("ROLLBACK: restored {} managed + {} inline policy(ies) to AWS user {}",
                           len(attached), len(inline), user)
            return make_action(action, user, True, None)
        except Exception as e:
            logger.error("AWS IAM rollback failed for {}: {}", user, e)
            return make_action(action, user, False, str(e))

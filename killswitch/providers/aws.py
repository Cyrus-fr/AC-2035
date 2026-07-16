"""AWS kill-switch provider — STUB (U2).

The full implementation (IAM role/credential revocation via the AWS SDK) is
deferred to U10 (Research tier). Enabling this provider before then requires
adding boto3 and implementing execute()/verify()/rollback(). It ships disabled
in killswitch/config.yaml.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loguru import logger

from killswitch import ActionResult, make_action
from killswitch.providers.base import Provider

_NOT_IMPL = "AWS provider not implemented yet (see U10)"


class AWSProvider(Provider):
    action_type = "aws_iam_revoke"

    def available(self) -> tuple[bool, str]:
        return (False, _NOT_IMPL)

    def execute(self, attack) -> ActionResult:
        logger.warning("AWSProvider.execute called but {}", _NOT_IMPL)
        return make_action(self.action_type, "", False, _NOT_IMPL)

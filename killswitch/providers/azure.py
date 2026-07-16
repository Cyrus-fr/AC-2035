"""Azure kill-switch provider — STUB (U2).

The full implementation (Azure AD token/session revocation via the Azure SDK)
is deferred to U10 (Research tier). Enabling this provider before then requires
adding azure-identity/azure-mgmt-* and implementing execute()/verify()/
rollback(). It ships disabled in killswitch/config.yaml.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loguru import logger

from killswitch import ActionResult, make_action
from killswitch.providers.base import Provider

_NOT_IMPL = "Azure provider not implemented yet (see U10)"


class AzureProvider(Provider):
    action_type = "azure_ad_revoke"

    def available(self) -> tuple[bool, str]:
        return (False, _NOT_IMPL)

    def execute(self, attack) -> ActionResult:
        logger.warning("AzureProvider.execute called but {}", _NOT_IMPL)
        return make_action(self.action_type, "", False, _NOT_IMPL)

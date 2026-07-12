"""Generates cryptographically convincing fake credentials (honeytokens).

Token values are structurally realistic — correct prefixes, lengths, JSON
shape, PEM framing — but built entirely from random bytes. None of them are
live, functioning credentials.
"""

from __future__ import annotations

import base64
import json
import random
import secrets
import string
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass
class Token:
    token_id: str
    token_type: str
    token_value: str
    created_at: str
    target_pod: Optional[str]
    target_namespace: Optional[str]

    def to_dict(self) -> dict:
        return asdict(self)


_ENV_WORDS = ["prod", "staging", "dev"]
_PROJECT_WORDS = [
    "data-platform", "billing-sync", "analytics-core", "auth-service",
    "payments-hub", "inventory-svc", "ml-pipeline", "user-events",
    "orders-backend", "reporting-svc",
]
_SA_NAMES = [
    "svc-billing-sync", "svc-data-ingest", "svc-reporting", "svc-ml-infer",
    "svc-order-proc", "svc-auth-bridge", "svc-inventory-sync", "svc-events-writer",
]
_DB_HOST_WORDS = ["db-prod", "db-replica", "db-analytics", "db-primary", "db-staging"]
_DB_REGIONS = ["us-central1", "us-east1", "europe-west1", "asia-southeast1"]
_DB_NAMES = ["analytics_prod", "billing_db", "orders_db", "inventory_db", "users_db"]
_DB_USERS = ["svc_reporting", "svc_ingest", "svc_billing", "app_readonly", "svc_migrator"]


def _rand_hex(n: int) -> str:
    return secrets.token_hex(n)


def _rand_alphanumeric(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _rand_project_id() -> str:
    return f"{random.choice(_ENV_WORDS)}-{random.choice(_PROJECT_WORDS)}-{_rand_hex(3)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fake_pem_private_key() -> str:
    """Structurally valid PEM framing filled with random bytes — never a
    real, usable key."""
    raw = secrets.token_bytes(1192)  # ~ RSA-2048 PKCS8 DER size
    b64 = base64.b64encode(raw).decode("ascii")
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"


def generate_gcp_key(
    target_pod: Optional[str] = None, target_namespace: Optional[str] = None
) -> Token:
    project_id = _rand_project_id()
    sa_name = random.choice(_SA_NAMES)
    client_email = f"{sa_name}@{project_id}.iam.gserviceaccount.com"

    key_dict = {
        "type": "service_account",
        "project_id": project_id,
        "private_key_id": _rand_hex(20),
        "private_key": _fake_pem_private_key(),
        "client_email": client_email,
        "client_id": str(secrets.randbelow(10**20)).zfill(21),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": (
            f"https://www.googleapis.com/robot/v1/metadata/x509/"
            f"{sa_name}%40{project_id}.iam.gserviceaccount.com"
        ),
        "universe_domain": "googleapis.com",
    }

    return Token(
        token_id=str(uuid.uuid4()),
        token_type="gcp_key",
        token_value=json.dumps(key_dict, indent=2),
        created_at=_now_iso(),
        target_pod=target_pod,
        target_namespace=target_namespace,
    )


def generate_gcp_api_key(
    target_pod: Optional[str] = None, target_namespace: Optional[str] = None
) -> Token:
    prefix = "AIza"
    value = prefix + _rand_alphanumeric(35 - len(prefix))

    return Token(
        token_id=str(uuid.uuid4()),
        token_type="gcp_api_key",
        token_value=value,
        created_at=_now_iso(),
        target_pod=target_pod,
        target_namespace=target_namespace,
    )


def generate_db_connection(
    target_pod: Optional[str] = None, target_namespace: Optional[str] = None
) -> Token:
    scheme = random.choice(["postgresql", "mysql"])
    user = random.choice(_DB_USERS)
    password = _rand_alphanumeric(16)
    host = f"{random.choice(_DB_HOST_WORDS)}-{random.choice(_DB_REGIONS)}.internal"
    port = 5432 if scheme == "postgresql" else 3306
    dbname = random.choice(_DB_NAMES)

    value = f"{scheme}://{user}:{password}@{host}:{port}/{dbname}"

    return Token(
        token_id=str(uuid.uuid4()),
        token_type="db_connection",
        token_value=value,
        created_at=_now_iso(),
        target_pod=target_pod,
        target_namespace=target_namespace,
    )


def generate_api_token(
    target_pod: Optional[str] = None, target_namespace: Optional[str] = None
) -> Token:
    value = f"Bearer {secrets.token_hex(32)}"

    return Token(
        token_id=str(uuid.uuid4()),
        token_type="api_token",
        token_value=value,
        created_at=_now_iso(),
        target_pod=target_pod,
        target_namespace=target_namespace,
    )


_GENERATORS: dict[str, Callable[..., Token]] = {
    "gcp_key": generate_gcp_key,
    "gcp_api_key": generate_gcp_api_key,
    "db_connection": generate_db_connection,
    "api_token": generate_api_token,
}


def generate(
    token_type: str, target_pod: Optional[str] = None, target_namespace: Optional[str] = None
) -> Token:
    try:
        fn = _GENERATORS[token_type]
    except KeyError:
        raise ValueError(
            f"Unknown token_type {token_type!r}. Supported: {sorted(_GENERATORS)}"
        ) from None
    return fn(target_pod=target_pod, target_namespace=target_namespace)

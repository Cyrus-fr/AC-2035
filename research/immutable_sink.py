"""U11 — immutable GCS audit sink (application side).

Streams raw telemetry (FIRST) and processed results / kill-switch audit
(SECOND) to the GCS Object-Lock bucket provisioned in infra/storage.tf, before
any backtrace processing runs. Writing raw events first means an attacker who
compromises the cluster after the fact cannot alter what was already recorded.

Live GCS is ARTIFACT-ONLY here (needs a real project + the Object-Lock bucket +
google-cloud-storage). Without a client/bucket the sink degrades to a gitignored
local mirror so the flow is still exercised. Every write is best-effort — the
sink never crashes its caller.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

LOCAL_MIRROR = Path(__file__).resolve().parent / "immutable_local"
_PLACEHOLDER_PREFIXES = ("your-", "change-me")


def _env(name: str) -> str:
    val = os.getenv(name, "").strip()
    if not val or val.lower().startswith(_PLACEHOLDER_PREFIXES):
        return ""
    return val


def _default_bucket() -> str:
    bucket = _env("AUDIT_GCS_BUCKET")
    if bucket:
        return bucket
    project = _env("GCP_PROJECT_ID")
    return f"ac2035-audit-{project}" if project else ""  # matches infra/storage.tf


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


class ImmutableSink:
    def __init__(self, client=None, bucket: Optional[str] = None):
        self.bucket_name = bucket if bucket is not None else _default_bucket()
        self._client = client
        if self._client is None and self.bucket_name:
            self._client = self._make_client()

    def _make_client(self):
        try:
            from google.cloud import storage

            return storage.Client()
        except Exception as e:  # google-cloud-storage absent or no creds
            logger.warning("GCS client unavailable ({}) — sink will mirror locally", e)
            return None

    def _write(self, blob_path: str, data: dict) -> str:
        body = json.dumps(data, indent=2, default=str)
        if self._client and self.bucket_name:
            try:
                blob = self._client.bucket(self.bucket_name).blob(blob_path)
                blob.upload_from_string(body, content_type="application/json")
                uri = f"gs://{self.bucket_name}/{blob_path}"
                logger.info("Immutable sink wrote {}", uri)
                return uri
            except Exception as e:
                logger.warning("GCS write failed for {} ({}) — mirroring locally", blob_path, e)
        local = LOCAL_MIRROR / blob_path
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(body, encoding="utf-8")
        logger.warning("Immutable sink mirrored locally: {}", local)
        return str(local)

    def write_raw_telemetry(self, token_id: str, events: list) -> str:
        """Write raw telemetry events FIRST, before any backtrace processing."""
        return self._write(f"raw/{token_id}/{_ts()}.json", {"token_id": token_id, "events": events})

    def write_audit(self, result: dict) -> str:
        """Write a processed kill-switch audit result SECOND."""
        token_id = result.get("attack_object_token_id") or result.get("token_id") or "unknown"
        return self._write(f"audit/{token_id}/{_ts()}.json", result)


# Module-level default sink + best-effort wrappers used by the pipeline hooks.
_default_sink: Optional[ImmutableSink] = None


def get_sink() -> ImmutableSink:
    global _default_sink
    if _default_sink is None:
        _default_sink = ImmutableSink()
    return _default_sink


def write_raw_telemetry(token_id: str, events: list) -> Optional[str]:
    try:
        return get_sink().write_raw_telemetry(token_id, events)
    except Exception as e:  # never fatal
        logger.warning("Immutable sink (raw) failed non-fatally: {}", e)
        return None


def write_audit(result: dict) -> Optional[str]:
    try:
        return get_sink().write_audit(result)
    except Exception as e:  # never fatal
        logger.warning("Immutable sink (audit) failed non-fatally: {}", e)
        return None

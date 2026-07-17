"""U11 — immutable sink tests (Windows, fake GCS client / local mirror)."""

from __future__ import annotations

import research.immutable_sink as sink_mod
from research.immutable_sink import ImmutableSink


class _FakeBlob:
    def __init__(self, store, name):
        self._store = store
        self._name = name

    def upload_from_string(self, body, content_type=None):
        self._store[self._name] = body


class _FakeBucket:
    def __init__(self, store):
        self._store = store

    def blob(self, name):
        return _FakeBlob(self._store, name)


class _FakeClient:
    def __init__(self):
        self.store: dict[str, str] = {}

    def bucket(self, name):
        return _FakeBucket(self.store)


def test_raw_and_audit_go_to_expected_paths():
    client = _FakeClient()
    sink = ImmutableSink(client=client, bucket="ac2035-audit-test")

    raw_uri = sink.write_raw_telemetry("tok1", [{"event_type": "vpc_flow"}])
    audit_uri = sink.write_audit({"attack_object_token_id": "tok1", "status": "executed"})

    keys = list(client.store.keys())
    assert any(k.startswith("raw/tok1/") for k in keys)
    assert any(k.startswith("audit/tok1/") for k in keys)
    assert raw_uri.startswith("gs://ac2035-audit-test/raw/tok1/")
    assert audit_uri.startswith("gs://ac2035-audit-test/audit/tok1/")


def test_raw_written_before_processed():
    client = _FakeClient()
    sink = ImmutableSink(client=client, bucket="b")
    sink.write_raw_telemetry("t", [{"e": 1}])
    sink.write_audit({"attack_object_token_id": "t"})
    keys = list(client.store.keys())  # dict preserves insertion order
    assert keys[0].startswith("raw/") and keys[1].startswith("audit/")


def test_no_client_mirrors_locally_and_is_non_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr(sink_mod, "LOCAL_MIRROR", tmp_path / "mirror")
    sink = ImmutableSink(client=None, bucket="")  # no client, no bucket -> mirror

    uri = sink.write_raw_telemetry("t", [{"e": 1}])

    assert "mirror" in uri
    files = list((tmp_path / "mirror").rglob("*.json"))
    assert files and files[0].read_text(encoding="utf-8")

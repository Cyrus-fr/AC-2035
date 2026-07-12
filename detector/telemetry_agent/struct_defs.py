"""ctypes mirrors of the C structs in detector/ebpf/honeytoken_watch.c.

The field order, types and sizes MUST match the C definitions exactly — the
kernel writes these structs into the ring buffer as raw bytes and Python
reads them back here. Both sides use natural (unpacked) alignment; ctypes
reproduces the C ABI layout on x86-64, and the assertions at the bottom of
this file fail loudly if that ever drifts.

Never carries or logs token_value — only the token_id *hash* and process
metadata.
"""

from __future__ import annotations

import ctypes

# ── token_type enum (matches the C comment + deployer token_type strings) ──
TOKEN_TYPE_TO_INT = {"gcp_key": 0, "gcp_api_key": 1, "db_connection": 2, "api_token": 3}
INT_TO_TOKEN_TYPE = {v: k for k, v in TOKEN_TYPE_TO_INT.items()}

# process_event.kind discriminator
PROC_EXEC = 1
PROC_EXIT = 2

# Field widths (must match the C arrays)
COMM_LEN = 16
POD_ID_LEN = 64
NAMESPACE_LEN = 32

_u8 = ctypes.c_uint8
_u32 = ctypes.c_uint32
_u64 = ctypes.c_uint64


class TokenMeta(ctypes.Structure):
    """struct token_meta — the value stored in the watched_inodes map."""

    _fields_ = [
        ("token_id_hash", _u32),
        ("token_type", _u8),
        ("pod_id", _u8 * POD_ID_LEN),
        ("namespace", _u8 * NAMESPACE_LEN),
    ]


class HoneytokenEvent(ctypes.Structure):
    """struct honeytoken_event — emitted on a watched-file access."""

    _fields_ = [
        ("inode", _u64),
        ("pid", _u32),
        ("tgid", _u32),
        ("uid", _u32),
        ("gid", _u32),
        ("token_id_hash", _u32),
        ("token_type", _u8),
        ("comm", _u8 * COMM_LEN),
        ("pod_id", _u8 * POD_ID_LEN),
        ("namespace", _u8 * NAMESPACE_LEN),
        ("timestamp_ns", _u64),
        ("flags", _u32),
    ]


class ProcessEvent(ctypes.Structure):
    """struct process_event — emitted on exec/exit for lineage context.

    Distinct in size from HoneytokenEvent so the agent can tell the two
    apart on a shared ring buffer purely by sample length."""

    _fields_ = [
        ("kind", _u8),
        ("pid", _u32),
        ("tgid", _u32),
        ("uid", _u32),
        ("ppid", _u32),
        ("comm", _u8 * COMM_LEN),
        ("timestamp_ns", _u64),
    ]


HONEYTOKEN_EVENT_SIZE = ctypes.sizeof(HoneytokenEvent)
PROCESS_EVENT_SIZE = ctypes.sizeof(ProcessEvent)
TOKEN_META_SIZE = ctypes.sizeof(TokenMeta)


# ── (de)serialization helpers ────────────────────────────────────────────

def fnv1a_32(data) -> int:
    """32-bit FNV-1a — the exact hash the loader stores as token_id_hash so
    the agent can reverse it against the registry. Must match any C-side
    implementation byte-for-byte."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _cstr(value: str, length: int) -> bytes:
    """Encode a str into a fixed-width, null-terminated C byte array."""
    raw = value.encode("utf-8")[: length - 1]
    return raw + b"\x00" * (length - len(raw))


def _from_cstr(arr) -> str:
    return bytes(arr).split(b"\x00", 1)[0].decode("utf-8", "replace")


def pack_token_meta(token_id: str, token_type: int, pod_id: str, namespace: str) -> bytes:
    meta = TokenMeta(
        token_id_hash=fnv1a_32(token_id),
        token_type=token_type & 0xFF,
    )
    meta.pod_id[:] = _cstr(pod_id, POD_ID_LEN)
    meta.namespace[:] = _cstr(namespace, NAMESPACE_LEN)
    return bytes(meta)


def encode_honeytoken_event(
    *, inode: int, pid: int, tgid: int, uid: int, gid: int, token_id_hash: int,
    token_type: int, comm: str, pod_id: str, namespace: str, timestamp_ns: int, flags: int = 0,
) -> bytes:
    """Build a raw honeytoken_event byte string — used by the agent's
    simulate_event() to exercise the decode path without a live kernel."""
    ev = HoneytokenEvent(
        inode=inode, pid=pid, tgid=tgid, uid=uid, gid=gid,
        token_id_hash=token_id_hash & 0xFFFFFFFF, token_type=token_type & 0xFF,
        timestamp_ns=timestamp_ns, flags=flags,
    )
    ev.comm[:] = _cstr(comm, COMM_LEN)
    ev.pod_id[:] = _cstr(pod_id, POD_ID_LEN)
    ev.namespace[:] = _cstr(namespace, NAMESPACE_LEN)
    return bytes(ev)


def decode_honeytoken_event(raw: bytes) -> dict:
    ev = HoneytokenEvent.from_buffer_copy(raw)
    return {
        "inode": ev.inode,
        "pid": ev.pid,
        "tgid": ev.tgid,
        "uid": ev.uid,
        "gid": ev.gid,
        "token_id_hash": ev.token_id_hash,
        "token_type": ev.token_type,
        "comm": _from_cstr(ev.comm),
        "pod_id": _from_cstr(ev.pod_id),
        "namespace": _from_cstr(ev.namespace),
        "timestamp_ns": ev.timestamp_ns,
        "flags": ev.flags,
    }


def decode_process_event(raw: bytes) -> dict:
    ev = ProcessEvent.from_buffer_copy(raw)
    return {
        "kind": ev.kind,
        "pid": ev.pid,
        "tgid": ev.tgid,
        "uid": ev.uid,
        "ppid": ev.ppid,
        "comm": _from_cstr(ev.comm),
        "timestamp_ns": ev.timestamp_ns,
    }


# ── layout guards: catch any drift from the C ABI at import time ───────────

def _assert_layout() -> None:
    expected_offsets = {
        "inode": 0, "pid": 8, "tgid": 12, "uid": 16, "gid": 20,
        "token_id_hash": 24, "token_type": 28, "comm": 29, "pod_id": 45,
        "namespace": 109, "timestamp_ns": 144, "flags": 152,
    }
    for name, off in expected_offsets.items():
        actual = getattr(HoneytokenEvent, name).offset
        if actual != off:
            raise AssertionError(f"HoneytokenEvent.{name} at offset {actual}, expected {off}")
    if HONEYTOKEN_EVENT_SIZE != 160:
        raise AssertionError(f"HoneytokenEvent is {HONEYTOKEN_EVENT_SIZE} bytes, expected 160")
    if PROCESS_EVENT_SIZE != 48:
        raise AssertionError(f"ProcessEvent is {PROCESS_EVENT_SIZE} bytes, expected 48")
    if TOKEN_META_SIZE != 104:
        raise AssertionError(f"TokenMeta is {TOKEN_META_SIZE} bytes, expected 104")


_assert_layout()

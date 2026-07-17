"""Loads honeytoken_watch.o into the kernel and manages the watched_inodes
map, via a thin ctypes wrapper over the system libbpf (libbpf.so).

Linux + root + kernel 5.7+ only (LSM BPF landed in 5.7). Off-Linux, or when
libbpf isn't installed, load_program() raises a clear error — callers
(agent / demo) fall back to simulation mode.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loguru import logger

from detector.telemetry_agent.struct_defs import pack_token_meta

_OBJECT_PATH = Path(__file__).resolve().parent / "honeytoken_watch.o"
_MIN_KERNEL = (5, 7)

# Programs to attach, keyed by the C function name (bpf_object__find_program_by_name).
_PROGRAMS = ["ac2035_file_open", "ac2035_file_permission", "ac2035_execve", "ac2035_process_exit"]

# U4 — pin maps under a restricted dir so they are tamper-evident (their
# disappearance is a signal, see verify_attached) and survive across restarts.
_PIN_DIR = "/sys/fs/bpf/ac2035"
_PINNED_MAPS = ["watched_inodes", "events"]

# ring_buffer sample callback: int (*)(void *ctx, void *data, size_t size)
_RINGBUF_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)


@dataclass
class LoadedProgram:
    """Handle to the loaded eBPF object: the libbpf object pointer, the
    watched_inodes map fd, the ring buffer fd, and attach links (kept alive
    so the kernel programs stay attached)."""

    lib: "ctypes.CDLL"
    obj: int
    watched_inodes_fd: int
    events_fd: int
    links: list = field(default_factory=list)
    attached: list = field(default_factory=list)  # names of successfully attached programs (U4)
    ringbuf: Optional[int] = None
    pin_dir: Optional[str] = None  # dir the maps are pinned under, if any (U4)
    _cb_ref: Optional[Callable] = None  # keep the CFUNCTYPE alive


def _kernel_version() -> tuple[int, int]:
    rel = platform.release()  # e.g. "6.1.0-18-amd64"
    parts = rel.split(".")
    try:
        return int(parts[0]), int(parts[1].split("-")[0])
    except (IndexError, ValueError):
        return (0, 0)


def _check_preconditions() -> None:
    if sys.platform != "linux":
        raise RuntimeError(
            f"eBPF loading requires Linux; this is {sys.platform}. Use simulation mode instead."
        )
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PermissionError(
            "Loading eBPF LSM programs requires root. Re-run with sudo, or use simulation mode."
        )
    major, minor = _kernel_version()
    if (major, minor) < _MIN_KERNEL:
        raise RuntimeError(
            f"LSM BPF requires kernel {_MIN_KERNEL[0]}.{_MIN_KERNEL[1]}+; "
            f"running {major}.{minor}. Use simulation mode."
        )


def _open_libbpf() -> "ctypes.CDLL":
    name = ctypes.util.find_library("bpf") or "libbpf.so"
    try:
        lib = ctypes.CDLL(name, use_errno=True)
    except OSError as e:
        raise RuntimeError(
            f"Could not load libbpf ({name}): {e}. Install libbpf (e.g. `apt install libbpf-dev`)."
        ) from e

    # Declare the signatures we use so ctypes marshals pointers correctly.
    lib.bpf_object__open_file.restype = ctypes.c_void_p
    lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    lib.bpf_object__load.restype = ctypes.c_int
    lib.bpf_object__load.argtypes = [ctypes.c_void_p]
    lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p
    lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_map__fd.restype = ctypes.c_int
    lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
    lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p
    lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_program__attach.restype = ctypes.c_void_p
    lib.bpf_program__attach.argtypes = [ctypes.c_void_p]
    lib.bpf_map_update_elem.restype = ctypes.c_int
    lib.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    lib.bpf_map_delete_elem.restype = ctypes.c_int
    lib.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
    lib.ring_buffer__new.restype = ctypes.c_void_p
    lib.ring_buffer__new.argtypes = [ctypes.c_int, _RINGBUF_CB, ctypes.c_void_p, ctypes.c_void_p]
    lib.ring_buffer__poll.restype = ctypes.c_int
    lib.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ring_buffer__free.restype = None
    lib.ring_buffer__free.argtypes = [ctypes.c_void_p]
    lib.bpf_object__close.restype = None
    lib.bpf_object__close.argtypes = [ctypes.c_void_p]
    # U4 — map pinning + pin lookup.
    lib.bpf_map__pin.restype = ctypes.c_int
    lib.bpf_map__pin.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpf_obj_get.restype = ctypes.c_int
    lib.bpf_obj_get.argtypes = [ctypes.c_char_p]
    return lib


def load_program(inode_map: Optional[dict] = None) -> LoadedProgram:
    """Load honeytoken_watch.o, attach all four hooks, and populate
    watched_inodes from `inode_map`.

    inode_map: { inode_number: {token_id, token_type(int), pod_id, namespace} }
    """
    _check_preconditions()

    if not _OBJECT_PATH.is_file():
        raise RuntimeError(
            f"{_OBJECT_PATH.name} not found — run `make` in {_OBJECT_PATH.parent} first."
        )

    lib = _open_libbpf()

    obj = lib.bpf_object__open_file(str(_OBJECT_PATH).encode(), None)
    if not obj:
        raise RuntimeError(f"bpf_object__open_file failed (errno {ctypes.get_errno()})")

    if lib.bpf_object__load(obj) != 0:
        lib.bpf_object__close(obj)
        raise RuntimeError(
            f"bpf_object__load/verify failed (errno {ctypes.get_errno()}). "
            "Check that BPF LSM is enabled (lsm=...,bpf on the kernel cmdline)."
        )

    def _map_fd(name: str) -> int:
        m = lib.bpf_object__find_map_by_name(obj, name.encode())
        if not m:
            raise RuntimeError(f"map {name!r} not found in object")
        return lib.bpf_map__fd(m)

    handle = LoadedProgram(
        lib=lib, obj=obj,
        watched_inodes_fd=_map_fd("watched_inodes"),
        events_fd=_map_fd("events"),
    )

    for prog_name in _PROGRAMS:
        prog = lib.bpf_object__find_program_by_name(obj, prog_name.encode())
        if not prog:
            logger.warning("Program {} not found in object — skipping attach", prog_name)
            continue
        link = lib.bpf_program__attach(prog)
        if not link:
            logger.warning("Failed to attach {} (errno {})", prog_name, ctypes.get_errno())
            continue
        handle.links.append(link)
        handle.attached.append(prog_name)
        logger.info("Attached eBPF program {}", prog_name)

    if inode_map:
        update_inodes(handle, inode_map)

    # U4 — pin maps to a restricted dir (best-effort; a missing bpffs mount must
    # not fail the load).
    try:
        pin_maps(handle)
    except Exception as e:  # pragma: no cover — Linux/bpffs only
        logger.warning("Map pinning skipped: {}", e)

    logger.info("Loaded honeytoken_watch.o: {} hook(s) attached, {} inode(s) watched",
                len(handle.attached), len(inode_map or {}))
    return handle


def update_inodes(handle: LoadedProgram, new_inodes: dict) -> int:
    """Add/update watched inodes in the map at runtime — called by the
    deployer when tokens are injected or rotated, no reload needed."""
    count = 0
    for inode, meta in new_inodes.items():
        key = ctypes.c_uint64(int(inode))
        value = pack_token_meta(
            token_id=meta["token_id"],
            token_type=int(meta["token_type"]),
            pod_id=meta.get("pod_id", ""),
            namespace=meta.get("namespace", ""),
        )
        vbuf = ctypes.create_string_buffer(value, len(value))
        rc = handle.lib.bpf_map_update_elem(
            handle.watched_inodes_fd, ctypes.byref(key), vbuf, 0  # BPF_ANY
        )
        if rc != 0:
            logger.warning("Failed to add inode {} to watched_inodes (errno {})",
                           inode, ctypes.get_errno())
            continue
        count += 1
    logger.info("watched_inodes updated: {} inode(s) added/updated", count)
    return count


def remove_inode(handle: LoadedProgram, inode: int) -> bool:
    """Stop watching an inode (e.g. after a honeytoken is rotated out)."""
    key = ctypes.c_uint64(int(inode))
    return handle.lib.bpf_map_delete_elem(handle.watched_inodes_fd, ctypes.byref(key)) == 0


def open_ring_buffer(handle: LoadedProgram, callback: Callable[[bytes], None]) -> None:
    """Wire `callback(raw_bytes)` to the events ring buffer. Kept on the
    handle so the agent can poll it."""
    def _trampoline(_ctx, data, size):
        handle_bytes = ctypes.string_at(data, size)
        callback(handle_bytes)
        return 0

    cb = _RINGBUF_CB(_trampoline)
    handle._cb_ref = cb  # prevent GC of the callback
    rb = handle.lib.ring_buffer__new(handle.events_fd, cb, None, None)
    if not rb:
        raise RuntimeError(f"ring_buffer__new failed (errno {ctypes.get_errno()})")
    handle.ringbuf = rb


def poll_ring_buffer(handle: LoadedProgram, timeout_ms: int = 200) -> int:
    if handle.ringbuf is None:
        return 0
    return handle.lib.ring_buffer__poll(handle.ringbuf, timeout_ms)


def unload(handle: LoadedProgram) -> None:
    """Detach programs and free the object."""
    try:
        if handle.ringbuf is not None:
            handle.lib.ring_buffer__free(handle.ringbuf)
            handle.ringbuf = None
        # Closing the object detaches programs and frees links.
        handle.lib.bpf_object__close(handle.obj)
        logger.info("Unloaded eBPF object and detached all hooks")
    except Exception as e:  # pragma: no cover
        logger.warning("Error during eBPF unload: {}", e)


def pin_maps(handle: LoadedProgram, pin_dir: str = _PIN_DIR) -> None:
    """Pin the BPF maps under a restricted directory (U4). Pinning makes the
    maps tamper-evident — their disappearance is a signal picked up by
    verify_attached — and survives across process restarts."""
    os.makedirs(pin_dir, mode=0o700, exist_ok=True)
    os.chmod(pin_dir, 0o700)
    for name in _PINNED_MAPS:
        path = os.path.join(pin_dir, name)
        if os.path.exists(path):
            continue  # already pinned
        m = handle.lib.bpf_object__find_map_by_name(handle.obj, name.encode())
        if not m:
            logger.warning("pin_maps: map {} not found in object", name)
            continue
        if handle.lib.bpf_map__pin(m, path.encode()) != 0:
            logger.warning("pin_maps: failed to pin {} -> {} (errno {})", name, path, ctypes.get_errno())
        else:
            logger.info("Pinned map {} -> {}", name, path)
    handle.pin_dir = pin_dir


def verify_attached(handle: LoadedProgram) -> list[str]:
    """Best-effort tamper check (U4, Linux). Returns the names of hooks/maps
    that look tampered — an empty list means healthy.

    Two signals: (a) a program from _PROGRAMS not in handle.attached (never
    attached, or lost), and (b) a pinned map missing from the pin dir (an
    attacker unpinning/removing it). True per-link kernel liveness would need
    bpf_link introspection; this is the documented approximation."""
    missing: list[str] = [p for p in _PROGRAMS if p not in handle.attached]
    if handle.pin_dir:
        missing += [f"map:{n}" for n in _PINNED_MAPS if not os.path.exists(os.path.join(handle.pin_dir, n))]
    return missing


def reload_program(handle: LoadedProgram, inode_map: Optional[dict] = None) -> LoadedProgram:
    """Tamper recovery (U4): unload the (possibly compromised) program, then
    load + re-attach + re-pin a fresh one. Returns the new handle."""
    logger.warning("Reloading eBPF program (tamper recovery)")
    try:
        unload(handle)
    except Exception as e:  # pragma: no cover
        logger.warning("reload: unload failed (continuing): {}", e)
    return load_program(inode_map)

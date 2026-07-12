// SPDX-License-Identifier: GPL-2.0
//
// AC-2035 honeytoken kernel detector.
//
// Watches for any process opening / reading a deployed honeytoken file and
// emits a fully-attributed forensic event to userspace via a ring buffer.
// LSM hooks are used in *observe* mode only — every hook returns 0 (allow);
// this detector never blocks access, it attributes it.
//
// Four hooks:
//   lsm/file_open           — catches open() of a watched inode
//   lsm/file_permission     — catches read()/mmap() permission checks that
//                             can reach data without a fresh file_open
//   kprobe/sys_execve       — process-execution lineage in pods
//   tp/sched/sched_process_exit — process exit (an attacker process exiting
//                             right after touching a token is a strong tell)
//
// Requires kernel 5.7+ with BPF LSM enabled (CONFIG_BPF_LSM=y and
// "lsm=...,bpf" on the kernel command line). Built CO-RE with clang+libbpf
// against a BTF-generated vmlinux.h.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";  // BPF LSM programs must be GPL.

#define COMM_LEN 16
#define POD_ID_LEN 64
#define NAMESPACE_LEN 32

#define PROC_EXEC 1
#define PROC_EXIT 2

// Value stored in watched_inodes by the userspace loader. Layout mirrored
// by TokenMeta in detector/telemetry_agent/struct_defs.py.
struct token_meta {
	__u32 token_id_hash;   // FNV-1a(token_id), reversed against the registry
	__u8 token_type;       // 0=gcp_key 1=gcp_api_key 2=db_connection 3=api_token
	__u8 pod_id[POD_ID_LEN];
	__u8 namespace[NAMESPACE_LEN];
};

// Emitted on watched-file access. Layout mirrored by HoneytokenEvent in
// struct_defs.py (natural alignment → 160 bytes, timestamp_ns at +144).
struct honeytoken_event {
	__u64 inode;
	__u32 pid;             // kernel task pid (TID)
	__u32 tgid;            // thread-group id (the userspace-visible PID)
	__u32 uid;
	__u32 gid;
	__u32 token_id_hash;
	__u8 token_type;
	__u8 comm[COMM_LEN];
	__u8 pod_id[POD_ID_LEN];
	__u8 namespace[NAMESPACE_LEN];
	__u64 timestamp_ns;
	__u32 flags;           // reserved (file_permission passes the access mask)
};

// Emitted on exec/exit. Mirrored by ProcessEvent in struct_defs.py (48 bytes).
struct process_event {
	__u8 kind;             // PROC_EXEC / PROC_EXIT
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 ppid;
	__u8 comm[COMM_LEN];
	__u64 timestamp_ns;
};

// Force BTF emission of the event structs so userspace can rely on them.
const struct honeytoken_event *unused_hte __attribute__((unused));
const struct process_event *unused_pe __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);              // inode number
	__type(value, struct token_meta);
} watched_inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Shared core: if `file`'s inode is watched, emit a honeytoken_event.
// __always_inline keeps every hook a single verifier-friendly function with
// no unbounded work and well under the 512-byte stack limit (the event lives
// in ring-buffer memory, not on the stack).
static __always_inline int handle_file_access(struct file *file, __u32 flags)
{
	if (!file)
		return 0;

	// bpf_core_read walks file->f_inode->i_ino safely (never a raw deref).
	__u64 ino = 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;
	ino = BPF_CORE_READ(inode, i_ino);

	struct token_meta *meta = bpf_map_lookup_elem(&watched_inodes, &ino);
	if (!meta)
		return 0;  // not a honeytoken — allow, say nothing

	struct honeytoken_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;  // ring buffer full — drop rather than block

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->inode = ino;
	e->pid = (__u32)pid_tgid;            // low 32 bits = TID
	e->tgid = (__u32)(pid_tgid >> 32);   // high 32 bits = PID
	e->uid = (__u32)uid_gid;             // low 32 bits = uid
	e->gid = (__u32)(uid_gid >> 32);     // high 32 bits = gid
	e->token_id_hash = meta->token_id_hash;
	e->token_type = meta->token_type;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->flags = flags;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// Fixed-size copies out of map memory — verifier-safe (constant bounds).
	__builtin_memcpy(e->pod_id, meta->pod_id, sizeof(e->pod_id));
	__builtin_memcpy(e->namespace, meta->namespace, sizeof(e->namespace));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline void emit_process(__u8 kind)
{
	struct process_event *pe = bpf_ringbuf_reserve(&events, sizeof(*pe), 0);
	if (!pe)
		return;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	pe->kind = kind;
	pe->pid = (__u32)pid_tgid;
	pe->tgid = (__u32)(pid_tgid >> 32);
	pe->uid = (__u32)uid_gid;
	pe->ppid = task ? BPF_CORE_READ(task, real_parent, tgid) : 0;
	pe->timestamp_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(&pe->comm, sizeof(pe->comm));

	bpf_ringbuf_submit(pe, 0);
}

// ── Hook 1: open() of a watched file ──────────────────────────────────────
SEC("lsm/file_open")
int BPF_PROG(ac2035_file_open, struct file *file)
{
	return handle_file_access(file, 0);
}

// ── Hook 2: read()/mmap() permission checks (bypass a fresh file_open) ─────
SEC("lsm/file_permission")
int BPF_PROG(ac2035_file_permission, struct file *file, int mask)
{
	return handle_file_access(file, (__u32)mask);
}

// ── Hook 3: process execution lineage ─────────────────────────────────────
// NOTE: on x86-64 the concrete kprobe symbol is usually __x64_sys_execve;
// SEC("ksyscall/execve") is the portable form libbpf resolves per-arch. The
// spec's literal SEC name is kept here — adjust in loader/attach if a given
// kernel exposes a different symbol.
SEC("kprobe/sys_execve")
int BPF_KPROBE(ac2035_execve)
{
	emit_process(PROC_EXEC);
	return 0;
}

// ── Hook 4: process exit (post-theft exit is a strong signal) ─────────────
SEC("tp/sched/sched_process_exit")
int ac2035_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	emit_process(PROC_EXIT);
	return 0;
}

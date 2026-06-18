// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
// probectl eBPF agent (S21) — TLS plaintext capture via uprobes.
//
// Attaches to the SSL library's write/read entry points to read application
// plaintext BEFORE encryption / AFTER decryption, with no CA and no MITM
// (Pixie/eCapture model). OpenSSL and BoringSSL share the SSL_* API; GnuTLS uses
// gnutls_record_send / gnutls_record_recv — attach the same way (userspace picks
// the symbols per library). SSL_read is captured at the *return* uprobe because
// the destination buffer is not yet populated at entry.
//
// PROCESS SCOPE (EBPF-001/RED-003): uprobes on a SHARED libssl fire for every
// process that maps it, so the filter must live HERE, in the kernel, before
// any byte is copied. A process is in scope only if its tgid is in scope_tgids
// or its cgroup id is in scope_cgroups — both maps are programmed by userspace
// from the explicit l7_capture_scope allowlist. Empty maps (the load-time
// state) match nothing: DEFAULT = CAPTURE OFF, consistent with the U-003
// double-consent gate. Non-allowlisted process plaintext never enters the
// ring buffer at all.
//
// CAPTURE WINDOW (EBPF-002): capture_cfg.window bounds how many plaintext
// bytes per chunk may transit the ring. The map is zero-initialized, so the
// kernel default is 0 = LENGTH-ONLY (metadata, no payload bytes) until
// userspace explicitly programs the consented redaction mode's window. The
// chunk's orig_len always reports the true plaintext size for volumetrics;
// len is the bytes actually copied (len <= orig_len, and data[:len] is the
// only valid region — the D-001/U-003 invariant).
//
// OBSERVE-ONLY (CLAUDE.md §7 guardrail 8): this program only reads buffers and
// reports them; it attaches no enforcement hook and alters no traffic. Go's
// crypto/tls does not use libssl and needs the separate strategy documented in
// docs/ebpf-feasibility.md §7.
//
// Built into the agent only under -tags ebpf (bpf2go). See docs/ebpf-agent.md.

#include "vmlinux.h"
#include "arch_compat.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA 4096
#define DROP_RINGBUF_FULL 0
#define DROP_ACTIVE_READS_UPDATE 1
#define DROP_COUNTERS_MAX 2

// Mirrors sslChunk in l7chunk.go — keep field order/sizes in sync.
struct tls_chunk {
	__u32 pid;
	__u32 tid;
	__u64 conn;     // SSL* pointer, used as a per-connection key
	__u8 is_read;   // 0 = write (request/egress), 1 = read (response/ingress)
	__u8 pad[3];
	__u32 len;      // bytes copied into data (<= window; data[:len] valid)
	__u32 orig_len; // true plaintext size of the SSL_read/SSL_write
	__u8 data[MAX_DATA];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tls_chunks SEC(".maps");

// Process allowlist: tgids (exact PIDs + PIDs resolved from exe: entries).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); // tgid
	__type(value, __u8);
} scope_tgids SEC(".maps");

// Process allowlist: cgroup v2 ids (cgroup:/container scoping).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); // cgroup id (bpf_get_current_cgroup_id)
	__type(value, __u8);
} scope_cgroups SEC(".maps");

// Capture policy: [0] = window, the max payload bytes per chunk (0 = length-
// only metadata). Zero-initialized => length-only until userspace programs
// the consented mode (fail-closed for plaintext).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} capture_cfg SEC(".maps");

// scoped reports whether the CURRENT process opted in via the allowlist.
// Both maps empty (default) => nothing is in scope.
static __always_inline int scoped(void)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (bpf_map_lookup_elem(&scope_tgids, &tgid))
		return 1;
	__u64 cg = bpf_get_current_cgroup_id();
	if (bpf_map_lookup_elem(&scope_cgroups, &cg))
		return 1;
	return 0;
}

// SSL_read args stashed at entry, consumed at return (buffer filled by then).
struct read_args {
	__u64 conn;
	__u64 buf;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64); // tid
	__type(value, struct read_args);
} active_reads SEC(".maps");

// drop_counters accounts for kernel-side loss that userspace cannot infer:
// a failed ringbuf reserve creates no readable record, and a failed active_reads
// stash loses SSL_read correlation before the return probe can emit a chunk.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROP_COUNTERS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} drop_counters SEC(".maps");

static __always_inline void count_drop(__u32 reason)
{
	__u64 *cnt = bpf_map_lookup_elem(&drop_counters, &reason);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline void emit(__u64 conn, __u8 is_read, const void *buf, int num)
{
	if (num <= 0)
		return;

	__u32 zero = 0;
	__u32 *pol = bpf_map_lookup_elem(&capture_cfg, &zero);
	__u32 window = pol ? *pol : 0;
	if (window > MAX_DATA - 1)
		window = MAX_DATA - 1;

	struct tls_chunk *e = bpf_ringbuf_reserve(&tls_chunks, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF_FULL);
		return;
	}

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->conn = conn;
	e->is_read = is_read;
	e->pad[0] = e->pad[1] = e->pad[2] = 0;
	e->orig_len = (__u32)num;

	__u32 n = (__u32)num;
	if (n > window)
		n = window; /* EBPF-002: at most the policy window transits the ring.
		             * window < MAX_DATA always, so the D-001/U-003 invariant
		             * (len <= bytes actually copied) holds by construction. */
	e->len = n;
	if (n)
		bpf_probe_read_user(&e->data, n & (MAX_DATA - 1), buf); // mask aids the verifier
	bpf_ringbuf_submit(e, 0);
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, const void *buf, int num)
{
	if (!scoped())
		return 0; // EBPF-001: non-allowlisted plaintext never leaves the process
	emit((__u64)ssl, 0, buf, num);
	return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num); — capture the buffer at return.
SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_ssl_read_enter, void *ssl, void *buf, int num)
{
	if (!scoped())
		return 0; // not in scope: no stash, so the exit probe no-ops too
	__u64 tid = bpf_get_current_pid_tgid();
	struct read_args a = {.conn = (__u64)ssl, .buf = (__u64)buf};
	if (bpf_map_update_elem(&active_reads, &tid, &a, BPF_ANY))
		count_drop(DROP_ACTIVE_READS_UPDATE);
	return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_ssl_read_exit, int ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct read_args *a = bpf_map_lookup_elem(&active_reads, &tid);
	if (!a)
		return 0;
	emit(a->conn, 1, (void *)a->buf, ret);
	bpf_map_delete_elem(&active_reads, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

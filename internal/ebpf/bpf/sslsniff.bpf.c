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

// Mirrors sslChunk in source_live_l7_linux.go — keep field order/sizes in sync.
struct tls_chunk {
	__u32 pid;
	__u32 tid;
	__u64 conn;    // SSL* pointer, used as a per-connection key
	__u8 is_read;  // 0 = write (request/egress), 1 = read (response/ingress)
	__u8 pad[3];
	__u32 len;
	__u8 data[MAX_DATA];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tls_chunks SEC(".maps");

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

static __always_inline void emit(__u64 conn, __u8 is_read, const void *buf, int num)
{
	if (num <= 0)
		return;
	struct tls_chunk *e = bpf_ringbuf_reserve(&tls_chunks, sizeof(*e), 0);
	if (!e)
		return; // ring buffer full — userspace counts the drop

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->conn = conn;
	e->is_read = is_read;
	e->pad[0] = e->pad[1] = e->pad[2] = 0;

	__u32 n = (__u32)num;
	if (n > MAX_DATA - 1)
		n = MAX_DATA - 1; /* clamp BELOW the mask: at n==MAX_DATA the old code
	                       * copied ZERO bytes while declaring len=4096, shipping
	                       * stale ring memory to userspace (D-001/U-003). */
	e->len = n;
	bpf_probe_read_user(&e->data, n & (MAX_DATA - 1), buf); // mask aids the verifier (now identity)
	bpf_ringbuf_submit(e, 0);
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, const void *buf, int num)
{
	emit((__u64)ssl, 0, buf, num);
	return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num); — capture the buffer at return.
SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_ssl_read_enter, void *ssl, void *buf, int num)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct read_args a = {.conn = (__u64)ssl, .buf = (__u64)buf};
	bpf_map_update_elem(&active_reads, &tid, &a, BPF_ANY);
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

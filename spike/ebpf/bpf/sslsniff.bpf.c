// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
// S19a eBPF feasibility spike — minimal OpenSSL SSL_write uprobe.
//
// Demonstrates the S21 "plaintext-before-encryption" path: a uprobe on
// `SSL_write(SSL *ssl, const void *buf, int num)` reads the application's
// plaintext buffer from userspace before OpenSSL encrypts it, with no CA and
// no MITM. Attach with cilium/ebpf's link.OpenExecutable(libssl).Uprobe(...).
//
// NOTE: SSL_read must be captured at the uretprobe (the destination buffer is
// not populated at function entry). Go's crypto/tls does NOT use libssl and
// needs an entirely different strategy — see docs/ebpf-feasibility.md §7.
//
// Throwaway proof code; NOT part of the probectl production build.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUF 256

struct tls_event {
	__u32 pid;
	__u32 len;
	__u8 comm[16];
	__u8 data[MAX_BUF];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tls_events SEC(".maps");

SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, const void *buf, int num)
{
	if (num <= 0)
		return 0;

	struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	__u32 n = (__u32)num;
	if (n > sizeof(e->data))
		n = sizeof(e->data);
	e->len = n;
	// `buf` is a userspace pointer; bounded copy of the plaintext. Real code
	// often masks n (e.g. n & (MAX_BUF-1)) to satisfy the verifier's bound check.
	bpf_probe_read_user(&e->data, n, buf);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

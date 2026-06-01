// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
// S19a eBPF feasibility spike — minimal CO-RE L3/L4 capture.
//
// Attaches to the stable `sock:inet_sock_set_state` tracepoint and, for each
// TCP socket entering ESTABLISHED, emits the 5-tuple + pid/comm to a ring
// buffer. The tracepoint carries the tuple directly, so the common path needs
// no fragile per-kernel struct-offset reads — CO-RE still relocates the
// tracepoint context type against the target kernel's BTF.
//
// Requires a generated vmlinux.h (see ../Makefile `vmlinux`) and libbpf headers.
// This is throwaway proof code; it is NOT part of the netctl production build.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define IPPROTO_TCP 6
#ifndef BPF_TCP_ESTABLISHED
#define BPF_TCP_ESTABLISHED 1
#endif

// Mirrors l4Event in ../main.go — keep field order/sizes in sync.
struct l4_event {
	__u32 pid;
	__u8 comm[16];
	__u8 saddr[4];
	__u8 daddr[4];
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 newstate;
	__u8 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return 0;
	if (ctx->family != AF_INET) // keep the proof IPv4-only for brevity
		return 0;
	if (ctx->newstate != BPF_TCP_ESTABLISHED)
		return 0;

	struct l4_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0; // ring buffer full — a real agent counts this drop

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	__builtin_memcpy(e->saddr, ctx->saddr, sizeof(e->saddr));
	__builtin_memcpy(e->daddr, ctx->daddr, sizeof(e->daddr));
	e->sport = ctx->sport; // tracepoint provides ports in host byte order
	e->dport = ctx->dport;
	e->family = ctx->family;
	e->newstate = ctx->newstate;
	e->pad = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

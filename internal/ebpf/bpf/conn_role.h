// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
// probectl eBPF agent — connection-role cache shared by l4flow and sslsniff.
//
// Why a role cache exists (ING-24): the socket state tracepoint reports the
// LOCAL side as "source" whichever end opened the connection, and the passive
// transitions (SYN_RECV, ESTABLISHED on a server) run in softirq context, where
// bpf_get_current_pid_tgid() names whatever task happened to be on the CPU
// (often swapper). So the role and the owning process are learned where they
// are knowable and cached per socket:
//
//   * active open  (-> SYN_SENT, the connect() caller's context): CLIENT + pid;
//   * passive open (LISTEN -> SYN_RECV): SERVER + the listener's owner, which
//     was recorded when listen() ran (or seeded by the task_file iterator for
//     listeners that predate the agent).
//
// l4flow owns and populates the map; sslsniff loads the SAME map instance
// (cilium/ebpf MapReplacements) so an L7 chunk is attributed with the role the
// L4 program learned. Keep both definitions identical.
//
// OBSERVE-ONLY: a cache of observations, nothing here alters a socket.

#ifndef PROBECTL_CONN_ROLE_H
#define PROBECTL_CONN_ROLE_H

#define PROBECTL_ROLE_UNKNOWN 0
#define PROBECTL_ROLE_CLIENT 1
#define PROBECTL_ROLE_SERVER 2

#define PROBECTL_CONN_ROLES_MAX 65536

// Mirrors nothing in Go directly: userspace only ever sees the fields copied
// into an event. 32 bytes.
struct conn_role {
	__u64 born_ns; // bpf_ktime_get_ns() at SYN_SENT / SYN_RECV (0 = unknown)
	__u32 pid;     // owning process (client: connect() caller; server: listener owner / closer)
	__u8 role;     // PROBECTL_ROLE_*
	__u8 emitted;  // ESTABLISHED already reported for this socket
	__u8 pad[2];
	__u8 comm[16];
};

#endif

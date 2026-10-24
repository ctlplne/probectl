// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
// probectl eBPF agent (S20) — CO-RE L3/L4 capture.
//
// Attaches to the stable `sock:inet_sock_set_state` tracepoint as a RAW
// tracepoint and, for each TCP socket entering ESTABLISHED or CLOSE, emits the
// 5-tuple + the connection's ROLE (client / server) + its owning pid/comm + TCP
// byte/segment counters to a ring buffer. CO-RE relocates every socket read
// against the target kernel's BTF.
//
// WHY RAW (ING-23): a classic tracepoint link (perf_event_open on the event)
// first reads the event id from tracefs, and tracefs is root-only (0700) on
// every systemd distro, so the shipped non-root unit (CAP_BPF + CAP_PERFMON)
// could not attach. A raw tracepoint is attached by NAME through bpf() itself
// (BPF_RAW_TRACEPOINT_OPEN) and never touches tracefs. It hands the program the
// tracepoint's raw arguments (sk, oldstate, newstate) instead of the formatted
// record, so read_set_state() derives the record's fields from the socket
// exactly as the tracepoint's TP_fast_assign does
// (include/trace/events/sock.h): same values, same event format.
//
// ROLE + OWNER (ING-24): the tuple is always local-first, and the passive-open
// transitions run in softirq context, so neither direction nor process can be
// read off the event itself. The role and owner are learned where they are
// knowable and cached per socket (conn_role.h):
//   * CLOSE -> LISTEN runs in the listen() caller: record the listener owner;
//   * CLOSE -> SYN_SENT runs in the connect() caller: CLIENT + that process;
//   * LISTEN -> SYN_RECV: SERVER + the listener's recorded owner;
//   * -> FIN_WAIT1 / LAST_ACK run in the close() caller: fill a missing owner.
// Listeners that predate the agent are seeded once at start by the
// task_file iterator (seed_listeners), so a server opened before the agent
// still gets its process.
//
// OBSERVE-ONLY (CLAUDE.md §7 guardrail 8): this program only reads and reports —
// it attaches no enforcement hook and calls no traffic-altering helper. The
// observe-only guard test (observeonly_test.go) enforces that invariant.
//
// Built into the agent only under -tags ebpf (bpf2go); needs clang + libbpf
// headers + a generated vmlinux.h. See docs/ebpf-agent.md.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "conn_role.h"

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#ifndef BPF_TCP_ESTABLISHED
#define BPF_TCP_ESTABLISHED 1
#endif
#ifndef BPF_TCP_CLOSE
#define BPF_TCP_CLOSE 7
#endif
#define PROBECTL_TCP_SYN_SENT 2
#define PROBECTL_TCP_SYN_RECV 3
#define PROBECTL_TCP_FIN_WAIT1 4
#define PROBECTL_TCP_LAST_ACK 9
#define PROBECTL_TCP_LISTEN 10

#define DROP_RINGBUF_FULL 0

// Mirrors l4eventC in l4event.go — keep field order/sizes in sync.
// saddr/sport are the LOCAL side, daddr/dport the peer; role says which of
// them is the client. sock + born_ns identify the connection inside the agent
// (they join L4 and L7 and are never published).
struct l4_event {
	__u64 bytes;
	__u64 packets;
	__u64 sock;    // kernel socket identity (agent-internal)
	__u64 born_ns; // connection birth from the role cache (0 = unknown)
	__u32 pid;     // owning process (0 = unknown, never a softirq bystander)
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 newstate;
	__u8 role; // PROBECTL_ROLE_*
	__u8 comm[16];
	__u8 saddr[16];
	__u8 daddr[16];
	__u8 pad2[4];
};

// Per-socket role + owner (conn_role.h). LRU: a socket whose CLOSE was never
// seen (agent restart mid-connection) ages out instead of pinning an entry.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROBECTL_CONN_ROLES_MAX);
	__type(key, __u64); // struct sock *
	__type(value, struct conn_role);
} conn_roles SEC(".maps");

// Listening sockets -> the process that owns them, keyed by network namespace
// + local port (a dual-stack listener accepts both families, so family is not
// part of the key).
struct listen_key {
	__u32 netns;
	__u16 port;
	__u16 pad;
};

struct listen_owner {
	__u32 pid;
	__u32 pad;
	__u8 comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct listen_key);
	__type(value, struct listen_owner);
} listeners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB (resized from config at load, U-050)
} events SEC(".maps");

// filtered counts flows dropped in-kernel for an unsupported address family: a
// single per-CPU u64 userspace reads + sums, so unsupported L3 families are
// MEASURABLE rather than a silent blind spot.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} filtered SEC(".maps");

// drop_counters makes kernel-side loss measurable. Userspace cannot observe a
// failed ringbuf reserve: no record exists to read. So the kernel increments a
// per-CPU counter at the failure point and the agent sums it on flush.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drop_counters SEC(".maps");

// seed_stats counts each stage of the listener seed (ING-24), so a start that
// attributes no pre-existing listener says which filter dropped them:
// files visited, socket files, TCP listeners, owners recorded.
#define SEED_FILES 0
#define SEED_SOCKETS 1
#define SEED_TCP_LISTENERS 2
#define SEED_RECORDED 3
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} seed_stats SEC(".maps");

static __always_inline void count_seed(__u32 stage)
{
	__u64 *cnt = bpf_map_lookup_elem(&seed_stats, &stage);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline void count_drop(__u32 reason)
{
	__u64 *cnt = bpf_map_lookup_elem(&drop_counters, &reason);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline void count_filtered(void)
{
	__u32 k = 0;
	__u64 *cnt = bpf_map_lookup_elem(&filtered, &k);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

// set_state is the sock:inet_sock_set_state record, rebuilt from the raw
// tracepoint's arguments (ING-23). Ports are host byte order, like the
// tracepoint's own sport/dport fields.
struct set_state {
	const struct sock *sk;
	int oldstate;
	int newstate;
	__u16 protocol;
	__u16 family;
	__u16 sport; // local port
	__u16 dport; // peer port
};

/* Every socket read below goes through BPF_CORE_READ (probe-read with CO-RE
 * relocation): the raw tracepoint's sk argument is an untyped u64 to the
 * verifier, and the probe-read path is accepted by every CO-RE kernel back to
 * the documented >=5.8 floor. The sources mirror TP_fast_assign of
 * sock:inet_sock_set_state: family/protocol from the sock, ports from
 * inet_sock (inet_sport, and inet_dport == skc_dport), converted with ntohs. */
static __always_inline void read_set_state(struct set_state *st, const struct bpf_raw_tracepoint_args *ctx)
{
	// TP_PROTO(const struct sock *sk, const int oldstate, const int newstate).
	// Read through a plain u64 view of the context: vmlinux.h marks every
	// struct preserve_access_index, so ctx->args[i] would become a CO-RE
	// relocation against the zero-length args[] array and be refused at load.
	// The socket is read through a local pointer: BPF_CORE_READ(st->sk, ...)
	// would also emit a relocation for the local struct set_state, which no
	// kernel BTF has.
	const __u64 *args = (const __u64 *)ctx;
	const struct sock *sk = (const struct sock *)args[0];
	const struct inet_sock *inet = (const struct inet_sock *)sk;
	st->sk = sk;
	st->oldstate = (int)args[1];
	st->newstate = (int)args[2];
	st->protocol = BPF_CORE_READ(sk, sk_protocol);
	st->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	st->sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	st->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

// fill_addrs mirrors the tracepoint's address fields: IPv4 takes inet_saddr /
// inet_daddr (4 bytes, the rest of the 16-byte slot stays zero); IPv6 takes
// the socket's v6 pair (TP_STORE_ADDRS), which a dual-stack socket fills with
// v4-mapped addresses.
static __always_inline void fill_addrs(struct l4_event *e, const struct sock *sk, __u16 family)
{
	if (family == AF_INET) {
		const struct inet_sock *inet = (const struct inet_sock *)sk;
		__be32 saddr = BPF_CORE_READ(inet, inet_saddr);
		__be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(e->saddr, &saddr, sizeof(saddr));
		__builtin_memcpy(e->daddr, &daddr, sizeof(daddr));
		return;
	}
	BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
	BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
}

static __always_inline void fill_tcp_counters(struct l4_event *e, const void *skaddr)
{
	if (!skaddr)
		return;
	struct tcp_sock *tp = (struct tcp_sock *)skaddr;
	__u64 sent = BPF_CORE_READ(tp, bytes_acked);
	__u64 received = BPF_CORE_READ(tp, bytes_received);
	__u32 out = BPF_CORE_READ(tp, data_segs_out);
	__u32 in = BPF_CORE_READ(tp, data_segs_in);
	e->bytes = sent + received;
	e->packets = (__u64)out + (__u64)in;
}

static __always_inline __u32 sk_netns(const struct sock *sk)
{
	return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline void listen_key_for(struct listen_key *k, const struct sock *sk, __u16 port)
{
	k->netns = sk_netns(sk);
	k->port = port;
	k->pad = 0;
}

// remember caches the role + owner of a socket. owner_pid 0 means unknown.
static __always_inline void remember(__u64 key, __u8 role, __u32 owner_pid, const __u8 *owner_comm)
{
	struct conn_role r = {};
	r.born_ns = bpf_ktime_get_ns();
	r.role = role;
	r.pid = owner_pid;
	if (owner_comm)
		__builtin_memcpy(r.comm, owner_comm, sizeof(r.comm));
	bpf_map_update_elem(&conn_roles, &key, &r, BPF_ANY);
}

static __always_inline void remember_current(__u64 key, __u8 role)
{
	__u8 comm[16] = {};
	bpf_get_current_comm(&comm, sizeof(comm));
	remember(key, role, bpf_get_current_pid_tgid() >> 32, comm);
}

static __always_inline void remember_server(__u64 key, const struct sock *sk, __u16 lport)
{
	struct listen_key lk;
	listen_key_for(&lk, sk, lport);
	struct listen_owner *o = bpf_map_lookup_elem(&listeners, &lk);
	if (o)
		remember(key, PROBECTL_ROLE_SERVER, o->pid, o->comm);
	else
		remember(key, PROBECTL_ROLE_SERVER, 0, 0);
}

static __always_inline void emit(const struct set_state *st, __u64 key,
				 const struct conn_role *r)
{
	struct l4_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF_FULL);
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->sock = key;
	if (r) {
		e->born_ns = r->born_ns;
		e->pid = r->pid;
		e->role = r->role;
		__builtin_memcpy(e->comm, r->comm, sizeof(e->comm));
	}
	fill_addrs(e, st->sk, st->family);
	fill_tcp_counters(e, st->sk);
	e->sport = st->sport;
	e->dport = st->dport;
	e->family = st->family;
	e->newstate = st->newstate;
	bpf_ringbuf_submit(e, 0);
}

SEC("raw_tracepoint/inet_sock_set_state")
int handle_set_state(struct bpf_raw_tracepoint_args *ctx)
{
	struct set_state st = {};
	read_set_state(&st, ctx);
	const struct sock *sk = st.sk;
	int oldstate = st.oldstate;
	int newstate = st.newstate;

	if (!sk)
		return 0;
	if (st.protocol != IPPROTO_TCP)
		return 0;
	if (st.family != AF_INET && st.family != AF_INET6) {
		count_filtered();
		return 0;
	}
	__u64 key = (__u64)sk;
	__u16 lport = st.sport;
	struct listen_key lk;
	struct conn_role *r;

	switch (newstate) {
	case PROBECTL_TCP_LISTEN: {
		// listen() runs in the owner's context: record who serves this port.
		struct listen_owner o = {};
		o.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&o.comm, sizeof(o.comm));
		listen_key_for(&lk, sk, lport);
		bpf_map_update_elem(&listeners, &lk, &o, BPF_ANY);
		return 0;
	}
	case PROBECTL_TCP_SYN_SENT:
		remember_current(key, PROBECTL_ROLE_CLIENT); // connect() caller's context
		return 0;
	case PROBECTL_TCP_SYN_RECV:
		if (oldstate == PROBECTL_TCP_LISTEN)
			remember_server(key, sk, lport);
		return 0;
	case PROBECTL_TCP_FIN_WAIT1:
	case PROBECTL_TCP_LAST_ACK:
		// close() runs in the owner's context: fill an owner we could not
		// learn at open (a server whose listener predates the agent).
		r = bpf_map_lookup_elem(&conn_roles, &key);
		if (r && r->pid == 0) {
			r->pid = bpf_get_current_pid_tgid() >> 32;
			bpf_get_current_comm(&r->comm, sizeof(r->comm));
		}
		return 0;
	case BPF_TCP_ESTABLISHED:
		r = bpf_map_lookup_elem(&conn_roles, &key);
		if (!r) {
			// Handshake began before the agent attached: the old state still
			// says which side opened it; the owner stays unknown (0), never a
			// softirq bystander.
			if (oldstate == PROBECTL_TCP_SYN_SENT)
				remember(key, PROBECTL_ROLE_CLIENT, 0, 0);
			else if (oldstate == PROBECTL_TCP_SYN_RECV)
				remember_server(key, sk, lport);
			else
				remember(key, PROBECTL_ROLE_UNKNOWN, 0, 0);
			r = bpf_map_lookup_elem(&conn_roles, &key);
		}
		if (r)
			r->emitted = 1;
		emit(&st, key, r);
		return 0;
	case BPF_TCP_CLOSE:
		if (oldstate == PROBECTL_TCP_LISTEN) {
			listen_key_for(&lk, sk, lport);
			bpf_map_delete_elem(&listeners, &lk);
			return 0; // a listener closing is not a connection
		}
		r = bpf_map_lookup_elem(&conn_roles, &key);
		if (r) {
			struct conn_role copy = *r;
			emit(&st, key, &copy);
			bpf_map_delete_elem(&conn_roles, &key);
			return 0;
		}
		// Opened before the agent: a socket on a recorded listening port is
		// the server side; otherwise the role is unknown.
		listen_key_for(&lk, sk, lport);
		struct listen_owner *o = bpf_map_lookup_elem(&listeners, &lk);
		struct conn_role guess = {};
		if (o) {
			guess.role = PROBECTL_ROLE_SERVER;
			guess.pid = o->pid;
			__builtin_memcpy(guess.comm, o->comm, sizeof(guess.comm));
		}
		emit(&st, key, &guess);
		return 0;
	}
	return 0;
}

// seed_listeners runs once when the agent starts (an iterator over every
// task's open files): a TCP socket in LISTEN is recorded with the task that
// holds it, so a server whose listen() predates the agent is still attributed.
// BPF_NOEXIST keeps the tracepoint's (newer) record when both exist.
SEC("iter/task_file")
int seed_listeners(struct bpf_iter__task_file *ctx)
{
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	if (!file || !task)
		return 0;
	count_seed(SEED_FILES);
	struct socket *sock = bpf_sock_from_file(file);
	if (!sock)
		return 0;
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;
	count_seed(SEED_SOCKETS);
	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	if (BPF_CORE_READ(sk, __sk_common.skc_state) != PROBECTL_TCP_LISTEN)
		return 0;
	count_seed(SEED_TCP_LISTENERS);
	struct listen_key lk;
	listen_key_for(&lk, sk, BPF_CORE_READ(sk, __sk_common.skc_num));
	struct listen_owner o = {};
	o.pid = BPF_CORE_READ(task, tgid);
	BPF_CORE_READ_STR_INTO(&o.comm, task, comm);
	if (bpf_map_update_elem(&listeners, &lk, &o, BPF_NOEXIST) == 0)
		count_seed(SEED_RECORDED);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

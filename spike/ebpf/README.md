# S19a — eBPF feasibility spike (vertical proof)

Real CO-RE eBPF proof for the netctl eBPF agent (F11 / S20 / S21). The findings,
coverage matrices, overhead estimate, and go/no-go live in
**[`../../docs/ebpf-feasibility.md`](../../docs/ebpf-feasibility.md)** — read that
first. This directory is the runnable artifact behind it.

## What it proves

- **L3/L4 capture** (`bpf/l4flow.bpf.c`): a minimal **CO-RE** program attached to
  the `sock:inet_sock_set_state` tracepoint, streaming TCP 5-tuples (+ pid/comm)
  to a **ring buffer**, read by a pure-Go **cilium/ebpf** loader (`main.go`).
- **Uprobe / TLS plaintext** (`bpf/sslsniff.bpf.c`): an `SSL_write` uprobe that
  reads application plaintext **before encryption** — the S21 approach.

## It will NOT run here

eBPF is **Linux-only**, and loading needs a **BTF kernel (≥5.8)** plus
**`CAP_BPF`** (or root). It will not run on macOS, in most CI runners, or in an
unprivileged container. That constraint is the whole point of the spike — see
the report's §3 and [`PROBE-RESULTS.txt`](PROBE-RESULTS.txt) for the captured
evidence from this environment (BTF present, but no clang / no Go / no caps).

## Build & run (on a BTF-enabled Linux host, as root)

```sh
# prerequisites: clang, llvm, libbpf-dev (bpf/*.h), bpftool, Go 1.26
go mod tidy        # resolve cilium/ebpf + populate go.sum
make run           # = vmlinux (bpftool) + generate (bpf2go) + build + sudo ./l4flow
```

Expected output — one line per new TCP connection:

```
S19a l4flow spike: watching TCP connections (Ctrl-C to stop)...
pid=1234    comm=curl             10.0.0.5:53124 -> 93.184.216.34:443
```

## Not production code

Separate Go module, **not** in the repo `go.work`; excluded from CI/lint/format.
`cmd/netctl-ebpf-agent` (S20) supersedes this — nothing here is promoted as-is.

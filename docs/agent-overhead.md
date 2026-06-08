# Agent overhead — methodology + measured numbers (U-051)

The "lightweight agent" claim, with numbers and a regression tripwire
instead of adjectives. Feeds the agent whitepaper (U-034 / F2).

## What is measured, and where

The eBPF agent's cost has two halves:

1. **Userspace pipeline** — `Observe → ServiceMap → Drain → protobuf →
   bus publish`: everything the agent does per flow event after the kernel
   hands it over. Measured **everywhere** (CI included) by
   `internal/ebpf/bench_test.go` under a defined synthetic profile
   (50 destination peers × 8 ports, mixed ingress/egress, varied sizes —
   the shape the recorded fixtures replay), via `Getrusage` CPU time,
   wall-clock throughput, and heap/RSS.
2. **Kernel + ring buffer** — the BPF programs and ring-buffer drain need
   a live kernel with traffic; CI proves the load/attach path on real LTS
   kernels (the `ebpf-kernel-matrix` job), and the live numbers are taken
   on **reference hosts** with the same script below while driving a
   defined iperf3/wrk profile. Reference rows pending (table below).

Run it anywhere:

```sh
scripts/bench/agent_overhead.sh results.txt   # host context + benches + report
```

## Regression tripwire (CI, every pass)

`TestAgentOverheadReport` runs inside `make test` and **fails** if pipeline
throughput drops below **20k events/s** — ~20–40x headroom under today's
numbers even with `-race` and shared-runner noise. A change that makes the
agent meaningfully heavier cannot land silently.

## Measured numbers

Userspace pipeline (Go 1.26, arm64 dev container, 4 vCPU, plain build):

| Metric | Value |
|---|---|
| Pipeline throughput (wall) | **881k events/s** |
| CPU per event (user+sys) | **1.75 µs** → ~**0.18% of one core at 1k flows/s** |
| `Observe` (map + queue) | 827 ns/op, 2 allocs |
| `Observe→Drain→Emit` (full cycle) | 1.21 µs/op, 3 allocs |
| L7 redaction (`RedactHeaders`, 1.1 KiB) | 73 ns/op, 0 allocs, ~15 GB/s |
| Heap in use after 200k events | 3.6 MiB (Go `Sys` 17 MiB) |
| Process max RSS during run | 29 MiB |

Interpretation: at the documented tier shapes (hundreds–thousands of
flows/s per host), the agent's userspace cost is a low single-digit
percentage of one core and tens of MiB — the chart's default limits
(500m CPU / 256Mi) carry an order of magnitude of headroom.

| Date | Host | Profile | Pipeline events/s | CPU/event | Max RSS | Live ring-buffer events/s |
|---|---|---|---|---|---|---|
| 2026-06-07 | dev container, 4 vCPU arm64 | synthetic 50×8 | 881k | 1.75 µs | 29 MiB | n/a (no kernel) |
| _continuous_ | CI runner (in `make test`, -race) | synthetic 50×8 | see job log (floor 20k) | see job log | see job log | n/a |
| _pending_ | reference host (whitepaper, U-034) | iperf3 + wrk defined mix | — | — | — | — |

The reference-host row is BLOCKED-ON-HUMAN: run the script on the
whitepaper hardware with live traffic, paste the row, and cite it from the
whitepaper.

### Measuring the live ring-buffer path (Sprint 17, DOCS-006)

`TestLiveOverheadReport` (`internal/ebpf/live_smoke_ebpf_test.go`,
`linux && ebpf` tags) measures the REAL path the table above marks `n/a`:
it loads + attaches the BPF programs via `newLiveSource`, generates
loopback TCP connects through the tracepoints for a configurable window
(`PROBECTL_OVERHEAD_SECONDS`, default 10), drains the ring buffer, and
prints an `OVERHEAD ROW` with CPU% (rusage user+sys over the window),
heap, and max RSS. It skips cleanly without kernel privileges, so it runs
wherever the kernel-matrix smoke runs:

```sh
# on a reference host (root or CAP_BPF+CAP_PERFMON):
PROBECTL_OVERHEAD_SECONDS=60 go test -tags ebpf -count=1 -v \
  -run '^TestLiveOverheadReport$' ./internal/ebpf/
```

Paste the logged row into the table above (the "Live ring-buffer events/s"
column stops being `n/a` the first time this runs on real hardware).

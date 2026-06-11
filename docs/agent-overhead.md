# Agent overhead — methodology and measured numbers

## What this is

Every observability vendor calls their agent "lightweight." This doc replaces the
adjective with **numbers, a reproducible method, and a CI tripwire** so the claim
is checkable and can't silently rot. It's the evidence behind the eBPF agent's
overhead story.

## What is measured, and where

The eBPF agent's cost splits into two halves, measured differently because they
live in different worlds:

1. **Userspace pipeline** — `Observe → ServiceMap → Drain → protobuf → bus
   publish`: everything the agent does *per flow event* once the kernel has handed
   the event up. (**Userspace** is where ordinary programs run, outside the
   privileged **kernel** core of the OS.) This is pure Go and runs **everywhere**,
   so it's measured everywhere, CI included, by `internal/ebpf/bench_test.go`
   under a defined synthetic profile (50 destination peers × 8 ports, mixed
   ingress/egress, varied sizes — the same shape the recorded fixtures replay). It
   reports CPU time (via `Getrusage` — the OS's own per-process accounting of CPU
   seconds consumed), wall-clock throughput, and heap/RSS (**heap** is the memory
   the Go runtime manages for the program's data; **RSS**, resident set size, is
   the process's total physical-RAM footprint as the OS accounts it).

2. **Kernel + ring buffer** — the BPF programs and the drain of the **ring
   buffer** (the fixed-size kernel→userspace event queue; see
   [`ebpf-agent.md`](ebpf-agent.md)). This half needs a **live kernel with real
   traffic**, so it can't be priced in ordinary CI. Instead, CI proves the
   load/attach path works on real LTS kernels (the `ebpf-kernel-matrix` job), and
   the live overhead numbers are taken on **reference hosts** with the script
   below while driving a defined iperf3 / wrk profile (the standard load
   generators: bulk TCP streams and HTTP requests, respectively). (The
   reference-host rows are pending — see the table.)

The split matters because the two halves have very different cost profiles, and
conflating them would let a cheap userspace number hide an expensive kernel one
(or vice versa). They're measured separately and labeled separately.

Run the userspace half anywhere:

```sh
scripts/bench/agent_overhead.sh results.txt   # host context + benches + report
```

## The regression tripwire (CI, every run)

`TestAgentOverheadReport` runs inside `make test` and **fails the build** if the
userspace pipeline throughput drops below **20,000 events/s**. That floor is
deliberately loose — roughly 20–40× below the real numbers — because CI runners
are shared and noisy and `-race` (Go's race detector, which instruments every
memory access and is many times slower by design) runs many times slower than a
plain build. The point isn't to measure performance precisely in CI; it's to
catch a *regression*. The floor is a smoke alarm, not a thermometer: it says
nothing about how warm the kitchen is, but it cannot sleep through a fire — if
the pipeline suddenly does less than 20k/s, something got at least ~20× slower,
and that's a real change, not noise. A commit that makes the agent meaningfully
heavier cannot land unnoticed.

## Measured numbers

> These are a recorded run on **one** machine (Go 1.26, arm64 dev container,
> 4 vCPU, plain build). They are reproducible with the script above, but they are
> **hardware-specific** — treat them as a representative data point, not a
> guaranteed spec. The dated table below is the record; rerun on your own
> hardware to get your own row.

| Metric | Value |
|---|---|
| Pipeline throughput (wall) | **881k events/s** |
| CPU per event (user+sys) | **1.75 µs** → ~**0.18% of one core at 1k flows/s** |
| `Observe` (map + queue) | 827 ns/op, 2 allocs |
| `Observe→Drain→Emit` (full cycle) | 1.21 µs/op, 3 allocs |
| L7 redaction (`RedactHeaders`, ~1.1 KiB) | 73 ns/op, 0 allocs |
| Heap in use after 200k events | 3.6 MiB (Go `Sys` 17 MiB) |
| Process max RSS during run | 29 MiB |

**How to read this:** at the flow rates a host actually sees (hundreds to a few
thousand flows/s), the agent's *userspace* cost is a low single-digit percentage
of one core and tens of MiB of memory. For comparison, the shipped Helm chart's
default limits are 500m CPU and 256Mi memory — an order of magnitude of headroom
above these measured figures.

| Date | Host | Profile | Pipeline events/s | CPU/event | Max RSS | Live ring-buffer events/s |
|---|---|---|---|---|---|---|
| 2026-06-07 | dev container, 4 vCPU arm64 | synthetic 50×8 | 881k | 1.75 µs | 29 MiB | n/a (no kernel) |
| _continuous_ | CI runner (in `make test`, -race) | synthetic 50×8 | see job log (floor 20k) | see job log | see job log | n/a |
| _pending_ | reference host (the [agent whitepaper](security/agent-whitepaper.md) numbers) | iperf3 + wrk defined mix | — | — | — | — |

The reference-host row is intentionally left for a human to fill: run the script
on real hardware with live traffic and paste the row. That's also the only way to
populate the **live ring-buffer** column the synthetic table marks `n/a` — which
brings us to the live test.

## Measuring the live ring-buffer path

`TestLiveOverheadReport` (`internal/ebpf/live_smoke_ebpf_test.go`, built with the
`linux` and `ebpf` tags) measures the **real** kernel path the table above can't —
the one marked `n/a`. It loads and attaches the BPF programs via `newLiveSource`,
generates loopback TCP connects through the tracepoints for a configurable window
(`PROBECTL_OVERHEAD_SECONDS`, default 10), drains the ring buffer, and prints an
`OVERHEAD ROW` with CPU% (rusage user+sys over the window), heap, and max RSS. It
**skips cleanly** when there's no kernel privilege, so it runs wherever the
kernel-matrix smoke runs:

```sh
# on a reference host (root, or CAP_BPF+CAP_PERFMON):
PROBECTL_OVERHEAD_SECONDS=60 go test -tags ebpf -count=1 -v \
  -run '^TestLiveOverheadReport$' ./internal/ebpf/
```

Paste the logged row into the table above; the "Live ring-buffer events/s" column
stops being `n/a` the first time this runs on real hardware.

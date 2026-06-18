# Network chaos / fault injection

**Fault injection** (chaos testing) is breaking something *on purpose*, in a
controlled place, to prove your detection actually detects — the way you test
a smoke alarm with a match under a test rig, not by setting the corridor on
fire. probectl's chaos injector answers one question about probectl itself:
**if the network actually breaks, does this platform catch it?** It is a
self-test of efficacy — inject a KNOWN fault, assert the observability and
the SLO alerts surface it. A monitoring platform that has never been shown a
real failure is itself an untested alarm.

## Blast radius by construction

**Blast radius** is everything a fault could possibly touch; the safest
blast radius is one the design makes impossible to widen, rather than one a
careful operator must remember to keep small. `internal/chaos.UDPProxy` is an
in-process **datagram proxy** — a relay for UDP packets that sits between a
test and its target: it perturbs ONLY
traffic explicitly addressed to its listener. Nothing is intercepted, no
kernel/qdisc/iptables state is touched, no agent or tenant traffic is
affected, and the injector is **not wired into the control plane** — it
cannot be reached from any API. Actions against the network are human-gated
by design in probectl (a project
[non-negotiable](../CONTRIBUTING.md#non-negotiables)); this one isn't even
reachable.

## The fault config (the contract)

```go
chaos.Fault{
    LatencyMs: 200,  // per direction
    JitterMs:  50,   // ± uniform
    LossPct:   30,   // drop probability per datagram
    Partition: false // true = full blackhole
}
```

In words: **latency** delays each datagram, **jitter** is the wobble on that
delay, **loss** rolls a die per datagram, and a **partition** is the cable
pulled out entirely. Faults validate fail-closed (an out-of-range fault is
rejected, never half-applied) and are swappable mid-run (`SetFault`) — a
chaos run is: healthy baseline → inject → observe → heal → observe. The
baseline-first shape is what makes the result evidence: an alert that was
already firing before the fault proves nothing.

## The efficacy self-test

`go test -tags=integration ./internal/chaos/ -run Chaos`:

1. **`TestChaosRunDetectedBySLO`** — real UDP canary probes flow through
   the proxy against a real echo server while an OpenSLO availability SLO
   (see [slo.md](slo.md)) watches the target. Healthy baseline: nothing fires. **Inject a
   partition**: probes fail for real, the multi-window burn alert (the SLO
   alert that fires when the error budget is being spent too fast) fires,
   attainment drops. **Heal**: attainment recovers. A failure of this test
   is a failure of the platform's core promise.
2. **`TestChaosLatencyVisibleInProbeMetrics`** — a 100ms latency fault
   (not an outage) must be visible in the probe RTT metrics.

Unit tests pin the injector itself: latency adds up per direction,
partition blackholes and heals, loss dice roll, invalid faults rejected.

## Dependency-chaos release matrix

The UDP proxy proves that probectl detects a known network fault. Dependency
chaos proves the platform keeps the right blast radius when one of its own
dependencies fails. The machine-readable contract lives in
`internal/chaos.DependencyChaosMatrix` and is pinned by
`TestDependencyChaosMatrixCoversRequiredFaults`.

The matrix is intentionally a release-gated evidence map, not an always-on
fault injector. Each row names the dependency, the failure mode, the expected
counters or health signals, the retry/DLQ behavior, and the recovery assertion,
then points at the concrete test patterns that prove that row:

| Dependency class | Failure modes covered | Required behavior |
| --- | --- | --- |
| Kafka / bus producer | broker unreachable, produce latency, async buffer pressure | publish errors or counted sheds are visible; accepted records are never silently acknowledged before durable broker acceptance |
| In-memory bus | handler errors, subscriber overflow | the failing subscriber lane retries or sheds independently; the default block policy keeps drainable messages |
| TSDB/result writer | transient writer error, persistent outage, batching flush error | writes retry, exhausted writes enter DLQ with original bytes, and DLQ publish failure preserves redelivery |
| Flow/device/OTLP stores | store or exporter failure, tenant registry failure | each signal path retries or redelivers inside its tenant-scoped stream; tenant verification fails closed |
| ClickHouse | 5xx/429 storms, oversized response, failed migration statement | the shared client trips breakers and bounds responses; failed migrations stop before recording success |
| Postgres metadata writer | writer failover, writer unavailable, tenant-lifecycle source failure | mutating requests fail closed with `503`/`Retry-After`; readiness exposes write degradation |
| Agent disk buffer | control-plane outage, partial reconnect, disk cap, corrupt frame tail | frames stay tenant-bound, capped, and FIFO; corrupt or over-cap frames are rejected and counted |
| Memory pressure | cardinality flood, oversized labels, oversized ClickHouse response | noisy identities are dropped at the owning limiter while quiet tenants and known identities keep flowing |
| Control-plane replica | one replica restarts during result-derived view updates | shared side effects remain single-consumer; replica-local read views rebuild from their own group |

## Using it against your own stack

Point any echo-path test at a proxy you start in your own harness:

```go
proxy, _ := chaos.NewUDPProxy("your-echo-target:9999", chaos.Fault{})
go proxy.Run(ctx)
// create a probectl udp/voice test with target = proxy.Addr()
proxy.SetFault(chaos.Fault{LossPct: 50, LatencyMs: 200}) // chaos on
```

Out of scope by design: TCP/HTTP stream faults (different semantics —
connection-level faults, not datagram dice; a follow-up if needed),
cluster-level chaos orchestration (Chaos Mesh et al. own killing pods and
nodes; probectl validates the dependency failure contract above), and any
always-on or API-reachable injection.

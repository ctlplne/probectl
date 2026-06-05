# Network chaos / fault injection (S48, F47)

probectl's chaos injector answers one question about probectl itself: **if
the network actually breaks, does this platform catch it?** It is a
self-test of efficacy — inject a KNOWN fault, assert the observability and
the SLO alerts surface it.

## Blast radius by construction

`internal/chaos.UDPProxy` is an in-process datagram proxy: it perturbs ONLY
traffic explicitly addressed to its listener. Nothing is intercepted, no
kernel/qdisc/iptables state is touched, no agent or tenant traffic is
affected, and the injector is **not wired into the control plane** — it
cannot be reached from any API (in the spirit of guardrail 8: no un-gated
actions, ever; this one isn't even reachable).

## The fault config (the F47 contract)

```go
chaos.Fault{
    LatencyMs: 200,  // per direction
    JitterMs:  50,   // ± uniform
    LossPct:   30,   // drop probability per datagram
    Partition: false // true = full blackhole
}
```

Faults validate fail-closed and are swappable mid-run (`SetFault`) — a
chaos run is: healthy baseline → inject → observe → heal → observe.

## The efficacy self-test (the 'Done when')

`go test -tags=integration ./internal/chaos/ -run Chaos`:

1. **`TestChaosRunDetectedBySLO`** — real UDP canary probes flow through
   the proxy against a real echo server while an OpenSLO availability SLO
   (S45) watches the target. Healthy baseline: nothing fires. **Inject a
   partition**: probes fail for real, the multi-window burn alert fires,
   attainment drops. **Heal**: attainment recovers. A failure of this test
   is a failure of the platform's core promise.
2. **`TestChaosLatencyVisibleInProbeMetrics`** — a 100ms latency fault
   (not an outage) must be visible in the probe RTT metrics.

Unit tests pin the injector itself: latency adds up per direction,
partition blackholes and heals, loss dice roll, invalid faults rejected.

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
cluster-level chaos orchestration (Chaos Mesh et al. own that space —
probectl validates that IT would notice), and any always-on or
API-reachable injection.

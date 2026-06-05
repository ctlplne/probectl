//go:build integration

package chaos_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/chaos"
	"github.com/imfeelingtheagi/probectl/internal/slo"
)

const chaosSLOYAML = `apiVersion: openslo/v1
kind: SLO
metadata:
  name: chaos-path-availability
spec:
  service: chaos-selftest
  indicator:
    metadata:
      name: chaos-probe-success
    spec:
      ratioMetric:
        good:
          metricSource:
            type: probectl
            spec:
              target: CHAOS_TARGET
              outcome: success
        total:
          metricSource:
            type: probectl
            spec:
              target: CHAOS_TARGET
  timeWindow:
    - duration: 7d
      isRolling: true
  budgetingMethod: Occurrences
  objectives:
    - target: 0.99
`

// The S48 'Done when' for F47: a chaos run is DETECTED by probectl — real
// packets through a real injected fault, surfacing as a fired SLO burn
// alert, which clears after the fault heals.
func TestChaosRunDetectedBySLO(t *testing.T) {
	// A real UDP echo target behind the chaos proxy.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()

	proxy, err := chaos.NewUDPProxy(pc.LocalAddr().String(), chaos.Fault{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = proxy.Run(ctx) }()

	// The SLO engine watches the canary's target (the proxy address).
	dir := t.TempDir()
	yaml := []byte(strings.ReplaceAll(chaosSLOYAML, "CHAOS_TARGET", proxy.Addr()))
	if err := os.WriteFile(filepath.Join(dir, "chaos.yaml"), yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	slos, err := slo.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine := slo.NewEngine(slos)

	probe, err := canary.NewUDP(canary.Config{
		Type: "udp", Target: proxy.Addr(), Timeout: 250 * time.Millisecond,
		Params: map[string]string{"count": "3"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// run executes n REAL probes through the proxy and feeds outcomes into
	// the SLO engine on a compressed synthetic timeline (one per minute).
	tick := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	fired := false
	run := func(n int) {
		for i := 0; i < n; i++ {
			res, err := probe.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			sigs := engine.ObserveResult("chaos-tenant", "udp", proxy.Addr(), res.Success, tick)
			for _, s := range sigs {
				if s.Kind == "slo.burn_rate" || s.Plane == "slo" {
					fired = true
				}
			}
			tick = tick.Add(time.Minute)
		}
	}

	// Healthy baseline: the error budget is intact, nothing fires.
	run(60)
	if fired {
		t.Fatal("burn alert fired on a healthy path — the self-test is miscalibrated")
	}
	sts := engine.Statuses("chaos-tenant")
	if len(sts) != 1 || sts[0].Attainment < 0.99 {
		t.Fatalf("healthy baseline wrong: %+v", sts)
	}

	// INJECT: full partition. Probes now fail for real.
	if err := proxy.SetFault(chaos.Fault{Partition: true}); err != nil {
		t.Fatal(err)
	}
	run(40)
	if !fired {
		t.Fatal("THE EFFICACY CLAIM FAILED: an injected partition was not detected by the SLO burn alerts")
	}
	sts = engine.Statuses("chaos-tenant")
	if sts[0].Attainment >= 0.99 {
		t.Fatalf("attainment must reflect the chaos window: %+v", sts)
	}

	// HEAL: the path recovers and the platform sees the recovery.
	if err := proxy.SetFault(chaos.Fault{}); err != nil {
		t.Fatal(err)
	}
	run(30)
	final := engine.Statuses("chaos-tenant")[0]
	if final.Attainment <= sts[0].Attainment {
		t.Fatalf("attainment must recover after healing: %.4f → %.4f", sts[0].Attainment, final.Attainment)
	}
}

// A latency fault (not a hard outage) must be VISIBLE in the probe metrics —
// the observability half of the efficacy claim.
func TestChaosLatencyVisibleInProbeMetrics(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	proxy, err := chaos.NewUDPProxy(pc.LocalAddr().String(), chaos.Fault{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = proxy.Run(ctx) }()

	probe, err := canary.NewUDP(canary.Config{
		Type: "udp", Target: proxy.Addr(), Timeout: time.Second,
		Params: map[string]string{"count": "3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := probe.Run(context.Background())
	if err != nil || !baseline.Success {
		t.Fatalf("baseline probe failed: %v %v", err, baseline.Error)
	}

	if err := proxy.SetFault(chaos.Fault{LatencyMs: 100}); err != nil {
		t.Fatal(err)
	}
	faulted, err := probe.Run(context.Background())
	if err != nil || !faulted.Success {
		t.Fatalf("latency-faulted probe must still succeed: %v %v", err, faulted.Error)
	}
	if faulted.Metrics["rtt.avg.ms"] < baseline.Metrics["rtt.avg.ms"]+150 {
		t.Errorf("injected 100ms/direction must show in rtt: baseline %.1fms → faulted %.1fms",
			baseline.Metrics["rtt.avg.ms"], faulted.Metrics["rtt.avg.ms"])
	}
}

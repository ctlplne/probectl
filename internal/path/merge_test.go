package path

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func ms(x float64) time.Duration { return time.Duration(x * float64(time.Millisecond)) }

func ob(ttl int, ip string, rttMs float64, mpls ...MPLSLabel) hopObservation {
	o := hopObservation{ttl: ttl, ip: ip, sent: 1}
	if ip != "" {
		o.received = 1
		o.rtts = []time.Duration{ms(rttMs)}
		o.mpls = mpls
	}
	return o
}

func hopAt(p *Path, ttl int) *Hop {
	for i := range p.Hops {
		if p.Hops[i].TTL == ttl {
			return &p.Hops[i]
		}
	}
	return nil
}

func TestMergeECMPAndLinks(t *testing.T) {
	const target = "10.0.0.9"
	cfg := Config{Target: "d", Mode: "icmp", MaxHops: 30}
	traces := []flowTrace{
		{flowID: 1, hops: []hopObservation{ob(1, "10.0.0.1", 1), ob(2, "10.0.0.2", 2), ob(3, target, 3)}},
		{flowID: 2, hops: []hopObservation{ob(1, "10.0.0.1", 1), ob(2, "10.0.0.3", 2), ob(3, target, 4)}},
	}
	p := mergeTraces(cfg, target, traces)

	if !p.DestinationReached {
		t.Error("destination should be reached")
	}
	if h := hopAt(p, 2); h == nil || len(h.Nodes) != 2 {
		t.Fatalf("ttl 2 should show 2 ECMP nodes, got %+v", h)
	}
	want := map[string]bool{
		"1|10.0.0.1|10.0.0.2": true,
		"1|10.0.0.1|10.0.0.3": true,
		"2|10.0.0.2|10.0.0.9": true,
		"2|10.0.0.3|10.0.0.9": true,
	}
	if len(p.Links) != len(want) {
		t.Fatalf("links = %d, want %d: %+v", len(p.Links), len(want), p.Links)
	}
	for _, l := range p.Links {
		if !want[fmt.Sprintf("%d|%s|%s", l.TTL, l.From, l.To)] {
			t.Errorf("unexpected link %+v", l)
		}
	}
}

func TestMergeLossAndRTT(t *testing.T) {
	traces := []flowTrace{
		{hops: []hopObservation{{ttl: 1, ip: "10.0.0.1", sent: 2, received: 1, rtts: []time.Duration{ms(10)}}}},
		{hops: []hopObservation{{ttl: 1, ip: "10.0.0.1", sent: 2, received: 2, rtts: []time.Duration{ms(20), ms(30)}}}},
	}
	p := mergeTraces(Config{}, "", traces)
	n := p.Hops[0].Nodes[0]
	if n.Sent != 4 || n.Received != 3 || n.LossRatio != 0.25 {
		t.Errorf("loss aggregate: sent=%d recv=%d loss=%v", n.Sent, n.Received, n.LossRatio)
	}
	if n.RTTMinMs != 10 || n.RTTAvgMs != 20 || n.RTTMaxMs != 30 {
		t.Errorf("rtt stats: %+v", n)
	}
}

func TestMergeMPLS(t *testing.T) {
	labels := []MPLSLabel{{Label: 100, S: true, TTL: 1}}
	traces := []flowTrace{{hops: []hopObservation{ob(1, "10.0.0.1", 1, labels...)}}}
	p := mergeTraces(Config{}, "", traces)
	got := p.Hops[0].Nodes[0].MPLS
	if len(got) != 1 || got[0].Label != 100 {
		t.Errorf("mpls not carried into the merged node: %+v", got)
	}
}

func TestMergeGapLeavesNoLink(t *testing.T) {
	traces := []flowTrace{{hops: []hopObservation{ob(1, "10.0.0.1", 1), {ttl: 2, ip: ""}, ob(3, "10.0.0.3", 3)}}}
	p := mergeTraces(Config{}, "", traces)
	if len(p.Links) != 0 {
		t.Errorf("adjacency across an unresponsive hop must not be inferred: %+v", p.Links)
	}
}

type fakeTracer struct {
	ip    string
	flows map[uint16]flowTrace
}

func (f *fakeTracer) resolve(string) (string, error) { return f.ip, nil }
func (f *fakeTracer) traceFlow(_ context.Context, _ Config, _ string, flowID uint16) (flowTrace, error) {
	if ft, ok := f.flows[flowID]; ok {
		return ft, nil
	}
	return flowTrace{flowID: flowID}, nil
}

func TestDiscoverRunsTracesAndMerges(t *testing.T) {
	cfg := Config{Target: "dest", Mode: "icmp", TraceCount: 3}
	one := flowTrace{hops: []hopObservation{{ttl: 1, ip: "10.0.0.1", sent: 1, received: 1, rtts: []time.Duration{ms(1)}}}}
	flows := map[uint16]flowTrace{}
	for i := 0; i < 3; i++ {
		flows[flowIDFor(i)] = one
	}
	p, err := discover(context.Background(), &fakeTracer{ip: "10.0.0.9", flows: flows}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.TargetIP != "10.0.0.9" || p.TraceCount != 3 {
		t.Errorf("path meta = %+v", p)
	}
	if len(p.Hops) != 1 || p.Hops[0].Nodes[0].Sent != 3 {
		t.Errorf("3 traces should aggregate to sent=3: %+v", p.Hops)
	}
}

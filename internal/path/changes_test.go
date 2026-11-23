// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package path

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestPathChangeRequiresRepeatedObservedEvidence(t *testing.T) {
	const firstHop, oldHop, newHop, destination = "192.0.2.1", "192.0.2.2", "198.51.100.2", "203.0.113.3"
	trace := func(middle string, lastRTT float64, quote uint8) *Path {
		p := &Path{TargetIP: destination, Mode: "icmp", Vantage: VantageControlPlane, TraceCount: 3, DestinationReached: true,
			MeasurementFidelity: &MeasurementFidelity{Version: 1, ProbeTransport: "icmp", AcquisitionMode: "raw_icmp",
				TimingSource: "application_monotonic", HopVisibility: "full"}}
		for i, ip := range []string{firstHop, middle, destination} {
			rtt := []float64{1, 5, lastRTT}[i]
			p.Hops = append(p.Hops, Hop{TTL: i + 2, Nodes: []HopNode{{IP: ip, Received: 3, RTTMinMs: rtt, RTTMaxMs: rtt + 1}}})
		}
		p.Hops[0].Nodes[0].QuotedTTL, p.Hops[1].Nodes[0].QuotedTTL = quote, quote+1
		p.Links = []Link{{TTL: 2, From: firstHop, To: middle}, {TTL: 3, From: middle, To: destination}}
		return p
	}
	index := func(ip netip.Addr) uint32 {
		return map[string]uint32{firstHop: 64496, oldHop: 64496, newHop: 64497, destination: 64498}[ip.String()]
	}
	signature := func(p *Path) ChangeRound {
		round, ok := NewChangeRound(p, index)
		if !ok {
			t.Fatal("complete trace could not participate in path changes")
		}
		return round
	}
	baseline := signature(trace(oldHop, 8, 0))
	changed := signature(trace(newHop, 8, 0))
	if out := ConfirmChanges(baseline, changed, changed, 10); len(out.HopTTLs) != 1 || out.HopTTLs[0] != 3 ||
		len(out.OriginTTLs) != 1 || out.OriginTTLs[0] != 3 || len(out.LatencySegments) != 0 {
		t.Fatalf("two changed rounds did not confirm the same hop and ASN: %+v", out)
	}
	if out := ConfirmChanges(baseline, changed, baseline, 10); !out.Empty() {
		t.Fatalf("a transient hop change became an event: %+v", out)
	}
	multipath := trace(oldHop, 8, 0)
	multipath.Hops[1].Nodes = append(multipath.Hops[1].Nodes, HopNode{IP: newHop, Received: 1})
	if out := ConfirmChanges(signature(multipath), changed, changed, 10); !out.Empty() {
		t.Fatalf("a known ECMP branch became a new path: %+v", out)
	}
	slow := signature(trace(oldHop, 26, 0))
	if out := ConfirmChanges(baseline, slow, slow, 10); len(out.LatencySegments) != 1 || out.LatencySegments[0].TTL != 3 || len(out.HopTTLs)+len(out.OriginTTLs) != 0 {
		t.Fatalf("confirmed latency delta was not isolated to its original link: %+v", out)
	}
	if out := ConfirmChanges(baseline, slow, slow, 30); !out.Empty() {
		t.Fatalf("the configured latency floor was ignored: %+v", out)
	}
	quoted := trace(oldHop, 8, 0)
	for index, ttl := range []byte{2, 3} {
		body := make([]byte, 20, 28)
		body[0], body[8], body[9] = 0x45, ttl, ianaProtoICMP
		body = append(body, craftParisEcho(21, 1, 443, 40)[:8]...)
		frame, err := (&icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: body}}).Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		reply, valid := parseICMPv4(frame)
		if !valid || !reply.matchedQuote || reply.origID != 21 || reply.origFlow != 443 || reply.quotedTTL != ttl {
			t.Fatal("the controlled ICMP frame lost its original quote")
		}
		quoted.Hops[index].Nodes[0].QuotedTTL = reply.quotedTTL
	}
	if out := InferMPLS(quoted); len(out) != 1 || out[0].Method != "quoted_ttl" || out[0].From != firstHop || out[0].To != oldHop {
		t.Fatalf("quoted TTLs did not produce the labeled inference: %+v", out)
	}
	quoted.Hops[1].Nodes[0].QuotedTTL = 1
	if out := InferMPLS(quoted); len(out) != 0 {
		t.Fatalf("ordinary TTL replies produced an MPLS inference: %+v", out)
	}
	if os.Getenv("PROBECTL_PATH_CHANGE_FRR_TARGET") != "" {
		t.Run("owned-frr-path", proveFRRPathReplacement)
	}
	if os.Getenv("PROBECTL_PATH_CHANGE_MPLS_LAB") == "1" {
		t.Run("owned-mpls-forwarding", proveMPLSForwardingPath)
	}
}

// The optional live leg runs inside the dedicated source container on an
// isolated FRR test network. Neither a host route nor another container's
// network namespace is edited by the test.
func proveFRRPathReplacement(t *testing.T) {
	const target = "198.19.33.10"
	if os.Getenv("PROBECTL_PATH_CHANGE_FRR_TARGET") != target {
		t.Fatal("live path change requires the lab's dedicated target address")
	}
	parseLabNextHop := func(name string) string {
		raw := os.Getenv(name)
		addr, err := netip.ParseAddr(raw)
		if err != nil || !netip.MustParsePrefix("198.19.33.0/24").Contains(addr) || addr.String() != raw || raw == target {
			t.Fatal("invalid owned FRR transit address")
		}
		return addr.String()
	}
	oldHop := parseLabNextHop("PROBECTL_PATH_CHANGE_FRR_OLD")
	newHop := parseLabNextHop("PROBECTL_PATH_CHANGE_FRR_NEW")
	if oldHop == newHop {
		t.Fatal("owned FRR fixture requires two distinct transits")
	}
	trace := func(expect string) ChangeRound {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		p, err := Run(ctx, Config{Target: target, Mode: "icmp", TraceCount: 3, MaxHops: 5,
			ProbesPerHop: 1, PerHopTimeout: time.Second, Privileged: true})
		if err != nil {
			t.Fatal(err)
		}
		p.Vantage = VantageControlPlane
		round, ok := NewChangeRound(p, nil)
		if !ok || len(round.Hops) < 2 || round.Hops[0].TTL != 1 || len(round.Hops[0].Responders) != 1 || round.Hops[0].Responders[0] != expect {
			t.Fatalf("live FRR probe did not cross the selected transit %s: reached=%t hops=%+v", expect, p.DestinationReached, p.Hops)
		}
		return round
	}
	// Install and observe the original, then move the same exact host route
	// to the second next hop through FRR's static daemon.
	set := func(next, previous string) {
		args := []string{"-c", "configure terminal"}
		if previous != "" {
			args = append(args, "-c", "no ip route "+target+"/32 "+previous)
		}
		args = append(args, "-c", "ip route "+target+"/32 "+next)
		if out, err := exec.CommandContext(t.Context(), "/usr/bin/vtysh", args...).CombinedOutput(); err != nil {
			t.Fatalf("update the owned FRR route: %v (%s)", err, out)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			out, err := exec.CommandContext(t.Context(), "/sbin/ip", "route", "get", target).Output()
			if err == nil && strings.Contains(string(out), "via "+next+" ") {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("FRR did not install the owned route in the kernel")
	}
	set(oldHop, "")
	baseline := trace(oldHop)
	set(newHop, oldHop)
	first, second := trace(newHop), trace(newHop)
	if out := ConfirmChanges(baseline, first, second, 10); len(out.HopTTLs) != 1 || out.HopTTLs[0] != 1 || len(out.OriginTTLs)+len(out.LatencySegments) != 0 {
		t.Fatalf("expected one changed hop after the FRR route move: %+v", out)
	}
}

func proveMPLSForwardingPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	p, err := Run(ctx, Config{Target: "198.19.33.10", Mode: "icmp", TraceCount: 2,
		MaxHops: 6, PerHopTimeout: time.Second, Privileged: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.DestinationReached || p.MeasurementFidelity == nil || p.MeasurementFidelity.AcquisitionMode != "raw_icmp" {
		t.Fatalf("the owned label-switched path did not reach its target: %+v", p.Hops)
	}
	if matches := InferMPLS(p); len(matches) != 0 {
		t.Fatalf("silent Linux label-switch hops fabricated quoted TTL evidence: %+v", matches)
	}
}

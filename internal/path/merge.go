package path

import (
	"math"
	"sort"
	"time"
)

// mergeTraces combines per-flow traces into one multi-path Path: per-TTL ECMP
// branches (the distinct responders seen at that distance), the adjacency links
// observed within individual flows (each flow follows one stable path), and
// per-node RTT/loss + MPLS aggregates.
func mergeTraces(cfg Config, targetIP string, traces []flowTrace) *Path {
	p := &Path{
		Target: cfg.Target, TargetIP: targetIP, Mode: cfg.Mode,
		MaxHops: cfg.MaxHops, TraceCount: len(traces),
	}

	type agg struct {
		sent, received int
		rtts           []time.Duration
		mpls           []MPLSLabel
	}
	byTTL := map[int]map[string]*agg{}
	linkSet := map[Link]bool{}
	maxTTL := 0

	for _, tr := range traces {
		for i, ob := range tr.hops {
			if ob.ip == "" {
				continue // unresponsive at this TTL for this flow ("*")
			}
			if ob.ttl > maxTTL {
				maxTTL = ob.ttl
			}
			ips := byTTL[ob.ttl]
			if ips == nil {
				ips = map[string]*agg{}
				byTTL[ob.ttl] = ips
			}
			a := ips[ob.ip]
			if a == nil {
				a = &agg{}
				ips[ob.ip] = a
			}
			a.sent += ob.sent
			a.received += ob.received
			a.rtts = append(a.rtts, ob.rtts...)
			if len(ob.mpls) > 0 && len(a.mpls) == 0 {
				a.mpls = ob.mpls
			}
			if ob.ip == targetIP {
				p.DestinationReached = true
			}
			// Link to the immediately following hop in this flow, when it
			// responded (a gap leaves no link — adjacency across "*" is unknown).
			if i+1 < len(tr.hops) {
				if next := tr.hops[i+1]; next.ip != "" {
					linkSet[Link{TTL: ob.ttl, From: ob.ip, To: next.ip}] = true
				}
			}
		}
	}

	for ttl := 1; ttl <= maxTTL; ttl++ {
		ips := byTTL[ttl]
		if len(ips) == 0 {
			continue
		}
		hop := Hop{TTL: ttl}
		for _, ip := range sortedKeys(ips) {
			a := ips[ip]
			n := HopNode{IP: ip, Sent: a.sent, Received: a.received, MPLS: a.mpls}
			if a.sent > 0 {
				n.LossRatio = round(float64(a.sent-a.received)/float64(a.sent), 4)
			}
			if len(a.rtts) > 0 {
				n.RTTMinMs, n.RTTAvgMs, n.RTTMaxMs = rttStats(a.rtts)
			}
			hop.Nodes = append(hop.Nodes, n)
		}
		p.Hops = append(p.Hops, hop)
	}

	links := make([]Link, 0, len(linkSet))
	for l := range linkSet {
		links = append(links, l)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].TTL != links[j].TTL {
			return links[i].TTL < links[j].TTL
		}
		if links[i].From != links[j].From {
			return links[i].From < links[j].From
		}
		return links[i].To < links[j].To
	})
	p.Links = links
	return p
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func rttStats(rtts []time.Duration) (minMs, avgMs, maxMs float64) {
	mn, mx, sum := rtts[0], rtts[0], time.Duration(0)
	for _, d := range rtts {
		if d < mn {
			mn = d
		}
		if d > mx {
			mx = d
		}
		sum += d
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return round(ms(mn), 3), round(ms(sum/time.Duration(len(rtts))), 3), round(ms(mx), 3)
}

func round(v float64, n int) float64 {
	p := math.Pow10(n)
	return math.Round(v*p) / p
}

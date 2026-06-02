package author

import (
	"fmt"
	"sort"
	"strings"

	"github.com/imfeelingtheagi/netctl/internal/testspec"
)

// Observation is one observed, potentially-monitorable endpoint — mined from the
// eBPF service map, flows, BGP-monitored prefixes, DNS, or incidents. Count
// weights ranking (how often / how strongly it was seen).
type Observation struct {
	Target   string
	Port     int
	Protocol string // "tcp" | "udp" | ""
	Kind     string // "service" | "flow" | "prefix" | "dns" | "incident"
	Count    int
}

// DiscoveryProposal is a suggested test pending human confirmation (never
// auto-applied).
type DiscoveryProposal struct {
	Spec      testspec.Spec `json:"spec"`
	Rationale string        `json:"rationale"`
	Score     int           `json:"score"`
	Source    string        `json:"source"`
}

// DiscoverOptions tune discovery. MinCount thresholds noise; Max caps the result.
type DiscoverOptions struct {
	MinCount int
	Max      int
}

func (o DiscoverOptions) withDefaults() DiscoverOptions {
	if o.MinCount <= 0 {
		o.MinCount = 2
	}
	if o.Max <= 0 {
		o.Max = 20
	}
	return o
}

// Discover ranks observations into monitoring proposals: it suggests a test type
// (by port/kind), thresholds low-signal observations (S26 watch-out: avoid
// noise), skips targets already covered by `existing`, scores + sorts, and caps
// the result. Every proposal is schema-valid.
func Discover(obs []Observation, existing []string, opts DiscoverOptions) []DiscoveryProposal {
	o := opts.withDefaults()
	covered := map[string]bool{}
	for _, e := range existing {
		covered[normalizeKey(e)] = true
	}

	out := []DiscoveryProposal{}
	seen := map[string]bool{}
	for _, ob := range obs {
		if ob.Count < o.MinCount {
			continue
		}
		spec, rationale, ok := suggest(ob)
		if !ok {
			continue
		}
		key := normalizeKey(spec.Target)
		if covered[key] || seen[key] {
			continue
		}
		clean, err := testspec.Clean(spec)
		if err != nil {
			continue
		}
		seen[key] = true
		out = append(out, DiscoveryProposal{Spec: clean, Rationale: rationale, Score: score(ob), Source: ob.Kind})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Spec.Target < out[j].Spec.Target
	})
	if len(out) > o.Max {
		out = out[:o.Max]
	}
	return out
}

// suggest picks a test type for an observation and builds a candidate spec.
func suggest(ob Observation) (testspec.Spec, string, bool) {
	target := strings.TrimSpace(ob.Target)
	if target == "" || isCIDR(target) {
		// A bare prefix is BGP-monitored, not a synthetic-test target.
		return testspec.Spec{}, "", false
	}
	host := displayHost(target)
	if host == "" {
		return testspec.Spec{}, "", false
	}

	var typ, tgt string
	switch {
	case strings.HasPrefix(strings.ToLower(target), "http"):
		typ, tgt = "http", target
	case ob.Port == 443:
		typ, tgt = "http", "https://"+host
	case ob.Port == 80:
		typ, tgt = "http", "http://"+host
	case ob.Port == 53:
		typ, tgt = "dns", host
	case ob.Port > 0:
		typ = "tcp"
		if strings.EqualFold(ob.Protocol, "udp") {
			typ = "udp"
		}
		tgt = hostPort(host, ob.Port)
	case isIP(host):
		typ, tgt = "icmp", host
	default:
		typ, tgt = "http", "https://"+host
	}

	name := truncate(host+" ("+strings.ToUpper(typ)+")", 200)
	rationale := fmt.Sprintf("Observed %d× on the %s plane with no monitoring test; suggest %s.", ob.Count, planeLabel(ob.Kind), typ)
	return testspec.Spec{Name: name, Type: typ, Target: tgt, Enabled: true}, rationale, true
}

func score(ob Observation) int {
	s := ob.Count
	switch ob.Port {
	case 443, 80, 53:
		s += 2 // well-known service ports are higher-value monitoring targets
	}
	return s
}

func planeLabel(kind string) string {
	if kind == "" {
		return "telemetry"
	}
	return kind
}

// normalizeKey reduces a target to its host for dedup (scheme/port/path stripped),
// so a discovered "host:443" dedups against an existing "https://host".
func normalizeKey(t string) string { return strings.ToLower(displayHost(t)) }

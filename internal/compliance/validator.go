package compliance

// The validator: observed traffic (eBPF + flow) checked against declared
// segmentation, per tenant. Verdict semantics (the honesty contract):
//
//	violation      — traffic matching a forbidden intent WAS observed
//	observed_clean — traffic between the zones WAS observed and none of it
//	                 matched the forbidden intent (e.g. only unscoped ports)
//	not_observed   — NO traffic between the zones was observed; this is NOT
//	                 proof of isolation (a quiet path isn't proven blocked)
//
// "Compliant" is a word this engine never emits — the strongest claim is
// "no violations observed, with the stated coverage".

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// Verdict classifies one rule's observed state.
type Verdict string

// Verdicts (see the package comment for exact semantics).
const (
	VerdictViolation     Verdict = "violation"
	VerdictObservedClean Verdict = "observed_clean"
	VerdictNotObserved   Verdict = "not_observed"
)

// FlowObs is one observed conversation, normalized from eBPF or flow.
type FlowObs struct {
	Src     string
	Dst     string
	DstPort uint16
	Bytes   uint64
	Source  string // "flow" | "ebpf" — which plane saw it
	At      time.Time
}

// ViolationSample is captured flow evidence for a violation (bounded).
type ViolationSample struct {
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	DstPort uint16    `json:"dst_port"`
	Bytes   uint64    `json:"bytes"`
	Source  string    `json:"source"`
	At      time.Time `json:"at"`
}

// RuleResult is one rule's validation state for a tenant.
type RuleResult struct {
	Policy      string            `json:"policy"`
	RuleID      string            `json:"rule_id"`
	Description string            `json:"description,omitempty"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Ports       string            `json:"ports"`
	Frameworks  map[string]string `json:"frameworks,omitempty"`
	Verdict     Verdict           `json:"verdict"`
	// Violations counts forbidden conversations; Samples holds bounded flow
	// evidence (first N) for the audit trail.
	Violations    uint64            `json:"violations"`
	ObservedPairs uint64            `json:"observed_pairs"` // any traffic between the zones (either matched or unscoped)
	Samples       []ViolationSample `json:"samples,omitempty"`
	FirstViolated *time.Time        `json:"first_violated,omitempty"`
	LastViolated  *time.Time        `json:"last_violated,omitempty"`
}

// Coverage states what was actually watched (never claim beyond it).
type Coverage struct {
	FlowObserved bool      `json:"flow_observed"` // any S38 flow records seen
	EBPFObserved bool      `json:"ebpf_observed"` // any S20 eBPF flows seen
	Observations uint64    `json:"observations"`
	ZonesSeen    int       `json:"zones_seen"`  // zones with at least one observed endpoint
	ZonesTotal   int       `json:"zones_total"` // zones declared
	FirstSample  time.Time `json:"first_sample,omitempty"`
	LastSample   time.Time `json:"last_sample,omitempty"`
	Notes        []string  `json:"notes"`
}

// maxSamples bounds per-rule violation evidence.
const maxSamples = 20

// Engine validates observed traffic against the loaded policies, per tenant.
type Engine struct {
	mu       sync.Mutex
	policies []Policy
	tenants  map[string]*tenantState
	clock    func() time.Time
}

type ruleState struct {
	violations    uint64
	observedPairs uint64
	samples       []ViolationSample
	first, last   time.Time
	alerted       bool // one violation signal per rule per quiet period
}

type tenantState struct {
	rules     map[string]*ruleState // policy|rule → state
	zonesSeen map[string]bool
	flowSeen  bool
	ebpfSeen  bool
	count     uint64
	first     time.Time
	last      time.Time
}

// NewEngine builds the validator over loaded policies.
func NewEngine(policies []Policy) *Engine {
	return &Engine{
		policies: append([]Policy(nil), policies...),
		tenants:  map[string]*tenantState{},
		clock:    time.Now,
	}
}

// Policies returns the loaded policy names (sorted).
func (e *Engine) Policies() []string {
	out := make([]string, 0, len(e.policies))
	for _, p := range e.policies {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) tenant(id string) *tenantState {
	ts, ok := e.tenants[id]
	if !ok {
		ts = &tenantState{rules: map[string]*ruleState{}, zonesSeen: map[string]bool{}}
		e.tenants[id] = ts
	}
	return ts
}

// Observe validates one conversation and returns violation signals (one per
// rule per episode — the signal carries the first evidence; the full sample
// trail lives in the results/evidence).
func (e *Engine) Observe(tenant string, f FlowObs) []incident.Signal {
	if tenant == "" || f.Src == "" || f.Dst == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)
	ts.count++
	if ts.first.IsZero() || f.At.Before(ts.first) {
		ts.first = f.At
	}
	if f.At.After(ts.last) {
		ts.last = f.At
	}
	switch f.Source {
	case "ebpf":
		ts.ebpfSeen = true
	default:
		ts.flowSeen = true
	}

	var sigs []incident.Signal
	for _, p := range e.policies {
		srcZone, srcOK := p.zoneOf(f.Src)
		dstZone, dstOK := p.zoneOf(f.Dst)
		if srcOK {
			ts.zonesSeen[p.Name+"|"+srcZone] = true
		}
		if dstOK {
			ts.zonesSeen[p.Name+"|"+dstZone] = true
		}
		if !srcOK || !dstOK || srcZone == dstZone {
			continue
		}
		observedPair := pairKey(srcZone, dstZone)
		for _, r := range p.Rules {
			covered := false
			for _, rp := range r.RulePairs() {
				if rp == observedPair {
					covered = true
					break
				}
			}
			if !covered {
				continue
			}
			st := e.ruleState(ts, p.Name, r.ID)
			st.observedPairs++
			if !r.portMatch(f.DstPort) {
				continue // traffic between the zones, outside the forbidden scope
			}
			// VIOLATION: declared-forbidden traffic was observed.
			st.violations++
			if st.first.IsZero() || f.At.Before(st.first) {
				st.first = f.At
			}
			if f.At.After(st.last) {
				st.last = f.At
			}
			if len(st.samples) < maxSamples {
				st.samples = append(st.samples, ViolationSample(f))
			}
			if !st.alerted {
				st.alerted = true
				sigs = append(sigs, incident.Signal{
					TenantID: tenant,
					Plane:    "compliance",
					Kind:     "compliance.segmentation_violation",
					Severity: incident.SeverityCritical,
					Title:    fmt.Sprintf("Segmentation violation: %s → %s (%s)", srcZone, dstZone, r.ID),
					Summary: fmt.Sprintf("policy %s rule %s: observed %s traffic %s → %s (%s, %s), declared forbidden",
						p.Name, r.ID, f.Source, f.Src, f.Dst, fmt.Sprintf("port %d", f.DstPort), r.describePorts()),
					Target: observedPair,
					Attributes: map[string]string{
						"compliance.policy":   p.Name,
						"compliance.rule":     r.ID,
						"compliance.from":     srcZone,
						"compliance.to":       dstZone,
						"compliance.src":      f.Src,
						"compliance.dst":      f.Dst,
						"compliance.dst_port": fmt.Sprintf("%d", f.DstPort),
						"compliance.source":   f.Source,
					},
					OccurredAt: f.At,
				})
			}
		}
	}
	return sigs
}

func (e *Engine) ruleState(ts *tenantState, policy, rule string) *ruleState {
	key := policy + "|" + rule
	st, ok := ts.rules[key]
	if !ok {
		st = &ruleState{}
		ts.rules[key] = st
	}
	return st
}

// Results returns the tenant's per-rule validation results (sorted).
func (e *Engine) Results(tenant string) []RuleResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)

	var out []RuleResult
	for _, p := range e.policies {
		for _, r := range p.Rules {
			st := e.ruleState(ts, p.Name, r.ID)
			res := RuleResult{
				Policy:      p.Name,
				RuleID:      r.ID,
				Description: r.Description,
				From:        r.From,
				To:          r.To,
				Ports:       r.describePorts(),
				Frameworks:  r.Frameworks,
				Violations:  st.violations,
				// observedPairs counts conversations between the zones in the
				// rule's direction(s), whether or not they hit the forbidden scope.
				ObservedPairs: st.observedPairs,
				Samples:       append([]ViolationSample(nil), st.samples...),
			}
			switch {
			case st.violations > 0:
				res.Verdict = VerdictViolation
				f, l := st.first, st.last
				res.FirstViolated, res.LastViolated = &f, &l
			case st.observedPairs > 0:
				res.Verdict = VerdictObservedClean
			default:
				res.Verdict = VerdictNotObserved // NOT proof of isolation
			}
			out = append(out, res)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Policy != out[j].Policy {
			return out[i].Policy < out[j].Policy
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// CoverageFor reports the tenant's visibility (the never-overclaim block).
func (e *Engine) CoverageFor(tenant string) Coverage {
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)

	zonesTotal := 0
	zonesSeen := 0
	for _, p := range e.policies {
		zonesTotal += len(p.Zones)
		for _, z := range p.Zones {
			if ts.zonesSeen[p.Name+"|"+z.Name] {
				zonesSeen++
			}
		}
	}
	c := Coverage{
		FlowObserved: ts.flowSeen,
		EBPFObserved: ts.ebpfSeen,
		Observations: ts.count,
		ZonesSeen:    zonesSeen,
		ZonesTotal:   zonesTotal,
		FirstSample:  ts.first,
		LastSample:   ts.last,
	}
	if !ts.flowSeen {
		c.Notes = append(c.Notes, "no flow-plane (S38) records observed — device-path traffic is invisible")
	}
	if !ts.ebpfSeen {
		c.Notes = append(c.Notes, "no eBPF-plane (S20) flows observed — host-level traffic is invisible")
	}
	if zonesSeen < zonesTotal {
		c.Notes = append(c.Notes, fmt.Sprintf("%d of %d declared zones have observed endpoints — quiet zones are NOT proven isolated", zonesSeen, zonesTotal))
	}
	c.Notes = append(c.Notes, "verdicts cover OBSERVED traffic only; absence of traffic is not proof of blocking")
	return c
}

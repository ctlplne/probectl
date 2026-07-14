// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package change

import (
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Candidate is a change event scored as a possible cause of an incident.
type Candidate struct {
	Event  Event   `json:"event"`
	Score  float64 `json:"score"`  // 0..1 — higher is a more likely cause
	Reason string  `json:"reason"` // why it correlated (topology + recency)
}

// correlationSkew tolerates a change logged slightly AFTER an incident started
// (clock skew across sources — the S29 watch-out), so a near-simultaneous deploy
// still correlates.
const correlationSkew = 5 * time.Minute

// Candidates ranks recent changes as candidate causes for an incident at time
// `at` concerning target/prefix, considering only changes within `window` before
// the incident (plus a small skew grace). Scoring blends TOPOLOGY proximity
// (exact target > IP-in-prefix > overlapping prefix) with TIME proximity (closer
// to the incident scores higher). A change that has neither a topology link to a
// targeted incident nor falls in the window is dropped — so the RCA is fed the
// few likely causes, not every change (avoid drowning in changes).
func Candidates(changes []Event, target, prefix string, at time.Time, window time.Duration) []Candidate {
	if window <= 0 {
		window = 24 * time.Hour
	}
	targeted := target != "" || prefix != ""

	out := make([]Candidate, 0, len(changes))
	for _, ev := range changes {
		dt := at.Sub(ev.OccurredAt) // >0 means the change preceded the incident
		if dt < -correlationSkew || dt > window {
			continue // outside the causal window
		}
		topo, why := topoScore(target, prefix, ev)
		if topo == 0 {
			if targeted {
				continue // the incident has a target but this change doesn't match it
			}
			why = "recent change" // no incident target → recency is the only signal
		}
		recency := timeScore(dt, window)
		score := 0.6*topo + 0.4*recency
		out = append(out, Candidate{Event: ev, Score: round2(score), Reason: why})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Event.OccurredAt.After(out[j].Event.OccurredAt) // newer first on ties
	})
	return out
}

// Relevant reports whether a change event is topologically related to a subject
// (target/prefix) — exposed for the RCA evidence source so it only feeds the model
// changes that concern the question's subject. An empty subject is not "relevant"
// here; the caller decides whether to include recent changes regardless of subject.
func Relevant(ev Event, target, prefix string) bool {
	score, _ := topoScore(target, prefix, ev)
	return score > 0
}

// topoScore scores topology proximity between an incident (target/prefix) and a
// change event, with a human-readable reason.
func topoScore(target, prefix string, ev Event) (float64, string) {
	if target != "" && ev.Target != "" && strings.EqualFold(target, ev.Target) {
		return 1.0, "same target " + ev.Target
	}
	if ipInPrefix(ev.Target, prefix) {
		return 0.8, ev.Target + " ∈ " + prefix
	}
	if ipInPrefix(target, ev.Prefix) {
		return 0.8, target + " ∈ " + ev.Prefix
	}
	if prefixesOverlap(prefix, ev.Prefix) {
		return 0.7, "overlapping prefixes"
	}
	return 0, ""
}

// timeScore maps a change's lead time before the incident to 0..1 (a change at
// the incident time scores 1; one a full window earlier scores ~0).
func timeScore(dt, window time.Duration) float64 {
	if dt < 0 {
		dt = 0
	}
	r := 1.0 - float64(dt)/float64(window)
	return math.Max(0, math.Min(1, r))
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }

// --- address helpers (mirrors internal/incident; the change package stays pure) ---

func asAddr(target string) (netip.Addr, bool) {
	if target == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(target); err == nil {
		return a, true
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func ipInPrefix(target, prefix string) bool {
	if target == "" || prefix == "" {
		return false
	}
	addr, ok := asAddr(target)
	if !ok {
		return false
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false
	}
	return p.Contains(addr)
}

func prefixesOverlap(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	pa, err := netip.ParsePrefix(a)
	if err != nil {
		return false
	}
	pb, err := netip.ParsePrefix(b)
	if err != nil {
		return false
	}
	return pa.Contains(pb.Addr()) || pb.Contains(pa.Addr())
}

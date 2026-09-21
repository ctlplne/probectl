// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package outage is the collective internet-outage view (S47a, F19): it
// aggregates public outage feeds (IODA, Cloudflare Radar) with the operator's
// OWN vantage points (synthetic-test results) into one situational view, and
// correlates external outages with the customer tests they affect.
//
// Honesty contract (the S47a watch-out): probectl does NOT own a global probe
// fleet. Coverage = the customer's vantage points + public open data — never
// claimed to be more. External feeds are shared infrastructure (ingested once,
// never tenant-owned — PRD §3); everything derived from CUSTOMER telemetry
// (vantage detections, affected-test correlation) is tenant-scoped and never
// crosses the boundary (guardrail 1). Feeds are OPT-IN (no phone-home,
// guardrail 2), fetched over hardened TLS with last-good kept on failure
// (guardrails 10, 12), with per-feed AUP/provenance tracked for MSP resale.
package outage

import (
	"sort"
	"sync"
	"time"
)

// ScopeKind classifies what an outage event covers.
type ScopeKind string

const (
	ScopeASN     ScopeKind = "asn"     // one autonomous system (an ISP/cloud/CDN network)
	ScopeCountry ScopeKind = "country" // a national outage
	ScopeRegion  ScopeKind = "region"  // a sub-national region
	ScopeUnknown ScopeKind = "unknown"
)

// Scope is a resolved outage scope: the unit external events and customer
// vantage observations are joined on.
type Scope struct {
	Kind ScopeKind `json:"kind"`
	Code string    `json:"code"` // "AS15169", "BR", "BR.SP"
	Name string    `json:"name,omitempty"`
}

// Key is the scope's stable join key.
func (s Scope) Key() string { return string(s.Kind) + ":" + s.Code }

// Event is the outage-signal model (the S47a contract): one normalized outage
// observation from any source — a public feed or the customer's own vantages.
type Event struct {
	ID         string    `json:"id"`     // stable: source + upstream id (+scope)
	Source     string    `json:"source"` // "ioda" | "cloudflare_radar" | "vantage"
	Scope      Scope     `json:"scope"`
	Severity   string    `json:"severity"`   // "info" | "warning" | "critical"
	Confidence float64   `json:"confidence"` // 0..1 (source-score heuristic, documented)
	Title      string    `json:"title"`
	Summary    string    `json:"summary,omitempty"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end,omitempty"` // zero = ongoing
	Evidence   string    `json:"evidence_url,omitempty"`
}

// Ongoing reports whether the event has no recorded end before now.
func (e Event) Ongoing(now time.Time) bool { return e.End.IsZero() || e.End.After(now) }

// activeAt reports whether the event covers t (with slack for feed lag).
func (e Event) activeAt(t time.Time, slack time.Duration) bool {
	if t.Before(e.Start.Add(-slack)) {
		return false
	}
	return e.End.IsZero() || t.Before(e.End.Add(slack))
}

// Store holds the SHARED external events — public data, ingested once, with
// last-good kept per source (graceful degradation, guardrail 10). It carries
// no tenant data: correlation against customer telemetry happens in Engine,
// per tenant.
type Store struct {
	mu        sync.RWMutex
	bySource  map[string][]Event
	retention time.Duration
	clock     func() time.Time
}

// DefaultRetention bounds how far back the collective view reaches.
const DefaultRetention = 48 * time.Hour

// NewStore builds a store keeping events newer than retention (<=0 = default).
func NewStore(retention time.Duration) *Store {
	if retention <= 0 {
		retention = DefaultRetention
	}
	return &Store{bySource: map[string][]Event{}, retention: retention, clock: time.Now}
}

// SetEvents replaces one source's events wholesale (a refresh). Events older
// than the retention window are dropped; the rest are kept as that source's
// last-good set until the next successful refresh.
func (s *Store) SetEvents(source string, events []Event) {
	cutoff := s.clock().Add(-s.retention)
	kept := make([]Event, 0, len(events))
	for _, e := range events {
		if e.Source != source || e.ID == "" || e.Start.IsZero() {
			continue // malformed or mislabeled — untrusted input stays out
		}
		if !e.End.IsZero() && e.End.Before(cutoff) {
			continue
		}
		kept = append(kept, e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bySource[source] = kept
}

// All returns every retained external event, newest start first.
func (s *Store) All() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Event
	cutoff := s.clock().Add(-s.retention)
	for _, evs := range s.bySource {
		for _, e := range evs {
			if e.End.IsZero() || e.End.After(cutoff) {
				out = append(out, e)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.After(out[j].Start)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ActiveFor returns the external events covering scope at t.
func (s *Store) ActiveFor(scope Scope, t time.Time) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Event
	for _, evs := range s.bySource {
		for _, e := range evs {
			if e.Scope.Key() == scope.Key() && e.activeAt(t, eventSlack) {
				out = append(out, e)
			}
		}
	}
	return out
}

// eventSlack pads event windows when matching customer failures against feed
// timestamps (feeds lag reality by minutes).
const eventSlack = 10 * time.Minute

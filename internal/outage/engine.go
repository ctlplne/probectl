// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package outage

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// Resolver maps a peer IP onto an outage scope (ASN preferred, country
// fallback) — wired from the S15 open-data enricher. nil = scope resolution
// unavailable: the external view still renders, but vantage detection and
// customer-impact correlation are off (reported honestly, never guessed).
type Resolver func(ip string) (Scope, bool)

// Vantage-detection tuning. Conservative on purpose: internet weather is
// situational awareness, not a pager storm.
const (
	vantageWindow      = 15 * time.Minute // failure-aggregation window
	vantageMinTargets  = 2                // distinct failing targets to call an outage
	vantageFireRatio   = 0.5              // scope-wide failure ratio to fire
	vantageClearRatio  = 0.25             // ratio below which an episode clears
	maxTargetsPerTen   = 1024             // bounded per-tenant target index
	maxSamplesPerTgt   = 64               // bounded per-target outcome window
	maxVantageHistory  = 32               // ended episodes kept per tenant
	maxCorrelatedAlert = 4096             // latched external-event alerts per tenant
)

// AffectedTest is one customer test correlated with an outage event.
type AffectedTest struct {
	CanaryType  string    `json:"canary_type"`
	Target      string    `json:"target"`
	Failures    int       `json:"failures"` // in the aggregation window
	LastFailure time.Time `json:"last_failure"`
}

// EventView is one outage event with the CALLER-tenant's correlated impact.
type EventView struct {
	Event
	Ongoing  bool           `json:"ongoing"`
	Affected []AffectedTest `json:"affected_tests,omitempty"`
}

// Snapshot is one tenant's collective outage view (the /v1/outages payload).
type Snapshot struct {
	Events          []EventView `json:"events"`           // external feeds, caller-correlated
	Vantage         []EventView `json:"vantage_events"`   // detected from the tenant's OWN vantages
	ScopeResolution bool        `json:"scope_resolution"` // false = enrichment off, correlation degraded
}

// Engine joins the shared external store with per-tenant vantage telemetry.
// All customer-derived state is tenant-partitioned (guardrail 1).
type Engine struct {
	mu      sync.Mutex
	store   *Store // shared external events; nil = feeds disabled
	resolve Resolver
	tenants map[string]*tenantState
	clock   func() time.Time
}

type tenantState struct {
	targets    map[string]*targetObs // target → windowed outcomes (bounded)
	active     map[string]*Event     // scope key → live vantage episode
	history    []Event               // ended episodes, newest first (bounded)
	correlated map[string]bool       // external event ID → alert latched
}

type targetObs struct {
	canaryType string
	scope      Scope
	samples    []sample // pruned to vantageWindow, bounded
}

type sample struct {
	at time.Time
	ok bool
}

// NewEngine builds the engine. store may be nil (feeds disabled — vantage
// detection still works); resolve may be nil (scope resolution off).
func NewEngine(store *Store, resolve Resolver) *Engine {
	return &Engine{store: store, resolve: resolve, tenants: map[string]*tenantState{}, clock: time.Now}
}

func (e *Engine) tenant(id string) *tenantState {
	ts, ok := e.tenants[id]
	if !ok {
		ts = &tenantState{
			targets:    map[string]*targetObs{},
			active:     map[string]*Event{},
			correlated: map[string]bool{},
		}
		e.tenants[id] = ts
	}
	return ts
}

// Observe folds one synthetic result into the tenant's vantage picture and
// returns any signals raised: a vantage-detected outage (latched per scope
// episode) and/or a correlation between an external outage event and this
// tenant's failing test (latched per event).
func (e *Engine) Observe(tenant, canaryType, target, peerIP string, success bool, at time.Time) []incident.Signal {
	if tenant == "" || target == "" || e.resolve == nil {
		return nil
	}
	scope, ok := e.resolve(peerIP)
	if !ok || scope.Code == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)

	obs, exists := ts.targets[target]
	if !exists {
		if len(ts.targets) >= maxTargetsPerTen {
			return nil // bounded: never grow without limit
		}
		obs = &targetObs{canaryType: canaryType, scope: scope}
		ts.targets[target] = obs
	}
	obs.scope = scope
	obs.samples = append(obs.samples, sample{at: at, ok: success})
	obs.pruneLocked(at)

	var sigs []incident.Signal
	sigs = append(sigs, e.evaluateVantageLocked(tenant, ts, scope, at)...)
	if !success {
		sigs = append(sigs, e.correlateExternalLocked(tenant, ts, scope, canaryType, target, at)...)
	}
	return sigs
}

func (o *targetObs) pruneLocked(now time.Time) {
	cutoff := now.Add(-vantageWindow)
	i := 0
	for ; i < len(o.samples); i++ {
		if !o.samples[i].at.Before(cutoff) {
			break
		}
	}
	o.samples = o.samples[i:]
	if len(o.samples) > maxSamplesPerTgt {
		o.samples = o.samples[len(o.samples)-maxSamplesPerTgt:]
	}
}

// windowStats summarizes one target's window: observed, failing (ratio ≥ 0.5
// over ≥2 samples — one blip is not an outage), failures and last failure.
func (o *targetObs) windowStats(now time.Time) (observed, failing bool, failures int, lastFail time.Time) {
	cutoff := now.Add(-vantageWindow)
	total := 0
	for _, s := range o.samples {
		if s.at.Before(cutoff) {
			continue
		}
		total++
		if !s.ok {
			failures++
			if s.at.After(lastFail) {
				lastFail = s.at
			}
		}
	}
	observed = total > 0
	failing = total >= 2 && float64(failures)/float64(total) >= 0.5
	return observed, failing, failures, lastFail
}

// evaluateVantageLocked re-scores the scope the observation landed in:
// enough distinct failing targets fire a latched vantage episode; recovery
// clears it into history and re-arms.
func (e *Engine) evaluateVantageLocked(tenant string, ts *tenantState, scope Scope, now time.Time) []incident.Signal {
	key := scope.Key()
	var observed, failing, failures int
	firstFail := time.Time{}
	for _, obs := range ts.targets {
		if obs.scope.Key() != key {
			continue
		}
		o, f, fails, last := obs.windowStats(now)
		if o {
			observed++
		}
		if f {
			failing++
			failures += fails
			if firstFail.IsZero() || (last.Before(firstFail) && !last.IsZero()) {
				firstFail = last
			}
		}
	}
	ratio := 0.0
	if observed > 0 {
		ratio = float64(failing) / float64(observed)
	}

	ev, live := ts.active[key]
	switch {
	case live && (failing == 0 || ratio < vantageClearRatio):
		// Episode over: close, keep in history, re-arm.
		ev.End = now
		ts.history = append([]Event{*ev}, ts.history...)
		if len(ts.history) > maxVantageHistory {
			ts.history = ts.history[:maxVantageHistory]
		}
		delete(ts.active, key)
		return nil
	case live || failing < vantageMinTargets || ratio < vantageFireRatio:
		return nil // already latched, or below the bar
	}

	start := firstFail
	if start.IsZero() {
		start = now
	}
	ne := Event{
		ID:         fmt.Sprintf("vantage:%s:%s:%d", tenant, key, start.Unix()),
		Source:     "vantage",
		Scope:      scope,
		Severity:   "warning",
		Confidence: minF(0.9, ratio), // your own vantages, but a small sample — capped
		Title:      fmt.Sprintf("Vantage-detected outage: %s", scopeLabel(scope)),
		Summary: fmt.Sprintf("%d of %d observed targets in %s failing over the last %s",
			failing, observed, scopeLabel(scope), vantageWindow),
		Start: start.UTC(),
	}
	ts.active[key] = &ne
	return []incident.Signal{{
		TenantID: tenant,
		Plane:    "outage",
		Kind:     "outage.vantage_detected",
		Severity: incident.SeverityWarning,
		Title:    ne.Title,
		Summary:  ne.Summary,
		Target:   scope.Code,
		Attributes: map[string]string{
			"outage.scope_kind":      string(scope.Kind),
			"outage.scope":           scope.Code,
			"outage.scope_name":      scope.Name,
			"outage.failing_targets": fmt.Sprintf("%d", failing),
			"outage.observed":        fmt.Sprintf("%d", observed),
		},
		OccurredAt: now,
	}}
}

// correlateExternalLocked checks a failing result against active external
// events in the same scope — the "your test is failing BECAUSE the internet
// is broken there" join. One latched signal per (tenant, external event).
func (e *Engine) correlateExternalLocked(tenant string, ts *tenantState, scope Scope, canaryType, target string, at time.Time) []incident.Signal {
	if e.store == nil {
		return nil
	}
	var sigs []incident.Signal
	for _, ev := range e.store.ActiveFor(scope, at) {
		if ts.correlated[ev.ID] {
			continue
		}
		if len(ts.correlated) >= maxCorrelatedAlert {
			e.pruneCorrelatedLocked(ts, at)
			if len(ts.correlated) >= maxCorrelatedAlert {
				return sigs // still saturated — stop alerting before unbounded growth
			}
		}
		ts.correlated[ev.ID] = true
		sigs = append(sigs, incident.Signal{
			TenantID: tenant,
			Plane:    "outage",
			Kind:     "outage.external_correlated",
			Severity: incident.SeverityWarning,
			Title:    fmt.Sprintf("Test failure correlates with %s", ev.Title),
			Summary: fmt.Sprintf("%s test against %s is failing while %s reports: %s",
				canaryType, target, ev.Source, ev.Summary),
			Target: target,
			Attributes: map[string]string{
				"outage.event_id":   ev.ID,
				"outage.source":     ev.Source,
				"outage.scope_kind": string(ev.Scope.Kind),
				"outage.scope":      ev.Scope.Code,
				"outage.evidence":   ev.Evidence,
			},
			OccurredAt: at,
		})
	}
	return sigs
}

// pruneCorrelatedLocked drops latched alerts whose events left the store.
func (e *Engine) pruneCorrelatedLocked(ts *tenantState, now time.Time) {
	live := map[string]bool{}
	for _, ev := range e.store.All() {
		live[ev.ID] = true
	}
	for id := range ts.correlated {
		if !live[id] {
			delete(ts.correlated, id)
		}
	}
	_ = now
}

// Snapshot renders the collective view for ONE tenant: shared external
// events annotated with this tenant's affected tests, plus the tenant's own
// vantage detections. Nothing from any other tenant is reachable from here.
func (e *Engine) Snapshot(tenant string) Snapshot {
	now := e.clock()
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := e.tenant(tenant)

	snap := Snapshot{ScopeResolution: e.resolve != nil, Events: []EventView{}, Vantage: []EventView{}}
	if e.store != nil {
		for _, ev := range e.store.All() {
			snap.Events = append(snap.Events, EventView{
				Event:    ev,
				Ongoing:  ev.Ongoing(now),
				Affected: affectedLocked(ts, ev, now),
			})
		}
	}
	for _, ev := range ts.active {
		v := EventView{Event: *ev, Ongoing: true, Affected: affectedLocked(ts, *ev, now)}
		snap.Vantage = append(snap.Vantage, v)
	}
	snap.Vantage = append(snap.Vantage, historyViews(ts.history)...)
	sort.Slice(snap.Vantage, func(i, j int) bool {
		if snap.Vantage[i].Ongoing != snap.Vantage[j].Ongoing {
			return snap.Vantage[i].Ongoing
		}
		return snap.Vantage[i].Start.After(snap.Vantage[j].Start)
	})
	return snap
}

func historyViews(history []Event) []EventView {
	out := make([]EventView, 0, len(history))
	for _, ev := range history {
		out = append(out, EventView{Event: ev, Ongoing: false})
	}
	return out
}

// affectedLocked lists this tenant's tests in the event's scope with
// failures inside the event window (or the live window for ongoing events).
func affectedLocked(ts *tenantState, ev Event, now time.Time) []AffectedTest {
	var out []AffectedTest
	for target, obs := range ts.targets {
		if obs.scope.Key() != ev.Scope.Key() {
			continue
		}
		_, _, failures, lastFail := obs.windowStats(now)
		if failures == 0 || !ev.activeAt(lastFail, eventSlack) {
			continue
		}
		out = append(out, AffectedTest{
			CanaryType: obs.canaryType, Target: target,
			Failures: failures, LastFailure: lastFail.UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

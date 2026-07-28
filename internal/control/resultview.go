// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/otel"
)

// Synthetic latest-result read model (S-FE5 surface for S7/S8/S12/S13). The
// canary pipeline flattens results into TSDB series; the per-type result
// DETAIL (DNS rcode/answers, the HTTP waterfall phases, browser transaction
// steps, latency families) lives in each result's metrics+attributes and was
// rendered nowhere. This store retains the LATEST full result per (tenant,
// optional exact test id, type, target, agent) so duplicate definitions do not
// collapse after current agents begin stamping identity and the test screens can
// show every type's result shape first-class.
// Tenant-partitioned (cross-tenant impossible by construction, guardrail 1),
// bounded per tenant (evict-stalest), newest-wins.

// ResultView is one synthetic result, verbatim from the pipeline.
type ResultView struct {
	ResultID   string             `json:"result_id,omitempty"`
	AgentID    string             `json:"agent_id"`
	Type       string             `json:"type"`
	Target     string             `json:"target,omitempty"`
	Success    bool               `json:"success"`
	Error      string             `json:"error,omitempty"`
	DurationMs float64            `json:"duration_ms,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
	Attributes map[string]string  `json:"attributes,omitempty"`
	ObservedAt time.Time          `json:"observed_at"`
}

// DefaultMaxResultsPerTenant bounds each tenant's latest-result partition.
const DefaultMaxResultsPerTenant = 5000

// DefaultMaxHistoryPerTenant bounds each tenant's recent-result ring (the
// short trend window behind GET /v1/results/history). The TSDB pipeline
// remains the long-horizon home for series; this ring only serves the
// dashboard-scale trailing window without a store round trip.
const DefaultMaxHistoryPerTenant = 2000

// LatestResults retains the newest result per (tenant, optional exact test id,
// type, target, agent) plus a bounded per-tenant ring of recent observations
// for trend rendering.
type LatestResults struct {
	mu      sync.Mutex
	max     int
	maxHist int
	tenants map[string]map[string]ResultView // tenant -> test|type|target|agent -> latest
	recent  map[string][]ResultView          // tenant -> bounded recent ring
	evicted map[string]bool                  // tenant -> at least one latest series was evicted
	// recentStartedAt is the process-local instant from which this store could
	// observe results. A window crossing it is incomplete after restart even
	// when the bounded ring has not evicted anything.
	recentStartedAt time.Time
	// recentEvictedThrough is the newest event timestamp evicted from each
	// tenant's history ring. A cadence window whose cutoff is not newer than
	// this timestamp is incomplete and must never be called healthy.
	recentEvictedThrough map[string]time.Time
}

// NewLatestResults builds a store; maxPerTenant <= 0 takes the default.
func NewLatestResults(maxPerTenant int) *LatestResults {
	if maxPerTenant <= 0 {
		maxPerTenant = DefaultMaxResultsPerTenant
	}
	return &LatestResults{
		max:                  maxPerTenant,
		maxHist:              DefaultMaxHistoryPerTenant,
		tenants:              map[string]map[string]ResultView{},
		recent:               map[string][]ResultView{},
		evicted:              map[string]bool{},
		recentStartedAt:      time.Now().UTC(),
		recentEvictedThrough: map[string]time.Time{},
	}
}

// Record stores rv as the latest for its series. Unscoped or type-less
// records are dropped (fail closed); older observations never overwrite.
func (s *LatestResults) Record(tenant string, rv ResultView) {
	if tenant == "" || rv.Type == "" {
		return
	}
	key := rv.Attributes[otel.AttrTestID] + "\x00" + rv.Type + "\x00" + rv.Target + "\x00" + rv.AgentID
	s.mu.Lock()
	defer s.mu.Unlock()
	// Every accepted observation joins the trend ring (evict-oldest), even
	// when a newer result already owns the latest slot for its series.
	s.recent[tenant] = append(s.recent[tenant], rv)
	if len(s.recent[tenant]) > s.maxHist {
		evicted := s.recent[tenant][:len(s.recent[tenant])-s.maxHist]
		for _, item := range evicted {
			if item.ObservedAt.After(s.recentEvictedThrough[tenant]) {
				s.recentEvictedThrough[tenant] = item.ObservedAt
			}
		}
		s.recent[tenant] = s.recent[tenant][len(s.recent[tenant])-s.maxHist:]
	}
	part, ok := s.tenants[tenant]
	if !ok {
		part = map[string]ResultView{}
		s.tenants[tenant] = part
	}
	if prev, exists := part[key]; exists {
		if rv.ObservedAt.Before(prev.ObservedAt) {
			return
		}
		part[key] = rv
		return
	}
	if len(part) >= s.max {
		stalest, found := "", false
		for k, v := range part {
			if !found || v.ObservedAt.Before(part[stalest].ObservedAt) {
				stalest, found = k, true
			}
		}
		if found {
			delete(part, stalest)
			s.evicted[tenant] = true
		}
	}
	part[key] = rv
}

// List returns the tenant's latest results, newest first (stable on ties).
func (s *LatestResults) List(tenant string) []ResultView {
	out, _ := s.ListWithTruncation(tenant)
	return out
}

// ListWithTruncation returns the same stable latest-series view plus whether
// this in-memory tenant partition has ever evicted a series at its configured
// safety bound. Coverage callers use the flag to keep absence unknown.
func (s *LatestResults) ListWithTruncation(tenant string) ([]ResultView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	part := s.tenants[tenant]
	out := make([]ResultView, 0, len(part))
	for _, v := range part {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ObservedAt.After(out[j].ObservedAt)
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Target < out[j].Target
	})
	return out, s.evicted[tenant]
}

// History returns the tenant's results observed inside the trailing window,
// oldest first (plot-ready). Bounded by the per-tenant ring by construction.
func (s *LatestResults) History(tenant string, window time.Duration) []ResultView {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-window)
	out := make([]ResultView, 0, len(s.recent[tenant]))
	for _, v := range s.recent[tenant] {
		if !v.ObservedAt.Before(cutoff) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ObservedAt.Before(out[j].ObservedAt)
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// RecentSnapshot returns one tenant's entire bounded recent ring, oldest event
// first, plus the newest instant through which its process-local history is
// incomplete. The watermark includes process startup and only that tenant's
// eviction state, so callers cannot call a restart-crossing or evicted window
// healthy and no row or tenant-owned watermark crosses partitions.
func (s *LatestResults) RecentSnapshot(tenant string) ([]ResultView, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]ResultView(nil), s.recent[tenant]...)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ObservedAt.Before(out[j].ObservedAt)
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].AgentID < out[j].AgentID
	})
	incompleteThrough := s.recentStartedAt
	if s.recentEvictedThrough[tenant].After(incompleteThrough) {
		incompleteThrough = s.recentEvictedThrough[tenant]
	}
	return out, incompleteThrough
}

// Len reports one tenant's partition size.
func (s *LatestResults) Len(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tenants[tenant])
}

// ResultViewConsumer feeds the store from the network-results topic (its own
// group, independent of the TSDB pipeline).
type ResultViewConsumer struct {
	bus       bus.Bus
	store     *LatestResults
	log       *slog.Logger
	nsTenants map[string]string
}

// NewResultViewConsumer builds the consumer.
func NewResultViewConsumer(b bus.Bus, store *LatestResults, log *slog.Logger) *ResultViewConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &ResultViewConsumer{bus: b, store: store, log: log}
}

// WithNamespaceTenants subscribes standalone result views to siloed result lanes.
func (cs *ResultViewConsumer) WithNamespaceTenants(ns map[string]string) *ResultViewConsumer {
	cs.nsTenants = ns
	return cs
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cs *ResultViewConsumer) LaneFanoutEnabled() bool { return true }

// Run consumes until ctx is done; malformed messages are dropped.
// (Standalone mode — production wires SinkResult through the decode-once
// ResultFan, SCALE-013.)
func (cs *ResultViewConsumer) Run(ctx context.Context) error {
	return runResultSinkLanes(ctx, cs.bus, viewGroup("result-view"), cs.log, cs.nsTenants, cs.SinkResult)
}

// SinkResult records one DECODED result (shared immutable — never mutated).
func (cs *ResultViewConsumer) SinkResult(_ context.Context, r *resultv1.Result) error {
	cs.store.Record(r.GetTenantId(), ResultView{
		ResultID:   r.GetResultId(),
		AgentID:    r.GetAgentId(),
		Type:       r.GetCanaryType(),
		Target:     r.GetServerAddress(),
		Success:    r.GetSuccess(),
		Error:      r.GetErrorMessage(),
		DurationMs: float64(r.GetDurationNano()) / 1e6,
		Metrics:    r.GetMetrics(),
		Attributes: r.GetAttributes(),
		ObservedAt: time.Unix(0, r.GetStartTimeUnixNano()),
	})
	return nil
}

// WithLatestResults attaches the store backing GET /v1/results/latest.
// nil is a no-op. Returns the server for chaining.
func (s *Server) WithLatestResults(lr *LatestResults) *Server {
	if lr != nil {
		s.latestResults = lr
	}
	return s
}

// handleResultsHistory serves GET /v1/results/history?window=1h — the
// tenant's recent synthetic results inside the trailing window, oldest first,
// so latency/duration trends render on a real time axis (the S11 charting
// layer). Same bounded read model and honesty contract as /v1/results/latest:
// collector_running=false distinguishes an unwired consumer from quiet.
func (s *Server) handleResultsHistory(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	window, err := windowParam(r, "window", time.Hour)
	if err != nil {
		return err
	}
	if s.latestResults == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items": []ResultView{}, "collector_running": false, "window": window.String(),
		})
		return nil
	}
	items := s.latestResults.History(tid, window)
	if items == nil {
		items = []ResultView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "collector_running": true, "window": window.String(),
	})
	return nil
}

// handleLatestResults serves GET /v1/results/latest — the tenant's newest
// synthetic result per (type, target, agent), full metrics + attributes, so
// every test type's result shape renders first-class (S-FE5).
// collector_running=false distinguishes an unwired consumer from no results.
func (s *Server) handleLatestResults(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.latestResults == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []ResultView{}, "collector_running": false})
		return nil
	}
	items := s.latestResults.List(tid)
	if items == nil {
		items = []ResultView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "collector_running": true})
	return nil
}

// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
)

// Synthetic latest-result read model (S-FE5 surface for S7/S8/S12/S13). The
// canary pipeline flattens results into TSDB series; the per-type result
// DETAIL (DNS rcode/answers, the HTTP waterfall phases, latency families)
// lives in each result's metrics+attributes and was rendered nowhere. This
// store retains the LATEST full result per (tenant, type, target, agent) so
// the test screens can show every type's result shape first-class.
// Tenant-partitioned (cross-tenant impossible by construction, guardrail 1),
// bounded per tenant (evict-stalest), newest-wins.

// ResultView is one synthetic result, verbatim from the pipeline.
type ResultView struct {
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

// LatestResults retains the newest result per (tenant, type, target, agent).
type LatestResults struct {
	mu      sync.Mutex
	max     int
	tenants map[string]map[string]ResultView // tenant -> type|target|agent -> latest
}

// NewLatestResults builds a store; maxPerTenant <= 0 takes the default.
func NewLatestResults(maxPerTenant int) *LatestResults {
	if maxPerTenant <= 0 {
		maxPerTenant = DefaultMaxResultsPerTenant
	}
	return &LatestResults{max: maxPerTenant, tenants: map[string]map[string]ResultView{}}
}

// Record stores rv as the latest for its series. Unscoped or type-less
// records are dropped (fail closed); older observations never overwrite.
func (s *LatestResults) Record(tenant string, rv ResultView) {
	if tenant == "" || rv.Type == "" {
		return
	}
	key := rv.Type + "\x00" + rv.Target + "\x00" + rv.AgentID
	s.mu.Lock()
	defer s.mu.Unlock()
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
		}
	}
	part[key] = rv
}

// List returns the tenant's latest results, newest first (stable on ties).
func (s *LatestResults) List(tenant string) []ResultView {
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
	return out
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
	bus   bus.Bus
	store *LatestResults
	log   *slog.Logger
}

// NewResultViewConsumer builds the consumer.
func NewResultViewConsumer(b bus.Bus, store *LatestResults, log *slog.Logger) *ResultViewConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &ResultViewConsumer{bus: b, store: store, log: log}
}

// Run consumes until ctx is done; malformed messages are dropped.
// (Standalone mode — production wires SinkResult through the decode-once
// ResultFan, SCALE-013.)
func (cs *ResultViewConsumer) Run(ctx context.Context) error {
	return runResultSink(ctx, cs.bus, viewGroup("result-view"), cs.log, cs.SinkResult)
}

// SinkResult records one DECODED result (shared immutable — never mutated).
func (cs *ResultViewConsumer) SinkResult(_ context.Context, r *resultv1.Result) error {
	cs.store.Record(r.GetTenantId(), ResultView{
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

// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/flow"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

// Flow analytics (S38, F17): tenant-scoped reads over the flow store. The
// tenant comes from the authenticated principal — never from a query param —
// and the store scopes every query by it before anything else (CLAUDE.md §6).

type flowQualityRetention struct {
	MaxPerTenant  int `json:"max_per_tenant"`
	RetentionDays int `json:"retention_days"`
}

type flowQualityResponse struct {
	ContractVersion   string                `json:"contract_version"`
	Items             []flow.QualityReceipt `json:"items"`
	IngestRunning     bool                  `json:"ingest_running"`
	EffectiveLimit    int                   `json:"effective_limit"`
	Truncated         bool                  `json:"truncated"`
	AsOf              time.Time             `json:"as_of"`
	StaleAfterSeconds int                   `json:"stale_after_seconds"`
	Retention         flowQualityRetention  `json:"retention"`
}

// handleFlowIngestQuality serves one bounded current receipt per
// ACL-accepted exporter/protocol. It never exposes raw datagrams, decoded flow
// fields, rejected-source addresses, credentials, or free-form errors.
func (s *Server) handleFlowIngestQuality(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", 100)
	if err != nil {
		return err
	}
	if limit > flow.MaxQualityReceiptRead {
		limit = flow.MaxQualityReceiptRead
	}
	state := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if state != "" && !flow.ValidQualityState(state) {
		return apierror.BadRequest("state must be healthy, degraded, or stale")
	}
	protocol := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("protocol")))
	if protocol != "" && !flow.ValidQualityProtocol(protocol) {
		return apierror.BadRequest("protocol must be netflow, netflow5, netflow9, ipfix, or sflow5")
	}
	exporter := strings.TrimSpace(r.URL.Query().Get("exporter"))
	if exporter != "" {
		exporter, err = flow.NormalizeQualityExporter(exporter)
		if err != nil {
			return apierror.BadRequest(err.Error())
		}
	}
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if len(agentID) > 128 {
		return apierror.BadRequest("agent_id must be at most 128 characters")
	}
	asOf := time.Now().UTC()
	resp := flowQualityResponse{
		ContractVersion: flow.QualityContractVersion,
		Items:           []flow.QualityReceipt{}, IngestRunning: s.flowQuality != nil,
		EffectiveLimit: limit, AsOf: asOf,
		StaleAfterSeconds: int(flow.QualityStaleAfter / time.Second),
		Retention: flowQualityRetention{
			MaxPerTenant:  flow.MaxQualityReceiptsPerTenant,
			RetentionDays: int(flow.QualityReceiptRetention / (24 * time.Hour)),
		},
	}
	if s.flowQuality == nil {
		writeJSON(w, http.StatusOK, resp)
		return nil
	}
	rows, truncated, err := s.flowQuality.ListQualityReceipts(r.Context(), tid, flow.QualityFilter{
		AgentID:  agentID,
		Exporter: exporter, Protocol: protocol, State: state, Limit: limit,
		AsOf: asOf,
	})
	if err != nil {
		return err
	}
	for i := range rows {
		rows[i] = flow.EvaluateQualityState(rows[i], asOf)
	}
	resp.Items, resp.Truncated = rows, truncated
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// handleFlowTop serves GET /v1/flows/top — the top-talkers view.
// Query: by=<allowlisted facet>, window=1h, bucket=3m, limit=10, and repeated
// filter=<field>:<value>. Filters never carry tenant scope.
func (s *Server) handleFlowTop(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	window, err := windowParam(r, "window", time.Hour)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", 10)
	if err != nil {
		return err
	}
	bucket, err := windowParam(r, "bucket", 3*time.Minute)
	if err != nil {
		return err
	}
	filters, err := flowFiltersParam(r)
	if err != nil {
		return err
	}
	q := flowstore.TopQuery{
		TenantID: tid,
		By:       r.URL.Query().Get("by"),
		Window:   window,
		Bucket:   bucket,
		Limit:    limit,
		Filters:  filters,
	}
	rows, err := s.flowStore.TopTalkers(r.Context(), q)
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	series, err := s.flowStore.TopSeries(r.Context(), q, rows)
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	// CORRECT-016: echo the EFFECTIVE limit the store applied (it clamps to
	// <=1000), so a caller that asked for more knows its request was bounded
	// rather than silently assuming it got everything.
	effLimit := limit
	if effLimit <= 0 {
		effLimit = 10
	}
	if effLimit > 1000 {
		effLimit = 1000
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           rows,
		"series":          series,
		"effective_limit": effLimit,
		"series_limit":    min(len(rows), 6),
		"window":          window.String(),
		"bucket":          bucket.String(),
		"filters":         filters,
	})
	return nil
}

// flowFiltersParam parses repeated filter=<field>:<value> parameters. SplitN
// preserves IPv6 values; field/value semantics are normalized again in the
// store so every caller (not only HTTP) gets the same fail-closed validation.
func flowFiltersParam(r *http.Request) ([]flowstore.Filter, error) {
	raw := r.URL.Query()["filter"]
	if len(raw) > 12 {
		return nil, apierror.BadRequest("too many flow filters (max 12)")
	}
	filters := make([]flowstore.Filter, 0, len(raw))
	for _, encoded := range raw {
		parts := strings.SplitN(encoded, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, apierror.BadRequest("invalid flow filter: want field:value")
		}
		filters = append(filters, flowstore.Filter{
			Field: flowstore.FilterField(strings.TrimSpace(parts[0])),
			Value: strings.TrimSpace(parts[1]),
		})
	}
	return filters, nil
}

// handleFlowCapacity serves GET /v1/flows/capacity — per-exporter/interface
// throughput buckets. Query: exporter=, direction=in|out, window=1h, bucket=3m.
func (s *Server) handleFlowCapacity(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	window, err := windowParam(r, "window", time.Hour)
	if err != nil {
		return err
	}
	bucket, err := windowParam(r, "bucket", 0)
	if err != nil {
		return err
	}
	points, err := s.flowStore.Capacity(r.Context(), flowstore.CapacityQuery{
		TenantID:  tid,
		Exporter:  r.URL.Query().Get("exporter"),
		Direction: r.URL.Query().Get("direction"),
		Window:    window,
		Bucket:    bucket,
	})
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": points})
	return nil
}

// handleFlowAnomalies serves GET /v1/flows/anomalies — interfaces whose latest
// bucket departs from their own baseline. Query: window=1h, bucket=, k=3,
// min_bps=1000, exporter=, direction=.
func (s *Server) handleFlowAnomalies(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	window, err := windowParam(r, "window", time.Hour)
	if err != nil {
		return err
	}
	bucket, err := windowParam(r, "bucket", 0)
	if err != nil {
		return err
	}
	k, err := floatParam(r, "k", 0)
	if err != nil {
		return err
	}
	minBps, err := floatParam(r, "min_bps", 0)
	if err != nil {
		return err
	}
	anomalies, err := s.flowStore.Anomalies(r.Context(), flowstore.AnomalyQuery{
		TenantID:    tid,
		Exporter:    r.URL.Query().Get("exporter"),
		Direction:   r.URL.Query().Get("direction"),
		Window:      window,
		Bucket:      bucket,
		Sensitivity: k,
		MinBps:      minBps,
	})
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": anomalies})
	return nil
}

// windowParam parses a duration query parameter (default when absent).
func windowParam(r *http.Request, name string, def time.Duration) (time.Duration, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, apierror.BadRequest("invalid " + name + ": want a positive Go duration like 30m")
	}
	return d, nil
}

// intParam parses a positive integer query parameter.
func intParam(r *http.Request, name string, def int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, apierror.BadRequest("invalid " + name + ": want a positive integer")
	}
	return n, nil
}

// floatParam parses a positive float query parameter.
func floatParam(r *http.Request, name string, def float64) (float64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return 0, apierror.BadRequest("invalid " + name + ": want a non-negative number")
	}
	return f, nil
}

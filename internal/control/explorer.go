// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/cost"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

type explorerColumn struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Numeric bool   `json:"numeric,omitempty"`
}

type explorerResult struct {
	Query        ai.ExplorerQuery    `json:"query"`
	Preview      string              `json:"preview"`
	Columns      []explorerColumn    `json:"columns"`
	Rows         []ai.Row            `json:"rows"`
	Suggestions  map[string][]string `json:"suggestions"`
	EvidencePath string              `json:"evidence_path"`
	Truncated    bool                `json:"truncated"`
}

// handleExplorerSchema returns the fixed grammar and discoverable J3 recipes.
// It contains no tenant telemetry; identity and ai.query are still required so
// this operator surface is never exposed as an unauthenticated capability map.
func (s *Server) handleExplorerSchema(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"templates":      ai.ExplorerTemplates(),
		"visualizations": []string{"table", "bar", "line", "timeline", "topology"},
		"max_rows":       500,
	})
	return nil
}

// handleExplorerQuery executes one bounded recipe against existing tenant-first
// stores. Tenant is resolved before source RBAC; it is never accepted in JSON.
func (s *Server) handleExplorerQuery(w http.ResponseWriter, r *http.Request) error {
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()

	p := auth.PrincipalFrom(r.Context())
	if p == nil || strings.TrimSpace(p.TenantID) == "" {
		return apierror.Unauthorized("authentication required")
	}
	var raw ai.ExplorerQuery
	if err := decodeJSONLimit(r, 1<<16, &raw); err != nil {
		return err
	}
	query, err := ai.NormalizeExplorerQuery(raw, time.Now())
	if err != nil {
		return apierror.Validation(err.Error())
	}
	permission := explorerPermission(query.Source)
	if permission == "" || !p.Has(permission) {
		return apierror.Forbidden("this role cannot read the selected Explorer source")
	}

	rows, err := s.executeExplorer(r.Context(), p.TenantID, query)
	if err != nil {
		s.log.Warn("explorer query failed", "tenant_id", p.TenantID, "source", query.Source, "error", err)
		return apierror.Unavailable("the selected Explorer source is temporarily unavailable")
	}
	filtered := filterExplorerRows(rows, query.Filters)
	truncated := len(filtered) > query.Limit
	if truncated {
		filtered = filtered[:query.Limit]
	}
	if filtered == nil {
		filtered = []ai.Row{}
	}
	result := explorerResult{
		Query: query, Preview: ai.ExplorerPreview(query), Columns: explorerColumns(query),
		Rows: filtered, Suggestions: explorerSuggestions(filtered, query.Dimensions),
		EvidencePath: explorerEvidencePath(query), Truncated: truncated,
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func explorerPermission(source ai.ExplorerSource) string {
	switch source {
	case ai.ExplorerFlow:
		return permFlowRead
	case ai.ExplorerChanges:
		return permChangeRead
	case ai.ExplorerPath:
		return permTestRead
	case ai.ExplorerTopology:
		return ai.PermTopologyRead
	case ai.ExplorerEndpoints:
		return permAgentRead
	case ai.ExplorerTLS:
		return permThreatRead
	case ai.ExplorerCost, ai.ExplorerSLO:
		return ai.PermMetricsRead
	default:
		return ""
	}
}

func (s *Server) executeExplorer(ctx context.Context, tenant string, query ai.ExplorerQuery) ([]ai.Row, error) {
	switch query.Source {
	case ai.ExplorerFlow:
		return s.exploreFlow(ctx, tenant, query)
	case ai.ExplorerChanges:
		selector := make(map[string]string, len(query.Filters)+1)
		for key, value := range query.Filters {
			selector[key] = value
		}
		if query.Template == "asn-before-incident" {
			selector["type"] = "bgp"
		}
		rows, err := (changeEventsSource{pool: s.pool, flow: nil}).QueryEvents(ctx, tenant, selector, ai.TimeRange{Start: query.From, End: query.To}, query.Limit+1)
		if query.Template == "deployments-before-incident" {
			rows = filterExplorerRows(rows, map[string]string{"kind": "deploy"})
		}
		return rows, err
	case ai.ExplorerPath:
		return s.explorePath(ctx, tenant, query)
	case ai.ExplorerTopology:
		return s.exploreTopology(tenant, query)
	case ai.ExplorerEndpoints:
		return s.exploreEndpoints(ctx, tenant, query)
	case ai.ExplorerTLS:
		return s.exploreTLS(tenant, query), nil
	case ai.ExplorerCost:
		return s.exploreCost(tenant), nil
	case ai.ExplorerSLO:
		return s.exploreSLO(tenant), nil
	default:
		return nil, fmt.Errorf("unsupported source %q", query.Source)
	}
}

func (s *Server) exploreFlow(ctx context.Context, tenant string, query ai.ExplorerQuery) ([]ai.Row, error) {
	direction := query.Filters["direction"]
	if direction == "" {
		direction = "in"
	}
	bucket := time.Minute
	window := query.To.Sub(query.From)
	if window > 24*time.Hour {
		bucket = time.Hour
	}
	points, err := s.flowStore.Capacity(ctx, flowstore.CapacityQuery{
		TenantID: tenant, Exporter: query.Filters["site"], Direction: direction,
		Window: window, Bucket: bucket, Now: query.To,
	})
	if err != nil {
		return nil, err
	}
	rows := make([]ai.Row, 0, len(points))
	for _, point := range points {
		rows = append(rows, ai.Row{
			"site": point.Exporter, "interface": strconv.FormatUint(uint64(point.Iface), 10),
			"direction": direction, "bps": point.Bps, "pps": point.Pps, "occurred_at": point.TS,
		})
	}
	return rows, nil
}

func (s *Server) explorePath(ctx context.Context, tenant string, query ai.ExplorerQuery) ([]ai.Row, error) {
	target := query.Filters["target"]
	targets := []string{target}
	if target == "" && s.latestResults != nil {
		targets = targets[:0]
		seen := map[string]bool{}
		for _, result := range s.latestResults.List(tenant) {
			if result.Target != "" && !seen[result.Target] {
				seen[result.Target] = true
				targets = append(targets, result.Target)
			}
		}
	}
	var discovered *path.Path
	for _, candidate := range targets {
		if candidate == "" {
			continue
		}
		latest, found, err := s.pathStore.Latest(ctx, tenant, candidate)
		if err != nil {
			return nil, err
		}
		if found {
			discovered = latest
			break
		}
	}
	if discovered == nil {
		return []ai.Row{}, nil
	}
	rows := []ai.Row{}
	for _, hop := range discovered.Hops {
		for _, node := range hop.Nodes {
			rows = append(rows, ai.Row{
				"target": discovered.Target, "hop": hop.TTL, "node": node.IP,
				"loss_ratio": node.LossRatio, "rtt_avg_ms": node.RTTAvgMs,
			})
		}
	}
	return rows, nil
}

func (s *Server) exploreTopology(tenant string, query ai.ExplorerQuery) ([]ai.Row, error) {
	if s.topo == nil {
		return []ai.Row{}, nil
	}
	graph, err := s.topo.ForTenant(tenant)
	if err != nil {
		return nil, err
	}
	snapshot := graph.SnapshotAt(query.To)
	if len(snapshot.Edges) == 0 {
		latest := graph.Latest()
		if !latest.At.Before(query.From) && !latest.At.After(query.To) {
			snapshot = latest
		}
	}
	rows := make([]ai.Row, 0, len(snapshot.Edges))
	for _, edge := range snapshot.Edges {
		rows = append(rows, ai.Row{"from": edge.From, "to": edge.To, "kind": string(edge.Kind), "edges": 1, "occurred_at": edge.LastSeen})
	}
	return rows, nil
}

func (s *Server) exploreEndpoints(ctx context.Context, tenant string, query ai.ExplorerQuery) ([]ai.Row, error) {
	if s.endpointViews == nil {
		return []ai.Row{}, nil
	}
	items, err := s.endpointViews.ListFilteredContext(ctx, tenant, endpoint.ListFilter{Cause: "impaired"})
	if err != nil {
		return nil, err
	}
	rows := make([]ai.Row, 0, len(items))
	for _, item := range items {
		if item.LastSeenAt.Before(query.From) || item.LastSeenAt.After(query.To) {
			continue
		}
		rows = append(rows, ai.Row{"endpoint": item.AgentID, "cause": item.Cause, "summary": item.Summary, "affected_endpoints": 1, "occurred_at": item.LastSeenAt})
	}
	return rows, nil
}

func (s *Server) exploreTLS(tenant string, query ai.ExplorerQuery) []ai.Row {
	if s.tlsPostures == nil {
		return []ai.Row{}
	}
	rows := []ai.Row{}
	deadline := query.To.Add(30 * 24 * time.Hour)
	for _, posture := range s.tlsPostures.List(tenant) {
		if posture.Leaf == nil || posture.Leaf.NotAfter.Before(query.To) || posture.Leaf.NotAfter.After(deadline) || posture.ObservedAt.Before(query.From) || posture.ObservedAt.After(query.To) {
			continue
		}
		rows = append(rows, ai.Row{
			"target": posture.Target, "subject": posture.Leaf.Subject, "issuer": posture.Leaf.Issuer,
			"days_remaining": int(posture.Leaf.NotAfter.Sub(query.To).Hours() / 24), "occurred_at": posture.ObservedAt,
		})
	}
	return rows
}

func (s *Server) exploreCost(tenant string) []ai.Row {
	if s.costEngine == nil {
		return []ai.Row{}
	}
	rows := []ai.Row{}
	summary := s.costEngine.Summary(tenant)
	for _, pair := range summary.ChattyPairs {
		rows = append(rows, ai.Row{
			"from_zone": pair.SrcZone, "to_zone": pair.DstZone, "service": pair.Service,
			"bytes": pair.Bytes, "usd": pair.USD,
		})
	}
	if len(rows) == 0 {
		if aggregate, ok := summary.ByClass[cost.ClassInterAZ]; ok && aggregate.Bytes > 0 {
			rows = append(rows, ai.Row{
				"from_zone": "multiple", "to_zone": "multiple", "service": "all",
				"bytes": aggregate.Bytes, "usd": aggregate.USD,
			})
		}
	}
	return rows
}

func (s *Server) exploreSLO(tenant string) []ai.Row {
	if s.sloEngine == nil {
		return []ai.Row{}
	}
	rows := []ai.Row{}
	for _, status := range s.sloEngine.Statuses(tenant) {
		burn := 0.0
		for _, window := range status.BurnRates {
			if window.Burn > burn {
				burn = window.Burn
			}
		}
		rows = append(rows, ai.Row{
			"slo": status.Name, "service": status.Service, "team": status.Team,
			"burn_rate": burn, "budget_remaining": status.ErrorBudgetRemaining,
		})
	}
	return rows
}

func filterExplorerRows(rows []ai.Row, filters map[string]string) []ai.Row {
	if len(filters) == 0 {
		return rows
	}
	out := make([]ai.Row, 0, len(rows))
	for _, row := range rows {
		matched := true
		for key, want := range filters {
			if key == "direction" || (key == "target" && row[key] == nil) {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(row[key])), want) {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, row)
		}
	}
	return out
}

func explorerColumns(query ai.ExplorerQuery) []explorerColumn {
	columns := make([]explorerColumn, 0, len(query.Dimensions)+len(query.Measures)+1)
	seen := map[string]bool{}
	// Time visualizations declare the bucket timestamp the source rows already
	// carry (flow points, change/routing events, endpoint and TLS records), so
	// clients can plot line/timeline results on a real time axis instead of an
	// index. Sources without a per-row timestamp simply leave the cells empty
	// and clients fall back to indexed rendering.
	if query.Visualization == "line" || query.Visualization == "timeline" {
		seen["occurred_at"] = true
		columns = append(columns, explorerColumn{Key: "occurred_at", Label: "Occurred at"})
	}
	for _, key := range append(append([]string{}, query.Dimensions...), query.Measures...) {
		if seen[key] {
			continue
		}
		seen[key] = true
		columns = append(columns, explorerColumn{Key: key, Label: explorerLabel(key), Numeric: containsExplorerMeasure(query.Measures, key)})
	}
	return columns
}

func explorerLabel(key string) string {
	words := strings.Split(key, "_")
	for i, word := range words {
		if strings.EqualFold(word, "az") {
			words[i] = "AZ"
			continue
		}
		if word != "" {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

func containsExplorerMeasure(values []string, key string) bool {
	for _, value := range values {
		if value == key {
			return true
		}
	}
	return false
}

func explorerSuggestions(rows []ai.Row, dimensions []string) map[string][]string {
	out := make(map[string][]string, len(dimensions))
	for _, dimension := range dimensions {
		unique := map[string]struct{}{}
		for _, row := range rows {
			value := strings.TrimSpace(fmt.Sprint(row[dimension]))
			if value != "" && value != "<nil>" {
				unique[value] = struct{}{}
			}
		}
		values := make([]string, 0, len(unique))
		for value := range unique {
			values = append(values, value)
		}
		sort.Strings(values)
		if len(values) > 50 {
			values = values[:50]
		}
		out[dimension] = values
	}
	return out
}

func explorerEvidencePath(query ai.ExplorerQuery) string {
	for _, template := range ai.ExplorerTemplates() {
		if template.ID == query.Template {
			return template.EvidencePath
		}
	}
	switch query.Source {
	case ai.ExplorerFlow:
		return "/planes/flow"
	case ai.ExplorerChanges:
		return "/incidents"
	case ai.ExplorerPath:
		return "/path"
	case ai.ExplorerTopology:
		return "/topology"
	case ai.ExplorerEndpoints:
		return "/endpoints"
	case ai.ExplorerTLS:
		return "/security"
	case ai.ExplorerCost:
		return "/cost"
	case ai.ExplorerSLO:
		return "/slos"
	default:
		return "/explore"
	}
}

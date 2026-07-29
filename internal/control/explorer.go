// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
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

// explorerExecutionReceipt is a sanitized, server-authored explanation of the
// logical work Explorer performed. It deliberately describes bounds and
// projection rather than returning SQL, a physical query plan, tenant
// identity, literal filter values, or datastore-wide cardinality.
type explorerExecutionReceipt struct {
	ContractVersion  string                      `json:"contract_version"`
	Recipe           string                      `json:"recipe"`
	Source           ai.ExplorerSource           `json:"source"`
	TenantScoped     bool                        `json:"tenant_scoped"`
	Bounds           explorerExecutionBounds     `json:"bounds"`
	Projection       explorerExecutionProjection `json:"projection"`
	FilterKeys       []string                    `json:"filter_keys"`
	SourceRows       int                         `json:"source_rows"`
	ReturnedRows     int                         `json:"returned_rows"`
	Truncated        bool                        `json:"truncated"`
	TruncationReason string                      `json:"truncation_reason"`
	Timings          explorerExecutionTimings    `json:"timings"`
}

type explorerExecutionBounds struct {
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	RowLimit int       `json:"row_limit"`
}

type explorerExecutionProjection struct {
	Dimensions []string `json:"dimensions"`
	Groupings  []string `json:"groupings"`
	Measures   []string `json:"measures"`
}

type explorerExecutionTimings struct {
	SourceMS  int64 `json:"source_ms"`
	ShapingMS int64 `json:"shaping_ms"`
	TotalMS   int64 `json:"total_ms"`
}

type explorerComparisonExecutionReceipt struct {
	ContractVersion string                            `json:"contract_version"`
	TenantScoped    bool                              `json:"tenant_scoped"`
	Current         explorerExecutionReceipt          `json:"current"`
	Previous        explorerExecutionReceipt          `json:"previous"`
	Alignment       explorerAlignmentExecutionReceipt `json:"alignment"`
	TotalMS         int64                             `json:"total_ms"`
}

type explorerAlignmentExecutionReceipt struct {
	RowLimit         int    `json:"row_limit"`
	ReturnedRows     int    `json:"returned_rows"`
	Truncated        bool   `json:"truncated"`
	TruncationReason string `json:"truncation_reason"`
	ElapsedMS        int64  `json:"elapsed_ms"`
}

type explorerResult struct {
	Query        ai.ExplorerQuery         `json:"query"`
	Preview      string                   `json:"preview"`
	Columns      []explorerColumn         `json:"columns"`
	Rows         []ai.Row                 `json:"rows"`
	Suggestions  map[string][]string      `json:"suggestions"`
	EvidencePath string                   `json:"evidence_path"`
	Truncated    bool                     `json:"truncated"`
	Execution    explorerExecutionReceipt `json:"execution"`
}

type explorerComparisonRequest struct {
	Query        ai.ExplorerQuery `json:"query"`
	PreviousFrom time.Time        `json:"previous_from"`
	PreviousTo   time.Time        `json:"previous_to"`
}

type explorerComparisonRow struct {
	Group         map[string]string `json:"group"`
	Measure       string            `json:"measure"`
	Aggregation   string            `json:"aggregation"`
	CurrentValue  *float64          `json:"current_value"`
	PreviousValue *float64          `json:"previous_value"`
	Delta         *float64          `json:"delta"`
	PercentChange *float64          `json:"percent_change"`
	DeltaState    string            `json:"delta_state"`
}

type explorerComparisonResult struct {
	ContractVersion   string                             `json:"contract_version"`
	Current           ai.ExplorerQuery                   `json:"current"`
	Previous          ai.ExplorerQuery                   `json:"previous"`
	CurrentPreview    string                             `json:"current_preview"`
	PreviousPreview   string                             `json:"previous_preview"`
	Groupings         []string                           `json:"groupings"`
	Rows              []explorerComparisonRow            `json:"rows"`
	Suggestions       map[string][]string                `json:"suggestions"`
	EvidencePath      string                             `json:"evidence_path"`
	State             string                             `json:"state"`
	CurrentTruncated  bool                               `json:"current_truncated"`
	PreviousTruncated bool                               `json:"previous_truncated"`
	RowsTruncated     bool                               `json:"rows_truncated"`
	Execution         explorerComparisonExecutionReceipt `json:"execution"`
}

// handleExplorerSchema returns the fixed grammar and discoverable J3 recipes.
// It contains no tenant telemetry; identity and ai.query are still required so
// this operator surface is never exposed as an unauthenticated capability map.
func (s *Server) handleExplorerSchema(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"templates":          ai.ExplorerTemplates(),
		"visualizations":     []string{"table", "bar", "line", "timeline", "topology"},
		"comparison_sources": []ai.ExplorerSource{ai.ExplorerFlow, ai.ExplorerChanges, ai.ExplorerTopology, ai.ExplorerEndpoints, ai.ExplorerTLS},
		"max_rows":           500,
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

	filtered, execution, err := s.executeExplorerBounded(r.Context(), p.TenantID, query)
	if err != nil {
		s.log.Warn("explorer query failed", "tenant_id", p.TenantID, "source", query.Source, "error", err)
		return apierror.Unavailable("the selected Explorer source is temporarily unavailable")
	}
	result := explorerResult{
		Query: query, Preview: ai.ExplorerPreview(query), Columns: explorerColumns(query),
		Rows: filtered, Suggestions: explorerSuggestions(filtered, query.Dimensions),
		EvidencePath: explorerEvidencePath(query), Truncated: execution.Truncated, Execution: execution,
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// handleExplorerComparison runs the same bounded, tenant-first dispatch for two
// explicit windows. Current-state-only sources are rejected instead of
// pretending their latest snapshot is historical evidence.
func (s *Server) handleExplorerComparison(w http.ResponseWriter, r *http.Request) error {
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()

	p := auth.PrincipalFrom(r.Context())
	if p == nil || strings.TrimSpace(p.TenantID) == "" {
		return apierror.Unauthorized("authentication required")
	}
	var raw explorerComparisonRequest
	if err := decodeJSONLimit(r, 1<<16, &raw); err != nil {
		return err
	}
	current, err := ai.NormalizeExplorerQuery(raw.Query, time.Now())
	if err != nil {
		return apierror.Validation(err.Error())
	}
	if !explorerComparisonSource(current.Source) {
		return apierror.Validation("the selected Explorer source does not retain two exact historical windows")
	}
	if len(current.Measures) == 0 {
		return apierror.Validation("Explorer comparison requires at least one numeric measure")
	}
	if raw.PreviousFrom.IsZero() || raw.PreviousTo.IsZero() {
		return apierror.Validation("previous_from and previous_to are required")
	}
	previous := current
	previous.From = raw.PreviousFrom
	previous.To = raw.PreviousTo
	previous, err = ai.NormalizeExplorerQuery(previous, time.Now())
	if err != nil {
		return apierror.Validation("previous window: " + err.Error())
	}
	if current.From.Equal(current.To) || previous.From.Equal(previous.To) {
		return apierror.Validation("Explorer comparison windows must have positive duration")
	}
	permission := explorerPermission(current.Source)
	if permission == "" || !p.Has(permission) {
		return apierror.Forbidden("this role cannot read the selected Explorer source")
	}

	comparisonStarted := time.Now()
	currentRows, currentExecution, err := s.executeExplorerBounded(r.Context(), p.TenantID, current)
	if err != nil {
		s.log.Warn("explorer comparison current window failed", "tenant_id", p.TenantID, "source", current.Source, "error", err)
		return apierror.Unavailable("the current Explorer window is temporarily unavailable")
	}
	previousRows, previousExecution, err := s.executeExplorerBounded(r.Context(), p.TenantID, previous)
	if err != nil {
		s.log.Warn("explorer comparison previous window failed", "tenant_id", p.TenantID, "source", current.Source, "error", err)
		return apierror.Unavailable("the previous Explorer window is temporarily unavailable")
	}
	alignmentStarted := time.Now()
	rows, rowsTruncated := alignExplorerComparison(currentRows, previousRows, current.Groupings, current.Measures, current.Limit)
	alignmentElapsed := time.Since(alignmentStarted).Milliseconds()
	suggestionRows := append(append([]ai.Row{}, currentRows...), previousRows...)
	writeJSON(w, http.StatusOK, explorerComparisonResult{
		ContractVersion: "explorer-comparison/v1",
		Current:         current, Previous: previous,
		CurrentPreview: ai.ExplorerPreview(current), PreviousPreview: ai.ExplorerPreview(previous),
		Groupings: current.Groupings, Rows: rows,
		Suggestions:  explorerSuggestions(suggestionRows, current.Dimensions),
		EvidencePath: explorerEvidencePath(current),
		State: explorerComparisonState(
			explorerRowsHaveMeasures(currentRows, current.Measures),
			explorerRowsHaveMeasures(previousRows, current.Measures),
		),
		CurrentTruncated: currentExecution.Truncated, PreviousTruncated: previousExecution.Truncated, RowsTruncated: rowsTruncated,
		Execution: explorerComparisonExecutionReceipt{
			ContractVersion: "explorer-comparison-execution/v1",
			TenantScoped:    true,
			Current:         currentExecution,
			Previous:        previousExecution,
			Alignment: explorerAlignmentExecutionReceipt{
				RowLimit:         current.Limit,
				ReturnedRows:     len(rows),
				Truncated:        rowsTruncated,
				TruncationReason: explorerTruncationReason(rowsTruncated, "comparison_row_limit"),
				ElapsedMS:        alignmentElapsed,
			},
			TotalMS: time.Since(comparisonStarted).Milliseconds(),
		},
	})
	return nil
}

func (s *Server) executeExplorerBounded(ctx context.Context, tenant string, query ai.ExplorerQuery) ([]ai.Row, explorerExecutionReceipt, error) {
	started := time.Now()
	sourceStarted := time.Now()
	rows, err := s.executeExplorer(ctx, tenant, query)
	if err != nil {
		return nil, explorerExecutionReceipt{}, err
	}
	sourceElapsed := time.Since(sourceStarted).Milliseconds()
	shapingStarted := time.Now()
	sourceRows := len(rows)
	filtered := filterExplorerRows(rows, query.Filters)
	truncated := len(filtered) > query.Limit
	if truncated {
		filtered = filtered[:query.Limit]
	}
	if filtered == nil {
		filtered = []ai.Row{}
	}
	shapingElapsed := time.Since(shapingStarted).Milliseconds()
	receipt := explorerExecutionReceipt{
		ContractVersion: "explorer-execution/v1",
		Recipe:          explorerRecipe(query),
		Source:          query.Source,
		TenantScoped:    true,
		Bounds: explorerExecutionBounds{
			From: query.From, To: query.To, RowLimit: query.Limit,
		},
		Projection: explorerExecutionProjection{
			Dimensions: append([]string{}, query.Dimensions...),
			Groupings:  append([]string{}, query.Groupings...),
			Measures:   append([]string{}, query.Measures...),
		},
		FilterKeys:       explorerFilterKeys(query.Filters),
		SourceRows:       sourceRows,
		ReturnedRows:     len(filtered),
		Truncated:        truncated,
		TruncationReason: explorerTruncationReason(truncated, "row_limit"),
		Timings: explorerExecutionTimings{
			SourceMS: sourceElapsed, ShapingMS: shapingElapsed, TotalMS: time.Since(started).Milliseconds(),
		},
	}
	return filtered, receipt, nil
}

func explorerRecipe(query ai.ExplorerQuery) string {
	if strings.TrimSpace(query.Template) == "" {
		return "custom"
	}
	return query.Template
}

func explorerFilterKeys(filters map[string]string) []string {
	keys := make([]string, 0, len(filters))
	for key := range filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func explorerTruncationReason(truncated bool, reason string) string {
	if !truncated {
		return "none"
	}
	return reason
}

func explorerComparisonSource(source ai.ExplorerSource) bool {
	switch source {
	case ai.ExplorerFlow, ai.ExplorerChanges, ai.ExplorerTopology, ai.ExplorerEndpoints, ai.ExplorerTLS:
		return true
	default:
		return false
	}
}

func explorerComparisonState(current, previous bool) string {
	switch {
	case !current && !previous:
		return "empty"
	case !current:
		return "previous_only"
	case !previous:
		return "current_only"
	default:
		return "comparable"
	}
}

func explorerRowsHaveMeasures(rows []ai.Row, measures []string) bool {
	for _, row := range rows {
		for _, measure := range measures {
			if _, ok := explorerNumeric(row[measure]); ok {
				return true
			}
		}
	}
	return false
}

type explorerAggregate struct {
	group  map[string]string
	values map[string]float64
	counts map[string]int
}

func alignExplorerComparison(current, previous []ai.Row, groupings, measures []string, limit int) ([]explorerComparisonRow, bool) {
	currentValues := aggregateExplorerRows(current, groupings, measures)
	previousValues := aggregateExplorerRows(previous, groupings, measures)
	keys := make([]string, 0, len(currentValues)+len(previousValues))
	seen := map[string]bool{}
	for key := range currentValues {
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range previousValues {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	rows := make([]explorerComparisonRow, 0, len(keys)*len(measures))
	for _, key := range keys {
		currentGroup, hasCurrent := currentValues[key]
		previousGroup, hasPrevious := previousValues[key]
		group := currentGroup.group
		if !hasCurrent {
			group = previousGroup.group
		}
		for _, measure := range measures {
			currentValue, currentOK := aggregateExplorerMeasure(currentGroup, measure, hasCurrent)
			previousValue, previousOK := aggregateExplorerMeasure(previousGroup, measure, hasPrevious)
			if !currentOK && !previousOK {
				continue
			}
			row := explorerComparisonRow{
				Group: group, Measure: measure, Aggregation: explorerMeasureAggregation(measure),
				CurrentValue: floatPointer(currentValue, currentOK), PreviousValue: floatPointer(previousValue, previousOK),
				DeltaState: "comparable",
			}
			switch {
			case !currentOK:
				row.DeltaState = "missing_current"
			case !previousOK:
				row.DeltaState = "missing_previous"
			default:
				delta := currentValue - previousValue
				row.Delta = &delta
				if previousValue == 0 {
					row.DeltaState = "zero_baseline"
				} else {
					percent := delta / previousValue * 100
					row.PercentChange = &percent
				}
			}
			rows = append(rows, row)
		}
	}
	truncated := len(rows) > limit
	if truncated {
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []explorerComparisonRow{}
	}
	return rows, truncated
}

func aggregateExplorerRows(rows []ai.Row, groupings, measures []string) map[string]explorerAggregate {
	out := map[string]explorerAggregate{}
	for _, row := range rows {
		group := make(map[string]string, len(groupings))
		var key strings.Builder
		for _, grouping := range groupings {
			value := strings.TrimSpace(fmt.Sprint(row[grouping]))
			group[grouping] = value
			_, _ = fmt.Fprintf(&key, "%d:%s|", len(value), value)
		}
		encoded := key.String()
		aggregate, ok := out[encoded]
		if !ok {
			aggregate = explorerAggregate{group: group, values: map[string]float64{}, counts: map[string]int{}}
		}
		for _, measure := range measures {
			if value, ok := explorerNumeric(row[measure]); ok {
				aggregate.values[measure] += value
				aggregate.counts[measure]++
			}
		}
		out[encoded] = aggregate
	}
	return out
}

func aggregateExplorerMeasure(aggregate explorerAggregate, measure string, present bool) (float64, bool) {
	if !present || aggregate.counts[measure] == 0 {
		return 0, false
	}
	value := aggregate.values[measure]
	if explorerMeasureAggregation(measure) == "mean" {
		value /= float64(aggregate.counts[measure])
	}
	return value, true
}

func explorerMeasureAggregation(measure string) string {
	switch measure {
	case "events", "edges", "affected_endpoints", "bytes", "usd":
		return "sum"
	default:
		return "mean"
	}
}

func explorerNumeric(value any) (float64, bool) {
	switch value := value.(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int8:
		return float64(value), true
	case int16:
		return float64(value), true
	case int32:
		return float64(value), true
	case int64:
		return float64(value), true
	case uint:
		return float64(value), true
	case uint8:
		return float64(value), true
	case uint16:
		return float64(value), true
	case uint32:
		return float64(value), true
	case uint64:
		return float64(value), true
	case json.Number:
		number, err := value.Float64()
		return number, err == nil
	default:
		return 0, false
	}
}

func floatPointer(value float64, ok bool) *float64 {
	if !ok {
		return nil
	}
	return &value
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
		rows, err := (changeEventsSource{pool: s.pool, flow: nil, configs: s.deviceOps}).QueryEvents(ctx, tenant, selector, ai.TimeRange{Start: query.From, End: query.To}, query.Limit+1)
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

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func nativeFlowProjectionError() error {
	return apierror.Unavailable("native flow result projection is unavailable")
}

func nativeFlowDimensions(fields []string, values map[string]string, other bool, vocabulary flow.QueryVocabulary) ([]mcp.NativeFlowDimension, error) {
	result := make([]mcp.NativeFlowDimension, 0, len(fields))
	if other {
		return result, nil
	}
	for _, field := range fields {
		if _, ok := vocabulary.Lookup(field); !ok {
			return nil, nativeFlowProjectionError()
		}
		value, ok := values[field]
		if !ok {
			return nil, nativeFlowProjectionError()
		}
		result = append(result, mcp.NativeFlowDimension{Field: field, Value: value})
	}
	return result, nil
}
func nativeFlowValues(metrics []flow.QueryMetric, values map[string]string, plotted bool) ([]mcp.NativeFlowValue, error) {
	result := make([]mcp.NativeFlowValue, 0, len(metrics))
	for _, metric := range metrics {
		if plotted && metric.Role == "additional" {
			continue
		}
		key := metric.Measure + ":" + metric.Calculation
		value, ok := values[key]
		if ok {
			if len(value) > 256 || !flowCSVDecimal.MatchString(value) {
				return nil, nativeFlowProjectionError()
			}
		}
		result = append(result, mcp.NativeFlowValue{Metric: key, Value: value, Defined: ok})
	}
	return result, nil
}
func nativeFlowRows(rows []flowstore.PlanRow, fields []string, metrics []flow.QueryMetric, vocabulary flow.QueryVocabulary) ([]mcp.NativeFlowRow, error) {
	result := make([]mcp.NativeFlowRow, 0, len(rows))
	for _, row := range rows {
		group, err := nativeFlowDimensions(fields, row.Group, row.Other, vocabulary)
		if err != nil {
			return nil, err
		}
		values, err := nativeFlowValues(metrics, row.Metrics, false)
		if err != nil {
			return nil, err
		}
		result = append(result, mcp.NativeFlowRow{Group: group, Other: row.Other, Metrics: values})
	}
	return result, nil
}
func nativeFlowSummary(row *flowstore.PlanRow, fields []string, metrics []flow.QueryMetric, vocabulary flow.QueryVocabulary) (*mcp.NativeFlowRow, error) {
	if row == nil {
		return nil, nil
	}
	rows, err := nativeFlowRows([]flowstore.PlanRow{*row}, fields, metrics, vocabulary)
	if err != nil {
		return nil, err
	}
	return &rows[0], nil
}
func nativeFlowPoints(points []flowstore.PlanPoint, fields []string, metrics []flow.QueryMetric, vocabulary flow.QueryVocabulary) ([]mcp.NativeFlowPoint, error) {
	result := make([]mcp.NativeFlowPoint, 0, len(points))
	for _, point := range points {
		group, err := nativeFlowDimensions(fields, point.Group, point.Other || len(point.Group) == 0, vocabulary)
		if err != nil {
			return nil, err
		}
		values, err := nativeFlowValues(metrics, point.Metrics, true)
		if err != nil {
			return nil, err
		}
		if len(point.DurationSeconds) > 256 || !flowCSVDecimal.MatchString(point.DurationSeconds) {
			return nil, nativeFlowProjectionError()
		}
		duration, ok := new(big.Rat).SetString(point.DurationSeconds)
		if point.TS.IsZero() || !ok || duration.Sign() <= 0 {
			return nil, nativeFlowProjectionError()
		}
		result = append(result, mcp.NativeFlowPoint{Group: group, Other: point.Other, TS: point.TS, DurationSeconds: point.DurationSeconds, Metrics: values})
	}
	return result, nil
}

type nativeFlowProjectionOptions struct {
	ctx    context.Context
	budget flowstore.ExplorerBudget
}

func projectNativeFlow(source flowstore.PlanResult, tenant string, options ...nativeFlowProjectionOptions) (mcp.NativeFlowResult, error) {
	if (source.Source != "raw" && source.Source != "rollup") || source.ResolutionSeconds < 1 || source.TotalGroups < 0 || source.Query.From.IsZero() || source.Query.To.IsZero() || source.Query.View == "" || len(source.Query.Metrics) == 0 {
		return mcp.NativeFlowResult{}, nativeFlowProjectionError()
	}
	ctx := context.Background()
	budget := flowstore.DefaultExplorerBudget()
	if len(options) > 0 {
		if options[0].ctx != nil {
			ctx = options[0].ctx
		}
		budget = options[0].budget
	}
	if err := ctx.Err(); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	vocabulary, err := source.OutputVocabulary(tenant)
	if err != nil {
		return mcp.NativeFlowResult{}, nativeFlowProjectionError()
	}
	query, err := flow.NormalizeQueryPlanWithVocabulary(source.Query, time.Now(), vocabulary)
	if err != nil {
		return mcp.NativeFlowResult{}, nativeFlowProjectionError()
	}
	out := mcp.NativeFlowResult{Query: query, Source: source.Source, ResolutionSeconds: source.ResolutionSeconds, TotalGroups: source.TotalGroups, DetailLimited: source.DetailLimited}
	if err := projectNativeFlowRoles(ctx, &out, source, tenant, budget); err != nil {
		return mcp.NativeFlowResult{}, err
	}

	if source.TagRevision > 0 {
		out.TagTenantID = source.TagTenantID
		out.TagRevision = strconv.FormatInt(source.TagRevision, 10)
		for field, id := range source.TagIDs {
			out.TagIDs = append(out.TagIDs, mcp.NativeFlowTagID{Field: field, ID: id})
		}
		sort.Slice(out.TagIDs, func(i, j int) bool { return out.TagIDs[i].Field < out.TagIDs[j].Field })
	}
	if source.Coverage != nil {
		fields := []string{}
		for _, field := range source.Coverage.Fields {
			if _, ok := vocabulary.Lookup(field); ok {
				fields = append(fields, field)
			}
		}
		out.Coverage = &mcp.NativeFlowCoverage{Fields: fields, ResolutionSeconds: source.Coverage.ResolutionSeconds, CompleteInputs: source.Coverage.CompleteInputs}
	}
	ids := make([]string, 0, len(source.SavedFilterVersions))
	for id := range source.SavedFilterVersions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out.FilterVersions = []mcp.NativeFlowRevision{}
	for _, id := range ids {
		version := source.SavedFilterVersions[id]
		if version < 1 {
			return mcp.NativeFlowResult{}, nativeFlowProjectionError()
		}
		out.FilterVersions = append(out.FilterVersions, mcp.NativeFlowRevision{ID: id, Version: strconv.FormatInt(version, 10)})
	}
	if out.Rows, err = nativeFlowRows(source.Rows, query.GroupBy, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.ChartRows, err = nativeFlowRows(source.ChartRows, query.GroupBy, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.MatrixRows, err = nativeFlowRows(source.MatrixRows, query.GroupBy, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.MatrixColumns, err = nativeFlowRows(source.MatrixColumns, query.MatrixWith, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.Other, err = nativeFlowSummary(source.Other, query.GroupBy, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.ChartOther, err = nativeFlowSummary(source.ChartOther, query.GroupBy, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.Totals, err = nativeFlowValues(query.Metrics, source.Totals, false); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.Series, err = nativeFlowPoints(source.Series, query.GroupBy, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.OtherSeries, err = nativeFlowPoints(source.OtherSeries, query.GroupBy, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	if out.TotalSeries, err = nativeFlowPoints(source.TotalSeries, nil, query.Metrics, vocabulary); err != nil {
		return mcp.NativeFlowResult{}, err
	}
	out.Matrix = []mcp.NativeFlowCell{}
	for _, cell := range source.Matrix {
		row, err := nativeFlowDimensions(query.GroupBy, cell.Row, cell.RowOther, vocabulary)
		if err != nil {
			return mcp.NativeFlowResult{}, err
		}
		column, err := nativeFlowDimensions(query.MatrixWith, cell.Column, cell.ColumnOther, vocabulary)
		if err != nil {
			return mcp.NativeFlowResult{}, err
		}
		values, err := nativeFlowValues(query.Metrics, cell.Metrics, false)
		if err != nil {
			return mcp.NativeFlowResult{}, err
		}
		out.Matrix = append(out.Matrix, mcp.NativeFlowCell{Row: row, Column: column, RowOther: cell.RowOther, ColumnOther: cell.ColumnOther, Metrics: values})
	}
	return out, nil
}
func nativeFlowPaging(source *flowSnapshotPaging) *mcp.NativeFlowPaging {
	if source == nil {
		return nil
	}
	return &mcp.NativeFlowPaging{SnapshotID: source.SnapshotID, ExpiresAt: source.ExpiresAt, SelectedRows: source.SelectedRows, Offset: source.Offset, PageSize: source.PageSize, More: source.More, NextCursor: source.NextCursor}
}
func projectNativeFlowQuery(source explorerResult, tenant string, options ...nativeFlowProjectionOptions) (mcp.NativeFlowQueryResult, error) {
	if source.Flow == nil {
		return mcp.NativeFlowQueryResult{}, nativeFlowProjectionError()
	}
	data, err := projectNativeFlow(*source.Flow, tenant, options...)
	if err != nil {
		return mcp.NativeFlowQueryResult{}, err
	}
	return mcp.NativeFlowQueryResult{Flow: data, Paging: nativeFlowPaging(source.FlowPaging)}, nil
}
func projectNativeFlowComparison(source explorerComparisonResult, tenant string, options ...nativeFlowProjectionOptions) (mcp.NativeFlowComparisonResult, error) {
	if source.Flow == nil {
		return mcp.NativeFlowComparisonResult{}, nativeFlowProjectionError()
	}
	if source.Flow.Current.RoleTenantID != source.Flow.Previous.RoleTenantID || source.Flow.Current.RoleDigest != source.Flow.Previous.RoleDigest || source.Flow.Current.TagTenantID != source.Flow.Previous.TagTenantID || source.Flow.Current.TagRevision != source.Flow.Previous.TagRevision || !maps.Equal(source.Flow.Current.TagIDs, source.Flow.Previous.TagIDs) {
		return mcp.NativeFlowComparisonResult{}, nativeFlowProjectionError()
	}
	now, err := projectNativeFlow(source.Flow.Current, tenant, options...)
	if err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	before, err := projectNativeFlow(source.Flow.Previous, tenant, options...)
	if err != nil {
		return mcp.NativeFlowComparisonResult{}, err
	}
	vocabulary, err := source.Flow.Current.OutputVocabulary(tenant)
	if err != nil {
		return mcp.NativeFlowComparisonResult{}, nativeFlowProjectionError()
	}
	rows := make([]mcp.NativeFlowComparisonRow, 0, len(source.Rows))
	selected := map[string]bool{}
	for _, metric := range now.Query.Metrics {
		selected[metric.Measure+":"+metric.Calculation] = true
	}
	for _, row := range source.Rows {
		if !selected[row.Measure] {
			return mcp.NativeFlowComparisonResult{}, nativeFlowProjectionError()
		}
		for index, value := range []*string{row.CurrentExact, row.PreviousExact, row.DeltaExact, row.PercentExact} {
			if value != nil {
				valid := len(*value) <= 256 && flowCSVDecimal.MatchString(*value)
				if index >= 2 {
					valid = len(*value) <= 256 && flowCSVSignedDecimal.MatchString(*value)
				}
				if !valid {
					return mcp.NativeFlowComparisonResult{}, nativeFlowProjectionError()
				}
			}
		}
		group, err := nativeFlowDimensions(now.Query.GroupBy, row.Group, row.Other, vocabulary)
		if err != nil {
			return mcp.NativeFlowComparisonResult{}, err
		}
		rows = append(rows, mcp.NativeFlowComparisonRow{Group: group, Other: row.Other, Metric: row.Measure, Calculation: row.Aggregation, Current: row.CurrentExact, Previous: row.PreviousExact, Delta: row.DeltaExact, PercentChange: row.PercentExact, State: row.DeltaState})
	}
	return mcp.NativeFlowComparisonResult{ContractVersion: source.ContractVersion, Current: now, Previous: before, Rows: rows, Membership: source.Flow.Membership, Paging: nativeFlowPaging(source.FlowPaging)}, nil
}
func projectNativeFlowFilter(source flow.SavedQueryFilter) mcp.NativeFlowFilter {
	return mcp.NativeFlowFilter{ID: source.ID, Version: strconv.FormatInt(source.Version, 10), Name: source.Name, Description: source.Description, Expression: source.Expression, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt}
}
func projectNativeFlowView(source flow.SavedQueryView) mcp.NativeFlowView {
	definition := source.Definition
	tagIDs := make([]mcp.NativeFlowTagID, 0, len(definition.TagIDs))
	for field, id := range definition.TagIDs {
		tagIDs = append(tagIDs, mcp.NativeFlowTagID{Field: field, ID: id})
	}
	sort.Slice(tagIDs, func(i, j int) bool { return tagIDs[i].Field < tagIDs[j].Field })
	projection := mcp.NativeFlowViewDefinition{Name: definition.Name, Description: definition.Description,
		Labels: definition.Labels, Visibility: definition.Visibility, Plan: definition.Plan,
		Time: definition.Time, Comparison: definition.Comparison, AutoRefreshSeconds: definition.AutoRefreshSeconds,
		Display: definition.Display, TagIDs: tagIDs}
	return mcp.NativeFlowView{ID: source.ID, OwnerID: source.OwnerID, Version: source.Version, Definition: projection, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt, Favorite: source.Favorite, LastOpenedAt: source.LastOpenedAt}
}

// Reconstruct the immutable projection under the authenticated tenant and the
// existing configured query admission. A digest is provenance, never a grant;
// service/current-credential checks have already run and remain mandatory.
func projectNativeFlowRoles(ctx context.Context, out *mcp.NativeFlowResult, source flowstore.PlanResult, tenant string, budget flowstore.ExplorerBudget) error {
	if !flowstore.PlanUsesInterfaceRoles(source.Query) {
		if source.RoleTenantID != "" || source.RoleDigest != "" || len(source.RoleSources) > 0 {
			return nativeFlowProjectionError()
		}
		return nil
	}
	if tenant == "" || source.RoleTenantID != tenant || source.RoleDigest == "" {
		return nativeFlowProjectionError()
	}
	at := time.Now().UTC()
	if bound, present := tenancy.FromContext(ctx); present && bound.String() != tenant {
		return nativeFlowProjectionError()
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	data, err := flowstore.NewInterfaceRoleQueryData(ctx, tenant, at, source.RoleSources, budget.MemoryBytes/8)
	if err != nil {
		return nativeFlowProjectionError()
	}
	digest, err := data.Digest(ctx, tenant, at)
	if err != nil || digest != source.RoleDigest {
		return nativeFlowProjectionError()
	}
	out.RoleTenantID, out.RoleDigest = mcp.NativeRoleUUID(tenant), mcp.NativeRoleDigest(digest)
	out.RoleSources = make([]mcp.NativeFlowRoleSource, 0, len(source.RoleSources))
	for _, row := range source.RoleSources {
		if err := ctx.Err(); err != nil {
			return err
		}
		refs := make([]mcp.NativeRoleSource, 0, len(row.Sources))
		for _, ref := range row.Sources {
			if err := ctx.Err(); err != nil {
				return err
			}
			refs = append(refs, mcp.NativeRoleSource(ref))
		}
		out.RoleSources = append(out.RoleSources, mcp.NativeFlowRoleSource{TenantID: mcp.NativeRoleUUID(row.TenantID), ContextID: mcp.NativeRoleUUID(row.ContextID), RouterID: mcp.NativeRoleUUID(row.RouterID), InterfaceID: mcp.NativeRoleUUID(row.InterfaceID), Exporter: row.Exporter, Protocol: row.Protocol, Domain: row.Domain, IfIndex: row.IfIndex, Role: string(row.Role), Reason: row.Reason, Sources: refs, ValidUntil: row.ValidUntil})
	}
	return nil
}

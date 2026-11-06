// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

// PlanQuery carries authenticated scope separately from the untrusted grammar.
// Saved expressions have already been tenant-resolved and authorized; the
// storage boundary validates the expanded expression again.
type PlanQuery struct {
	TenantID string
	Plan     flow.QueryPlan
	// Tags is one authenticated tenant's immutable tag revision. Nil keeps
	// native-only queries on their existing path.
	Tags *TagQueryData
	// Roles is current, fully authorized interface metadata. A selected role
	// field requires it; nil cannot silently turn missing authority into Other.
	Roles *InterfaceRoleQueryData
	// SelectedGroups is server-selected comparison membership, never grammar.
	// Nil ranks automatically; an explicit empty selection puts every row in Other.
	SelectedGroups [][]string
	// SelectedColumns pins the row-conditioned matrix axis across periods.
	SelectedColumns [][]string
	// Chart and matrix axes are independent of the detail/page row count.
	SelectedChartGroups [][]string
	SelectedMatrixRows  [][]string
}

// PlanRow's decimal strings preserve counters above JavaScript's integer limit.
// A metric key is measure:calculation; all ranking happens before formatting.
type PlanRow struct {
	Group   map[string]string `json:"group"`
	Other   bool              `json:"other"`
	Metrics map[string]string `json:"metrics"`
}

type PlanPoint struct {
	Group           map[string]string `json:"group"`
	Other           bool              `json:"other"`
	TS              time.Time         `json:"ts"`
	DurationSeconds string            `json:"duration_seconds"`
	Metrics         map[string]string `json:"metrics"`
}

type PlanMatrixCell struct {
	Row         map[string]string `json:"row"`
	Column      map[string]string `json:"column"`
	RowOther    bool              `json:"row_other"`
	ColumnOther bool              `json:"column_other"`
	Metrics     map[string]string `json:"metrics"`
}

// PlanResult is a complete bounded materialization before snapshot pagination.
// Detail and chart selections are independent. Other is recomputed from input
// identities, including exact distinct sets, rather than subtracting counts.
type PlanResult struct {
	// OldestInput is private cache-validity metadata from the same scoped,
	// filtered input, including groups represented by Other. Empty queries
	// leave it zero; the requested From bound is not an input-retention clock.
	OldestInput         time.Time                 `json:"-"`
	Coverage            *PlanSourceCoverage       `json:"coverage,omitempty"`
	Query               flow.QueryPlan            `json:"query"`
	SavedFilterVersions map[string]int64          `json:"saved_filter_versions,omitempty"`
	Source              string                    `json:"source"`
	TagRevision         int64                     `json:"tag_revision,omitempty"`
	TagTenantID         string                    `json:"tag_tenant_id,omitempty"`
	RoleDigest          string                    `json:"role_digest,omitempty"`
	RoleTenantID        string                    `json:"role_tenant_id,omitempty"`
	RoleSources         []InterfaceRoleProjection `json:"role_sources,omitempty"`
	// TagIDs preserves the immutable field identities in Query and Coverage.
	// It describes this result, never client-supplied query authority.
	TagIDs            map[string]string `json:"tag_ids,omitempty"`
	ResolutionSeconds int               `json:"resolution_seconds"`
	TotalGroups       int               `json:"total_groups"`
	DetailLimited     bool              `json:"detail_limited"`
	Rows              []PlanRow         `json:"rows"`
	ChartRows         []PlanRow         `json:"chart_rows,omitempty"`
	MatrixRows        []PlanRow         `json:"matrix_rows,omitempty"`
	Other             *PlanRow          `json:"other,omitempty"`
	ChartOther        *PlanRow          `json:"chart_other,omitempty"`
	Totals            map[string]string `json:"totals"`
	Series            []PlanPoint       `json:"series"`
	OtherSeries       []PlanPoint       `json:"other_series"`
	// TotalSeries is aggregated from all matching tenant inputs per bucket,
	// never from selected/Other group statistics. Table queries omit points.
	TotalSeries   []PlanPoint      `json:"total_series,omitzero"`
	Matrix        []PlanMatrixCell `json:"matrix"`
	MatrixColumns []PlanRow        `json:"matrix_columns,omitempty"`
}

// PlanStore is the expanded query capability. Pagination belongs to a durable,
// tenant-prefixed materialization, so replicas cannot recalculate page two
// against a later ingestion snapshot.
type PlanStore interface {
	ExplorePlan(context.Context, PlanQuery) (PlanResult, error)
}

func PlanStoreOf(store Store) (PlanStore, bool) {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		default:
			result, ok := store.(PlanStore)
			return result, ok
		}
	}
}

const planIntermediateLimit = 500000

func planMetricKey(metric flow.QueryMetric) string { return metric.Measure + ":" + metric.Calculation }

func planDistinctFields(plan flow.QueryPlan) []string {
	fields := []string{}
	for _, definition := range flow.QueryMetricDefinitions() {
		if definition.DistinctField == "" {
			continue
		}
		for _, metric := range plan.Metrics {
			if metric.Measure == definition.Name {
				fields = append(fields, definition.DistinctField)
				break
			}
		}
	}
	return fields
}

type planAccumulator struct {
	bytes, packets, flows big.Int
	distinct              map[string]map[string]struct{}
}

func newPlanAccumulator(distinct []string) *planAccumulator {
	a := &planAccumulator{distinct: map[string]map[string]struct{}{}}
	for _, field := range distinct {
		a.distinct[field] = map[string]struct{}{}
	}
	return a
}

// add returns an allocation charge for the cost budget (not a user row cap).
func (a *planAccumulator) add(row Row) int {
	a.bytes.Add(&a.bytes, new(big.Int).SetUint64(row.BytesScaled))
	a.packets.Add(&a.packets, new(big.Int).SetUint64(row.PacketsScaled))
	a.flows.Add(&a.flows, big.NewInt(1))
	charged := 0
	for field, set := range a.distinct {
		value := ""
		switch field {
		case "src_addr":
			value = explorerCanonicalAddress(row.SrcAddr)
		case "dst_addr":
			value = explorerCanonicalAddress(row.DstAddr)
		case "src_port":
			value = new(big.Int).SetUint64(uint64(row.SrcPort)).String()
		case "dst_port":
			value = new(big.Int).SetUint64(uint64(row.DstPort)).String()
		case "src_asn":
			if row.SrcASN != 0 {
				value = new(big.Int).SetUint64(uint64(row.SrcASN)).String()
			}
		case "dst_asn":
			if row.DstASN != 0 {
				value = new(big.Int).SetUint64(uint64(row.DstASN)).String()
			}
		case "src_country":
			value = row.SrcCountry
		case "dst_country":
			value = row.DstCountry
		}
		if value != "" {
			if _, exists := set[value]; !exists {
				set[value] = struct{}{}
				charged += 64 + len(value)
			}
		}
	}
	return charged
}

func (a *planAccumulator) value(measure string, duration time.Duration) *big.Rat {
	switch measure {
	case "bytes":
		return new(big.Rat).SetInt(&a.bytes)
	case "packets":
		return new(big.Rat).SetInt(&a.packets)
	case "flows":
		return new(big.Rat).SetInt(&a.flows)
	case "bps", "pps", "fps":
		numerator := new(big.Int).Set(&a.bytes)
		switch measure {
		case "bps":
			numerator.Mul(numerator, big.NewInt(8))
		case "pps":
			numerator.Set(&a.packets)
		case "fps":
			numerator.Set(&a.flows)
		}
		numerator.Mul(numerator, big.NewInt(int64(time.Second)))
		return new(big.Rat).SetFrac(numerator, big.NewInt(int64(duration)))
	}
	field := map[string]string{"unique_src": "src_addr", "unique_dst": "dst_addr", "unique_src_port": "src_port", "unique_dst_port": "dst_port", "unique_src_asn": "src_asn", "unique_dst_asn": "dst_asn", "unique_src_country": "src_country", "unique_dst_country": "dst_country"}[measure]
	if field != "" {
		return new(big.Rat).SetInt64(int64(len(a.distinct[field])))
	}
	return new(big.Rat)
}

func planMetricString(value *big.Rat) string {
	if value.IsInt() {
		return value.Num().String()
	}
	// Decimal statistics use 18 fractional places, truncated toward zero, as
	// ClickHouse divideDecimal does. Integer counters remain exact.
	scaled := new(big.Int).Mul(value.Num(), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	scaled.Quo(scaled, value.Denom())
	digits := scaled.String()
	if len(digits) <= 18 {
		digits = strings.Repeat("0", 19-len(digits)) + digits
	}
	return digits[:len(digits)-18] + "." + digits[len(digits)-18:]
}

type planAggregate struct {
	group   map[string]string
	total   *planAccumulator
	buckets map[int64]*planAccumulator
	stats   map[string]*big.Rat
}

func newPlanAggregate(group map[string]string, distinct []string) *planAggregate {
	return &planAggregate{group: group, total: newPlanAccumulator(distinct), buckets: map[int64]*planAccumulator{}}
}

type planCost struct {
	groups, bytes int
	budget        ExplorerBudget
}

func (c *planCost) charge(groups, bytes int) error {
	budget := c.budget
	if budget == (ExplorerBudget{}) {
		budget = DefaultExplorerBudget()
	}
	byteLimit := min(budget.ReadBytes, budget.MemoryBytes)
	if groups < 0 || bytes < 0 || groups > budget.IntermediateGroups-c.groups || int64(bytes) > byteLimit-int64(c.bytes) {
		return ErrExplorerBudget
	}
	c.groups += groups
	c.bytes += bytes
	return nil
}

func (a *planAggregate) add(row Row, plan flow.QueryPlan, distinct []string, cost *planCost) error {
	bucket := int64(row.TS.Sub(plan.From) / (time.Duration(plan.BucketSeconds) * time.Second))
	charged := a.total.add(row)
	if a.buckets[bucket] == nil {
		if err := cost.charge(1, 384+len(distinct)*64); err != nil {
			return err
		}
		a.buckets[bucket] = newPlanAccumulator(distinct)
	}
	charged += a.buckets[bucket].add(row)
	return cost.charge(0, charged)
}

func planBucketBounds(plan flow.QueryPlan, index int64) (time.Time, time.Duration) {
	start := plan.From.Add(time.Duration(index) * time.Duration(plan.BucketSeconds) * time.Second)
	duration := time.Duration(plan.BucketSeconds) * time.Second
	if remaining := plan.To.Sub(start); remaining < duration {
		duration = remaining
	}
	return start, duration
}

func (a *planAggregate) calculate(plan flow.QueryPlan) error {
	window := plan.To.Sub(plan.From)
	width := time.Duration(plan.BucketSeconds) * time.Second
	buckets := uint64((window-1)/width) + 1
	a.stats = map[string]*big.Rat{}
	for _, metric := range plan.Metrics {
		input := make([]metricBucket, 0, len(a.buckets))
		for index, bucket := range a.buckets {
			_, duration := planBucketBounds(plan, index)
			input = append(input, metricBucket{value: bucket.value(metric.Measure, duration), duration: duration})
		}
		rate := metric.Measure == "bps" || metric.Measure == "pps" || metric.Measure == "fps"
		totalMeasure := metric.Measure
		switch metric.Measure {
		case "bps":
			totalMeasure = "bytes"
		case "pps":
			totalMeasure = "packets"
		case "fps":
			totalMeasure = "flows"
		}
		value, err := calculateFlowMetric(input, buckets, window, metric.Calculation, a.total.value(totalMeasure, window), rate)
		if err != nil {
			return err
		}
		a.stats[planMetricKey(metric)] = value
	}
	return nil
}

func (a *planAggregate) row(other bool) PlanRow {
	row := PlanRow{Group: a.group, Other: other, Metrics: map[string]string{}}
	for key, value := range a.stats {
		row.Metrics[key] = planMetricString(value)
	}
	return row
}

func planPrimary(plan flow.QueryPlan) string {
	for _, metric := range plan.Metrics {
		if metric.Role == "primary" {
			return planMetricKey(metric)
		}
	}
	return ""
}

func sortedPlanGroups(groups map[string]*planAggregate, plan flow.QueryPlan) ([]string, error) {
	keys := make([]string, 0, len(groups))
	primary := planPrimary(plan)
	for key, group := range groups {
		if err := group.calculate(plan); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		compared := groups[keys[i]].stats[primary].Cmp(groups[keys[j]].stats[primary])
		if compared != 0 {
			return compared > 0
		}
		return keys[i] < keys[j]
	})
	return keys, nil
}

func planTuple(value func(string) string, fields []string) (string, map[string]string) {
	tuple := make([]string, len(fields))
	group := map[string]string{}
	for i, field := range fields {
		tuple[i] = value(field)
		group[field] = tuple[i]
	}
	encoded, _ := json.Marshal(tuple)
	return string(encoded), group
}

type planInput struct {
	row                    Row
	key, rowKey, columnKey string
	column                 map[string]string
}

func memoryPlanTagVocabulary(query PlanQuery) (flow.QueryVocabulary, error) {
	if query.Tags == nil {
		return flow.QueryVocabulary{}, nil
	}
	return query.Tags.Vocabulary(query.TenantID)
}

func memoryPlanCoverage(query PlanQuery, vocabulary flow.QueryVocabulary) ([]string, error) {
	fields := allPlanFields()
	if query.Tags == nil {
		return fields, nil
	}
	available, err := vocabulary.Fields()
	if err != nil {
		return nil, err
	}
	for _, field := range available {
		if field.Derived == "tenant_tag" {
			fields = append(fields, field.Name)
		}
	}
	return fields, nil
}

func earliestPlanInput(current, candidate time.Time) time.Time {
	if current.IsZero() || candidate.Before(current) {
		return candidate.UTC()
	}
	return current
}

// ExplorePlan is the exact reference implementation for the new grammar.
// Storage scope is enforced before snapshot copying and before filter work.
func (m *Memory) ExplorePlan(ctx context.Context, query PlanQuery) (PlanResult, error) {
	if strings.TrimSpace(query.TenantID) == "" {
		return PlanResult{}, ErrNoTenant
	}
	budget, err := explorerPlanBudget(ctx, m, query.TenantID, m)
	if err != nil {
		return PlanResult{}, err
	}
	ctx = withExplorerBudget(ctx, budget)
	vocabulary, err := memoryPlanTagVocabulary(query)
	if err != nil {
		return PlanResult{}, err
	}
	plan, err := flow.NormalizeQueryPlanWithVocabulary(query.Plan, time.Now(), vocabulary)
	if err != nil {
		return PlanResult{}, err
	}
	if plan.Cursor != "" {
		return PlanResult{}, errors.New("flow cursor must be resolved from its stored snapshot before execution")
	}
	if err := validatePlanInterfaceRoles(ctx, query, plan); err != nil {
		return PlanResult{}, err
	}
	if plan.DataSeries == "rollup" {
		return PlanResult{}, errors.New("rollup coverage is unavailable from the memory store")
	}
	selectedGroups, err := normalizePlanGroupsWithVocabulary(query.SelectedGroups, plan, vocabulary, budget)
	if err != nil {
		return PlanResult{}, err
	}
	selectedColumns, err := normalizePlanColumnsWithVocabulary(query.SelectedColumns, plan, vocabulary, budget)
	if err != nil {
		return PlanResult{}, err
	}
	selectedChart, err := normalizePlanChartGroupsWithVocabulary(query.SelectedChartGroups, plan, vocabulary, budget)
	if err != nil {
		return PlanResult{}, err
	}
	selectedMatrixRows, err := normalizePlanMatrixRowsWithVocabulary(query.SelectedMatrixRows, plan, vocabulary, budget)
	if err != nil {
		return PlanResult{}, err
	}
	prepared, err := flow.PrepareQueryFilterWithVocabulary(plan.Filter, vocabulary)
	if err != nil {
		return PlanResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	m.mu.Lock()
	source := m.explorerInterfaces
	m.mu.Unlock()
	names, err := explorerInterfaceNames(ctx, source, query.TenantID, plan, budget)
	if err != nil {
		return PlanResult{}, err
	}
	entries, err := m.explorerSnapshot(ctx, query.TenantID, plan)
	if err != nil {
		return PlanResult{}, err
	}
	distinct := planDistinctFields(plan)
	cost := &planCost{budget: budget}
	groups := map[string]*planAggregate{}
	rowGroups := map[string]*planAggregate{}
	total := newPlanAggregate(map[string]string{}, distinct)
	matched := make([]planInput, 0, len(entries))
	var oldestInput time.Time
	add := func(groups map[string]*planAggregate, key string, group map[string]string, row Row) error {
		if groups[key] == nil {
			if err := cost.charge(1, 512+len(key)); err != nil {
				return err
			}
			groups[key] = newPlanAggregate(group, distinct)
		}
		return groups[key].add(row, plan, distinct, cost)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return PlanResult{}, err
		}
		values := map[string]string{}
		value := func(field string) string {
			if found, ok := values[field]; ok {
				return found
			}
			result := explorerFieldValue(entry, field, plan, names, vocabulary, query.Tags, query.Roles)
			values[field] = result
			return result
		}
		if !prepared.Matches(value) {
			continue
		}
		oldestInput = earliestPlanInput(oldestInput, entry.row.TS)
		key, group := planTuple(value, plan.GroupBy)
		if err := add(groups, key, group, entry.row); err != nil {
			return PlanResult{}, err
		}
		if err := total.add(entry.row, plan, distinct, cost); err != nil {
			return PlanResult{}, err
		}
		input := planInput{row: entry.row, key: key}
		if plan.View == "matrix" {
			input.rowKey = key
			input.columnKey, input.column = planTuple(value, plan.MatrixWith)
			if err := add(rowGroups, key, groups[key].group, entry.row); err != nil {
				return PlanResult{}, err
			}
		}
		matched = append(matched, input)
	}
	keys, err := sortedPlanGroups(groups, plan)
	if err != nil {
		return PlanResult{}, err
	}
	if err := total.calculate(plan); err != nil {
		return PlanResult{}, err
	}
	coverageFields, err := memoryPlanCoverage(query, vocabulary)
	if err != nil {
		return PlanResult{}, err
	}
	result := PlanResult{Query: plan, Source: "raw", ResolutionSeconds: flow.MinPlanBucketSeconds, Coverage: &PlanSourceCoverage{Fields: coverageFields, ResolutionSeconds: flow.MinPlanBucketSeconds, CompleteInputs: true}, Rows: []PlanRow{}, Series: []PlanPoint{}, OtherSeries: []PlanPoint{}, TotalSeries: []PlanPoint{}, Matrix: []PlanMatrixCell{}, TotalGroups: len(keys), DetailLimited: len(keys) > plan.RowLimit, Totals: total.row(false).Metrics}
	if err := captureResultTagIdentity(&result, query, vocabulary); err != nil {
		return PlanResult{}, err
	}
	result.OldestInput = oldestInput
	selected := map[string]bool{}
	detailKeys := selectedPlanKeys(keys, plan.RowLimit, selectedGroups, groups)
	chartKeys := selectedPlanKeys(keys, plan.SeriesDepth, selectedChart, groups)

	if plan.View != "table" && plan.View != "matrix" {
		for _, key := range chartKeys {
			result.ChartRows = append(result.ChartRows, groups[key].row(false))
		}
	}
	for _, key := range detailKeys {
		selected[key] = true
		result.Rows = append(result.Rows, groups[key].row(false))
	}
	other := newPlanAggregate(map[string]string{}, distinct)
	chart := map[string]*planAggregate{}
	for _, key := range chartKeys {
		chart[key] = groups[key]
	}
	chartOther := newPlanAggregate(map[string]string{}, distinct)
	for _, input := range matched {
		if err := ctx.Err(); err != nil {
			return PlanResult{}, err
		}
		if !selected[input.key] {
			if err := other.add(input.row, plan, distinct, cost); err != nil {
				return PlanResult{}, err
			}
		}
		if chart[input.key] == nil {
			if err := chartOther.add(input.row, plan, distinct, cost); err != nil {
				return PlanResult{}, err
			}
		}
	}
	if other.total.flows.Sign() > 0 {
		if err := other.calculate(plan); err != nil {
			return PlanResult{}, err
		}
		row := other.row(true)
		result.Other = &row
		result.DetailLimited = true
	}

	if plan.View != "table" {
		result.TotalSeries = memoryPlanPoints(plan, total, false)
	}
	if plan.View != "table" && plan.View != "matrix" {
		for _, key := range chartKeys {
			result.Series = append(result.Series, memoryPlanPoints(plan, chart[key], false)...)
		}
		if chartOther.total.flows.Sign() > 0 {
			if err := chartOther.calculate(plan); err != nil {
				return PlanResult{}, err
			}
			row := chartOther.row(true)
			result.ChartOther = &row
			result.OtherSeries = memoryPlanPoints(plan, chartOther, true)
		}
	}
	if plan.View == "matrix" {
		work := memoryPlanMatrixWork{plan: plan, matched: matched, groups: groups, rowGroups: rowGroups, keys: keys, selectedRows: selectedMatrixRows, selectedColumns: selectedColumns, distinct: distinct, cost: cost, add: add}
		if err := work.render(ctx, &result); err != nil {
			return PlanResult{}, err
		}
	}

	sortPlanPoints(result.Series)
	sortPlanPoints(result.OtherSeries)
	if err := captureResultRoleIdentity(ctx, &result, query); err != nil {
		return PlanResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return PlanResult{}, err
	}
	return result, nil
}

// A nil selection ranks automatically; an explicit empty selection selects none.
func selectedPlanKeys(keys []string, limit int, selected [][]string, groups map[string]*planAggregate) []string {
	if selected == nil {
		return keys[:min(len(keys), limit)]
	}
	result := []string{}
	for _, tuple := range selected {
		encoded, _ := json.Marshal(tuple)
		key := string(encoded)
		if groups[key] != nil {
			result = append(result, key)
		}
	}
	return result
}

func memoryPlanPoints(plan flow.QueryPlan, group *planAggregate, isOther bool) []PlanPoint {
	points := make([]PlanPoint, 0, len(group.buckets))
	indices := make([]int64, 0, len(group.buckets))
	for index := range group.buckets {
		indices = append(indices, index)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	for _, index := range indices {
		bucket := group.buckets[index]
		start, duration := planBucketBounds(plan, index)
		point := PlanPoint{Group: group.group, Other: isOther, TS: start, DurationSeconds: new(big.Rat).SetFrac(big.NewInt(int64(duration)), big.NewInt(int64(time.Second))).FloatString(9), Metrics: map[string]string{}}
		for _, metric := range plan.Metrics {
			if metric.Role != "additional" {
				point.Metrics[planMetricKey(metric)] = planMetricString(bucket.value(metric.Measure, duration))
			}
		}
		points = append(points, point)
	}
	return points
}

type memoryPlanMatrixWork struct {
	plan                          flow.QueryPlan
	matched                       []planInput
	groups, rowGroups             map[string]*planAggregate
	keys                          []string
	selectedRows, selectedColumns [][]string
	distinct                      []string
	cost                          *planCost
	add                           func(map[string]*planAggregate, string, map[string]string, Row) error
}

func (w memoryPlanMatrixWork) render(ctx context.Context, result *PlanResult) error {
	plan, matched, groups, rowGroups, keys := w.plan, w.matched, w.groups, w.rowGroups, w.keys
	selectedMatrixRows, selectedColumns := w.selectedRows, w.selectedColumns
	distinct, cost, add := w.distinct, w.cost, w.add
	columnGroups := map[string]*planAggregate{}
	rows, columns := map[string]bool{}, map[string]bool{}
	rowKeys := keys[:min(len(keys), plan.MatrixDepth)]
	if selectedMatrixRows != nil {
		rowKeys = []string{}
		for _, tuple := range selectedMatrixRows {
			encoded, _ := json.Marshal(tuple)
			rowKeys = append(rowKeys, string(encoded))
		}
	}
	for _, key := range rowKeys {
		rows[key] = true
		if groups[key] != nil {
			result.MatrixRows = append(result.MatrixRows, groups[key].row(false))
		}
	}
	// Kentik's published matrix algorithm ranks columns inside the chosen
	// row population. A globally popular column outside those rows must not
	// displace a relevant column and leave the visible matrix empty.
	for _, input := range matched {
		if !rows[input.rowKey] {
			continue
		}
		if err := add(columnGroups, input.columnKey, input.column, input.row); err != nil {
			return err
		}
	}
	columnKeys, err := sortedPlanGroups(columnGroups, plan)
	if err != nil {
		return err
	}
	columnKeys = columnKeys[:min(len(columnKeys), plan.MatrixDepth)]
	if selectedColumns != nil {
		columnKeys = []string{}
		for _, tuple := range selectedColumns {
			encoded, _ := json.Marshal(tuple)
			columnKeys = append(columnKeys, string(encoded))
		}
	}
	for _, key := range columnKeys {
		columns[key] = true
		if columnGroups[key] != nil {
			result.MatrixColumns = append(result.MatrixColumns, columnGroups[key].row(false))
		}
	}
	cells := map[string]*planAggregate{}
	identities := map[string]PlanMatrixCell{}
	for _, input := range matched {
		if err := ctx.Err(); err != nil {
			return err
		}
		rowKey, columnKey := input.rowKey, input.columnKey
		rowOther, columnOther := !rows[rowKey], !columns[columnKey]
		if rowOther {
			rowKey = ""
		}
		if columnOther {
			columnKey = ""
		}
		identity, _ := json.Marshal([]any{rowKey, columnKey, rowOther, columnOther})
		key := string(identity)
		if cells[key] == nil {
			if err := cost.charge(1, 512+len(key)); err != nil {
				return err
			}
			cells[key] = newPlanAggregate(map[string]string{}, distinct)
			cell := PlanMatrixCell{Row: map[string]string{}, Column: map[string]string{}, RowOther: rowOther, ColumnOther: columnOther}
			if !rowOther {
				cell.Row = rowGroups[rowKey].group
			}
			if !columnOther {
				// A pinned column can occur only outside this period's
				// selected rows; retain its full tuple without inventing
				// conditioned column statistics.
				var tuple []string
				_ = json.Unmarshal([]byte(columnKey), &tuple)
				for i, name := range plan.MatrixWith {
					cell.Column[name] = tuple[i]
				}
			}
			identities[key] = cell
		}
		if err := cells[key].add(input.row, plan, distinct, cost); err != nil {
			return err
		}
	}
	cellKeys := make([]string, 0, len(cells))
	for key := range cells {
		cellKeys = append(cellKeys, key)
	}
	sort.Strings(cellKeys)
	for _, key := range cellKeys {
		if err := cells[key].calculate(plan); err != nil {
			return err
		}
		cell := identities[key]
		cell.Metrics = cells[key].row(false).Metrics
		result.Matrix = append(result.Matrix, cell)
	}

	return nil
}

var _ PlanStore = (*Memory)(nil)

// Precompute display keys once; comparison never repeatedly encodes a group
// map inside O(N log N) sorting work for a long time-series response.
func sortPlanPoints(points []PlanPoint) {
	type sortable struct {
		point PlanPoint
		key   string
	}
	ordered := make([]sortable, len(points))
	for i, point := range points {
		key, _ := json.Marshal(point.Group)
		ordered[i] = sortable{point: point, key: string(key)}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if !a.point.TS.Equal(b.point.TS) {
			return a.point.TS.Before(b.point.TS)
		}
		if a.point.Other != b.point.Other {
			return !a.point.Other
		}
		return a.key < b.key
	})
	for i, item := range ordered {
		points[i] = item.point
	}
}

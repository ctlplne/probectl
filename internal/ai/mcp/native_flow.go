// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

// NativeFlowBackend uses the same authorized registry services as REST, with
// deliberately declared projections. No store object or unchecked map crosses.
// The legacy query_flows event tool remains a separate capability.
type NativeFlowBackend interface {
	FlowPlan(context.Context, *auth.Principal, NativeFlowQuestionInput) (NativeFlowQuestionResult, error)
	FlowSchema(context.Context, *auth.Principal) (NativeFlowSchemaResult, error)
	FlowQuery(context.Context, *auth.Principal, flow.QueryPlan) (NativeFlowQueryResult, error)
	FlowCompare(context.Context, *auth.Principal, NativeFlowCompareInput) (NativeFlowComparisonResult, error)
	FlowPage(context.Context, *auth.Principal, string) (NativeFlowQueryResult, error)
	FlowComparisonPage(context.Context, *auth.Principal, string) (NativeFlowComparisonResult, error)
	FlowCSV(context.Context, *auth.Principal, NativeFlowCSVInput) (NativeFlowCSVResult, error)
	FlowFilters(context.Context, *auth.Principal, string, int) (NativeFlowFilterPage, error)
	FlowFilter(context.Context, *auth.Principal, string) (NativeFlowFilter, error)
	SaveFlowFilter(context.Context, *auth.Principal, NativeFlowFilterInput) (NativeFlowFilter, error)
	DeleteFlowFilter(context.Context, *auth.Principal, string, string) (NativeFlowMutationResult, error)
	FlowViews(context.Context, *auth.Principal, NativeFlowViewListInput) (NativeFlowViewPage, error)
	FlowView(context.Context, *auth.Principal, string) (NativeFlowView, error)
	SaveFlowView(context.Context, *auth.Principal, flow.SaveQueryView) (NativeFlowView, error)
	DeleteFlowView(context.Context, *auth.Principal, string, string) (NativeFlowMutationResult, error)
	FavoriteFlowView(context.Context, *auth.Principal, string, bool) (NativeFlowMutationResult, error)
	RunFlowView(context.Context, *auth.Principal, string) (NativeFlowExecution, error)
}

type NativeFlowQuestionInput struct {
	Question string `json:"question"`
}

// NativeFlowQuestionProposal is configuration, never telemetry or a tool call.
// Its declared fields prevent model/provider metadata crossing the MCP seam.
type NativeFlowQuestionProposal struct {
	Status            string                    `json:"status"`
	Plan              *flow.QueryPlan           `json:"plan,omitempty"`
	Comparison        *flow.QueryViewComparison `json:"comparison,omitempty"`
	Previous          *NativeFlowQuestionPeriod `json:"previous,omitempty"`
	Display           *flow.QueryViewDisplay    `json:"display,omitempty"`
	Guidance          string                    `json:"guidance,omitempty"`
	Assumptions       []string                  `json:"assumptions,omitempty"`
	NeedsConfirmation bool                      `json:"needs_confirmation,omitempty"`
}
type NativeFlowQuestionPeriod struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}
type NativeFlowQuestionResult struct {
	Proposal NativeFlowQuestionProposal `json:"proposal"`
}

// Entries are ordered by the validated query. Arbitrary storage-map keys never
// become new fields. Values are authoritative decimal/text strings, not floats.
type NativeFlowDimension struct {
	Field string `json:"field"`
	Value string `json:"value"`
}
type NativeFlowValue struct {
	Metric  string `json:"metric"`
	Value   string `json:"value"`
	Defined bool   `json:"defined"`
}
type NativeFlowRevision struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type NativeFlowRow struct {
	Group   []NativeFlowDimension `json:"group"`
	Other   bool                  `json:"other"`
	Metrics []NativeFlowValue     `json:"metrics"`
}
type NativeFlowPoint struct {
	Group           []NativeFlowDimension `json:"group"`
	Other           bool                  `json:"other"`
	TS              time.Time             `json:"ts"`
	DurationSeconds string                `json:"duration_seconds"`
	Metrics         []NativeFlowValue     `json:"metrics"`
}
type NativeFlowCell struct {
	Row         []NativeFlowDimension `json:"row"`
	Column      []NativeFlowDimension `json:"column"`
	RowOther    bool                  `json:"row_other"`
	ColumnOther bool                  `json:"column_other"`
	Metrics     []NativeFlowValue     `json:"metrics"`
}
type NativeFlowCoverage struct {
	Fields            []string `json:"fields"`
	ResolutionSeconds int      `json:"resolution_seconds"`
	CompleteInputs    bool     `json:"complete_inputs"`
}

// NativeFlowRoleSource is an explicit projection of current, authorized role
// provenance. Identity fields contain only validated server-created UUIDs;
// exporter addresses, reasons and untrusted evidence retain full redaction.
type NativeFlowRoleSource struct {
	TenantID    NativeRoleUUID     `json:"tenant_id"`
	ContextID   NativeRoleUUID     `json:"context_id"`
	RouterID    NativeRoleUUID     `json:"router_id"`
	InterfaceID NativeRoleUUID     `json:"interface_id"`
	Exporter    string             `json:"exporter"`
	Protocol    string             `json:"protocol"`
	Domain      uint32             `json:"obs_domain"`
	IfIndex     uint32             `json:"if_index"`
	Role        string             `json:"role"`
	Reason      string             `json:"reason"`
	Sources     []NativeRoleSource `json:"sources"`
	ValidUntil  time.Time          `json:"valid_until"`
}

type NativeFlowResult struct {
	RoleTenantID      NativeRoleUUID         `json:"role_tenant_id,omitempty"`
	RoleDigest        NativeRoleDigest       `json:"role_digest,omitempty"`
	RoleSources       []NativeFlowRoleSource `json:"role_sources,omitempty"`
	TagTenantID       string                 `json:"tag_tenant_id,omitempty"`
	TagRevision       string                 `json:"tag_revision,omitempty"`
	TagIDs            []NativeFlowTagID      `json:"tag_ids,omitempty"`
	Query             flow.QueryPlan         `json:"query"`
	Coverage          *NativeFlowCoverage    `json:"coverage,omitempty"`
	FilterVersions    []NativeFlowRevision   `json:"filter_versions"`
	Source            string                 `json:"source"`
	ResolutionSeconds int                    `json:"resolution_seconds"`
	TotalGroups       int                    `json:"total_groups"`
	DetailLimited     bool                   `json:"detail_limited"`
	Rows              []NativeFlowRow        `json:"rows"`
	ChartRows         []NativeFlowRow        `json:"chart_rows"`
	MatrixRows        []NativeFlowRow        `json:"matrix_rows"`
	MatrixColumns     []NativeFlowRow        `json:"matrix_columns"`
	Other             *NativeFlowRow         `json:"other,omitempty"`
	ChartOther        *NativeFlowRow         `json:"chart_other,omitempty"`
	Totals            []NativeFlowValue      `json:"totals"`
	Series            []NativeFlowPoint      `json:"series"`
	OtherSeries       []NativeFlowPoint      `json:"other_series"`
	TotalSeries       []NativeFlowPoint      `json:"total_series"`
	Matrix            []NativeFlowCell       `json:"matrix"`
}
type NativeFlowPaging struct {
	SnapshotID   string    `json:"snapshot_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	SelectedRows int       `json:"selected_rows"`
	Offset       int       `json:"offset"`
	PageSize     int       `json:"page_size"`
	More         bool      `json:"more"`
	NextCursor   string    `json:"next_cursor,omitempty"`
}
type NativeFlowQueryResult struct {
	Flow   NativeFlowResult  `json:"flow"`
	Paging *NativeFlowPaging `json:"paging,omitempty"`
}

// CSV pages retain complete cells, including quoted multiline labels. Every
// cell traverses the mandatory redactor before either MCP wire copy is sent.
type NativeFlowCSVInput struct {
	SnapshotID   string `json:"snapshot_id"`
	RecordOffset int    `json:"record_offset,omitempty"`
	PageSize     int    `json:"page_size,omitempty"`
}
type NativeFlowCSVResult struct {
	SnapshotID     string     `json:"snapshot_id"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Columns        []string   `json:"columns"`
	Records        [][]string `json:"records"`
	RecordOffset   int        `json:"record_offset"`
	NextRecord     *int       `json:"next_record,omitempty"`
	TotalRecords   int        `json:"total_records"`
	SelectedGroups int        `json:"selected_groups"`
	SourceBytes    int64      `json:"source_bytes"`
	SourceSHA256   string     `json:"source_sha256"`
}
type NativeFlowComparisonRow struct {
	Group         []NativeFlowDimension `json:"group"`
	Other         bool                  `json:"other"`
	Metric        string                `json:"metric"`
	Calculation   string                `json:"calculation"`
	Current       *string               `json:"current"`
	Previous      *string               `json:"previous"`
	Delta         *string               `json:"delta"`
	PercentChange *string               `json:"percent_change"`
	State         string                `json:"state"`
}
type NativeFlowComparisonResult struct {
	ContractVersion string                    `json:"contract_version"`
	Current         NativeFlowResult          `json:"current"`
	Previous        NativeFlowResult          `json:"previous"`
	Rows            []NativeFlowComparisonRow `json:"rows"`
	Membership      string                    `json:"membership"`
	Paging          *NativeFlowPaging         `json:"paging,omitempty"`
}
type NativeFlowExecution struct {
	Query      *NativeFlowQueryResult      `json:"query,omitempty"`
	Comparison *NativeFlowComparisonResult `json:"comparison,omitempty"`
}
type NativeFlowCompareInput struct {
	Plan         flow.QueryPlan `json:"plan"`
	PreviousFrom time.Time      `json:"previous_from"`
	PreviousTo   time.Time      `json:"previous_to"`
}
type NativeFlowFilterInput struct {
	ID          string                `json:"id,omitempty"`
	Version     string                `json:"version,omitempty"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Expression  flow.QueryFilterGroup `json:"expression"`
}
type NativeFlowFilter struct {
	ID          string                `json:"id"`
	Version     string                `json:"version"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Expression  flow.QueryFilterGroup `json:"expression"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
}
type NativeFlowFilterPage struct {
	Items []NativeFlowFilter `json:"items"`
	Next  string             `json:"next,omitempty"`
}
type NativeFlowViewListInput struct {
	After      string `json:"after"`
	Limit      int    `json:"limit"`
	Search     string `json:"search"`
	Label      string `json:"label"`
	Visibility string `json:"visibility"`
	Owner      string `json:"owner"`
	Sort       string `json:"sort"`
	Tab        string `json:"tab"`
}
type NativeFlowView struct {
	ID           string                   `json:"id"`
	OwnerID      string                   `json:"owner_id"`
	Version      string                   `json:"version"`
	Definition   NativeFlowViewDefinition `json:"definition"`
	CreatedAt    time.Time                `json:"created_at"`
	UpdatedAt    time.Time                `json:"updated_at"`
	Favorite     bool                     `json:"favorite"`
	LastOpenedAt *time.Time               `json:"last_opened_at,omitempty"`
}

// NativeFlowViewDefinition keeps stored tag identity in declared, bounded
// fields instead of exposing a caller-shaped map through the MCP result.
type NativeFlowViewDefinition struct {
	Name               string                    `json:"name"`
	Description        string                    `json:"description"`
	Labels             []string                  `json:"labels"`
	Visibility         string                    `json:"visibility"`
	Plan               flow.QueryPlan            `json:"plan"`
	Time               flow.QueryViewTime        `json:"time"`
	Comparison         *flow.QueryViewComparison `json:"comparison,omitempty"`
	AutoRefreshSeconds int                       `json:"auto_refresh_seconds"`
	Display            *flow.QueryViewDisplay    `json:"display,omitempty"`
	TagIDs             []NativeFlowTagID         `json:"tag_ids,omitempty"`
}
type NativeFlowTagID struct {
	Field string `json:"field"`
	ID    string `json:"id"`
}

type NativeFlowViewPage struct {
	Items []NativeFlowView `json:"items"`
	Next  string           `json:"next,omitempty"`
}
type NativeFlowMutationResult struct {
	ID      string `json:"id"`
	Updated bool   `json:"updated"`
}
type NativeFlowField struct {
	Name         string               `json:"name"`
	Type         flow.QueryFieldType  `json:"type"`
	Operators    []flow.QueryOperator `json:"operators"`
	LegacyHourly bool                 `json:"legacy_hourly_available"`
	Raw          bool                 `json:"raw_available"`
	Rollup       bool                 `json:"rollup_available"`
	Permission   string               `json:"required_permission,omitempty"`
}
type NativeFlowCalculation struct {
	Name string `json:"name"`
	Unit string `json:"unit"`
}
type NativeFlowMetric struct {
	Name          string                  `json:"name"`
	Unit          string                  `json:"unit"`
	DistinctField string                  `json:"distinct_field,omitempty"`
	Calculations  []NativeFlowCalculation `json:"calculations"`
}
type NativeFlowLimits struct {
	MaxGroups             int     `json:"max_groups"`
	MaxMatrixDimensions   int     `json:"max_matrix_dimensions"`
	MaxMatrixDepth        int     `json:"max_matrix_depth"`
	MaxChartSeries        int     `json:"max_chart_series"`
	MaxChartRows          int     `json:"max_chart_rows"`
	MaxTableRows          int     `json:"max_table_rows"`
	MaxPageRows           int     `json:"max_page_rows"`
	MinBucketSeconds      int     `json:"min_bucket_seconds"`
	MaxBucketSeconds      int     `json:"max_bucket_seconds"`
	MaxGroupEntries       int     `json:"max_group_entries"`
	MaxExpandedConditions int     `json:"max_expanded_conditions"`
	MaxFilterDepth        int     `json:"max_filter_depth"`
	MaxRegexBytes         int     `json:"max_regex_bytes"`
	MaxValuesPerPredicate int     `json:"max_values_per_predicate"`
	MaxValueBytes         int     `json:"max_value_bytes"`
	MaxTagValueCharacters int     `json:"max_tag_value_characters"`
	MaxTagValueBytes      int     `json:"max_tag_value_bytes"`
	GrammarBytes          int     `json:"grammar_bytes"`
	ExecutionSeconds      float64 `json:"execution_seconds"`
	ReadBytes             int64   `json:"read_bytes"`
	ReadRows              int     `json:"read_rows"`
	ResponseBytes         int64   `json:"response_bytes"`
	MemoryBytes           int64   `json:"memory_bytes"`
	IntermediateGroups    int     `json:"intermediate_groups"`
	InterfaceItems        int     `json:"interface_items"`
	Threads               int     `json:"threads"`
}
type NativeFlowDefaults struct {
	IPv4PrefixLength int `json:"ipv4_prefix_length"`
	IPv6PrefixLength int `json:"ipv6_prefix_length"`
	BucketSeconds    int `json:"bucket_seconds"`
	SeriesDepth      int `json:"series_depth"`
	RowLimit         int `json:"row_limit"`
}
type NativeFlowStatistics struct {
	Percentile          string `json:"percentile"`
	RateAverage         string `json:"rate_average"`
	DecimalPlaces       int    `json:"decimal_places"`
	DecimalRounding     string `json:"decimal_rounding"`
	DistinctTotal       string `json:"distinct_total"`
	DistinctBucketTotal string `json:"distinct_bucket_total"`
}
type NativeFlowSchemaResult struct {
	ContractVersion string                 `json:"contract_version"`
	Fields          []NativeFlowField      `json:"fields"`
	Metrics         []NativeFlowMetric     `json:"metrics"`
	Limits          NativeFlowLimits       `json:"limits"`
	RenderCost      NativeFlowRenderBudget `json:"render_cost"`
	Defaults        NativeFlowDefaults     `json:"defaults"`
	Statistics      NativeFlowStatistics   `json:"statistics"`
	TimeRange       string                 `json:"time_range"`
}

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/** Values and available choices come from the authenticated Explorer schema. */
export interface FlowQueryPredicate {
  field: string
  op: string
  values: string[]
}

export interface FlowQueryFilterGroup {
  match?: 'all' | 'any' | 'and' | 'or'
  mode?: 'include' | 'exclude'
  conditions?: FlowQueryPredicate[]
  groups?: FlowQueryFilterGroup[]
  saved?: { id: string; mode?: 'include' | 'exclude' }[]
}

export type FlowView = 'table' | 'bar' | 'line' | 'timeline' | 'matrix'
export type FlowCalculation = 'avg' | 'p95' | 'p99' | 'max' | 'total' | 'bucket_total'

export interface FlowQueryMetric {
  measure: string
  calculation: FlowCalculation
  role: 'primary' | 'secondary' | 'additional'
}

export interface FlowQueryPlan {
  from?: string
  to?: string
  group_by?: string[]
  matrix_with?: string[]
  filter?: FlowQueryFilterGroup
  metrics?: FlowQueryMetric[]
  view?: FlowView
  dataseries?: 'auto' | 'raw' | 'rollup'
  bucket_seconds?: number
  series_depth?: number
  matrix_depth?: number
  row_limit?: number
  page_size?: number
  cursor?: string
  ipv4_prefix_length?: number
  ipv6_prefix_length?: number
}

export interface FlowQueryField {
  name: string
  type: 'text' | 'address' | 'prefix' | 'unsigned' | 'timestamp' | 'flags'
  operators: string[]
  raw_available: boolean
  rollup_available: boolean
  legacy_hourly_available: boolean
  required_permission?: string
}

export interface FlowMetricDefinition {
  name: string
  unit: string
  distinct_field?: string
  calculations: FlowCalculation[]
  calculation_units: Partial<Record<FlowCalculation, string>>
}

export interface FlowExplorerSchema {
  contract_version: 'flow-explorer/v2'
  fields: FlowQueryField[]
  metrics: FlowMetricDefinition[]
  limits: Record<string, number>
  render_cost: {
    mcp_source_bytes: number
    mcp_wire_bytes: number
    mcp_result_nodes: number
    mcp_csv_page_bytes: number
  }
  defaults: Record<string, number>
  time_range: string
  statistics: {
    percentile: string
    rate_average: string
    decimal_places: number
    decimal_rounding: string
    distinct_total: string
    distinct_bucket_total: string
  }
}

/** Exact decimal strings are authoritative, including counters larger than 2^53. */
export interface FlowResultRow {
  group: Record<string, string>
  other: boolean
  metrics: Record<string, string>
}

export interface FlowResultPoint extends FlowResultRow {
  ts: string
  duration_seconds: string
}

export interface FlowMatrixCell {
  row: Record<string, string>
  column: Record<string, string>
  row_other: boolean
  column_other: boolean
  metrics: Record<string, string>
}

export interface FlowExplorerResult {
  query: FlowQueryPlan
  saved_filter_versions?: Record<string, number>
  source: 'raw' | 'rollup'
  resolution_seconds: number
  total_groups: number
  detail_limited: boolean
  rows: FlowResultRow[]
  chart_rows?: FlowResultRow[]
  matrix_rows?: FlowResultRow[]
  chart_other?: FlowResultRow
  other?: FlowResultRow
  totals: Record<string, string>
  series: FlowResultPoint[]
  other_series: FlowResultPoint[]
  /** Source-authoritative all-input bucket values; never a sum of group cardinalities. */
  total_series?: FlowResultPoint[]
  matrix: FlowMatrixCell[]
  matrix_columns?: FlowResultRow[]
  coverage?: {
    fields: string[]
    resolution_seconds: 60 | 3600
    complete_inputs: boolean
  }
}

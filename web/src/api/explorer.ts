// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { FlowExplorerResult, FlowExplorerSchema, FlowQueryPlan } from './flowExplorer'
import type { FlowQueryViewDefinition } from './flowViews'

export interface FlowQuestionProposal {
  status: 'ready' | 'clarify' | 'refused'
  plan?: FlowQueryPlan
  comparison?: FlowQueryViewDefinition['comparison']
  previous?: { from: string; to: string }
  display?: FlowQueryViewDefinition['display']
  guidance?: string
  assumptions?: string[]
  needs_confirmation?: boolean
}

export function useExplorerFlowPlan() {
  return useMutation({
    mutationFn: (question: string) =>
      apiFetch<{ proposal: FlowQuestionProposal }>('/explorer/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: 'flow', question, plan_only: true }),
      }),
  })
}

export type ExplorerSource =
  | 'flow'
  | 'changes'
  | 'path'
  | 'topology'
  | 'endpoints'
  | 'tls'
  | 'cost'
  | 'slo'
export type ExplorerVisualization = 'table' | 'bar' | 'line' | 'timeline' | 'matrix' | 'topology'

export interface ExplorerQuery {
  flow?: FlowQueryPlan
  template?: string
  question: string
  source: ExplorerSource
  from: string
  to: string
  dimensions: string[]
  filters: Record<string, string>
  groupings: string[]
  measures: string[]
  visualization: ExplorerVisualization
  limit: number
}

export interface FlowPaging {
  snapshot_id: string
  expires_at: string
  selected_rows: number
  offset: number
  page_size: number
  more: boolean
  next_cursor?: string
}

export interface ExplorerTemplate {
  id: string
  question: string
  source: ExplorerSource
  dimensions: string[]
  groupings: string[]
  measures: string[]
  visualization: ExplorerVisualization
  evidence_path: string
}

export interface ExplorerSchema {
  flow?: FlowExplorerSchema
  templates: ExplorerTemplate[]
  visualizations: ExplorerVisualization[]
  comparison_sources?: ExplorerSource[]
  max_rows: number
}

export interface ExplorerColumn {
  key: string
  label: string
  numeric?: boolean
}

export interface ExplorerExecutionReceipt {
  contract_version: 'explorer-execution/v1' | 'flow-explorer-execution/v2'
  recipe: string
  source: ExplorerSource
  tenant_scoped: true
  bounds: {
    from: string
    to: string
    row_limit: number
  }
  projection: {
    dimensions: string[]
    groupings: string[]
    measures: string[]
  }
  filter_keys: string[]
  source_rows: number
  returned_rows: number
  truncated: boolean
  truncation_reason: 'none' | 'row_limit'
  timings: {
    source_ms: number
    shaping_ms: number
    total_ms: number
  }
}

export interface ExplorerComparisonExecutionReceipt {
  contract_version: 'explorer-comparison-execution/v1' | 'flow-explorer-comparison-execution/v2'
  tenant_scoped: true
  current: ExplorerExecutionReceipt
  previous: ExplorerExecutionReceipt
  alignment: {
    row_limit: number
    returned_rows: number
    truncated: boolean
    truncation_reason: 'none' | 'comparison_row_limit'
    elapsed_ms: number
  }
  total_ms: number
}

export interface ExplorerResult {
  flow_paging?: FlowPaging
  flow?: FlowExplorerResult
  query: ExplorerQuery
  preview: string
  columns: ExplorerColumn[]
  rows: Record<string, unknown>[]
  suggestions: Record<string, string[]>
  evidence_path: string
  truncated: boolean
  execution: ExplorerExecutionReceipt
}

export interface ExplorerComparisonRequest {
  query: ExplorerQuery
  previous_from: string
  previous_to: string
}

export type ExplorerDeltaState =
  | 'comparable'
  | 'zero_baseline'
  | 'missing_current'
  | 'missing_previous'

export interface ExplorerComparisonRow {
  group: Record<string, string>
  measure: string
  aggregation:
    | 'sum'
    | 'mean'
    | 'exact_distinct'
    | 'avg'
    | 'p95'
    | 'p99'
    | 'max'
    | 'total'
    | 'bucket_total'
  other?: boolean
  current_value_str?: string
  previous_value_str?: string
  delta_str?: string
  percent_change_str?: string
  current_value: number | null
  previous_value: number | null
  delta: number | null
  percent_change: number | null
  delta_state: ExplorerDeltaState
}

export interface ExplorerComparisonResult {
  flow_paging?: FlowPaging
  flow?: {
    current: FlowExplorerResult
    previous: FlowExplorerResult
    membership: 'shared_top_groups_ranked_by_larger_period_value'
  }
  contract_version: 'explorer-comparison/v1' | 'flow-explorer-comparison/v2'
  current: ExplorerQuery
  previous: ExplorerQuery
  current_preview: string
  previous_preview: string
  groupings: string[]
  rows: ExplorerComparisonRow[]
  suggestions: Record<string, string[]>
  evidence_path: string
  state: 'comparable' | 'current_only' | 'previous_only' | 'empty'
  current_truncated: boolean
  previous_truncated: boolean
  rows_truncated: boolean
  execution: ExplorerComparisonExecutionReceipt
}

export function useExplorerSchema(identity?: string) {
  return useQuery({
    queryKey: identity ? ['explorer', 'schema', identity] : ['explorer', 'schema'],
    queryFn: () => apiFetch<ExplorerSchema>('/explorer/schema'),
  })
}

export function useExplorerQuery() {
  return useMutation({
    mutationFn: (query: ExplorerQuery) =>
      apiFetch<ExplorerResult>('/explorer/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(query),
      }),
  })
}

export function useExplorerFlowQuery() {
  return useMutation({
    mutationFn: (flow: FlowQueryPlan) =>
      apiFetch<ExplorerResult>('/explorer/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: 'flow', flow }),
      }),
  })
}

export function useExplorerFlowComparison() {
  return useMutation({
    mutationFn: ({
      flow,
      ...previous
    }: {
      flow: FlowQueryPlan
      previous_from: string
      previous_to: string
    }) =>
      apiFetch<ExplorerComparisonResult>('/explorer/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: { source: 'flow', flow }, ...previous }),
      }),
  })
}

export function useExplorerFlowPage() {
  return useMutation({
    mutationFn: (cursor: string) =>
      apiFetch<ExplorerResult>('/explorer/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: 'flow', flow: { cursor } }),
      }),
  })
}

export function useExplorerComparison() {
  return useMutation({
    mutationFn: (request: ExplorerComparisonRequest) =>
      apiFetch<ExplorerComparisonResult>('/explorer/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }),
  })
}

export function useExplorerFlowComparisonPage() {
  return useMutation({
    mutationFn: (cursor: string) =>
      apiFetch<ExplorerComparisonResult>('/explorer/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: { source: 'flow', flow: { cursor } } }),
      }),
  })
}

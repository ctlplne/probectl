// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

export type ExplorerSource =
  | 'flow'
  | 'changes'
  | 'path'
  | 'topology'
  | 'endpoints'
  | 'tls'
  | 'cost'
  | 'slo'
export type ExplorerVisualization = 'table' | 'bar' | 'line' | 'timeline' | 'topology'

export interface ExplorerQuery {
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
  contract_version: 'explorer-execution/v1'
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
  contract_version: 'explorer-comparison-execution/v1'
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
  aggregation: 'sum' | 'mean'
  current_value: number | null
  previous_value: number | null
  delta: number | null
  percent_change: number | null
  delta_state: ExplorerDeltaState
}

export interface ExplorerComparisonResult {
  contract_version: 'explorer-comparison/v1'
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

export function useExplorerSchema() {
  return useQuery({
    queryKey: ['explorer', 'schema'],
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

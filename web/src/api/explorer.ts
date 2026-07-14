// SPDX-License-Identifier: MPL-2.0

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
  max_rows: number
}

export interface ExplorerColumn {
  key: string
  label: string
  numeric?: boolean
}
export interface ExplorerResult {
  query: ExplorerQuery
  preview: string
  columns: ExplorerColumn[]
  rows: Record<string, unknown>[]
  suggestions: Record<string, string[]>
  evidence_path: string
  truncated: boolean
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

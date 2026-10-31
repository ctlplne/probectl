// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ExplorerComparisonResult, ExplorerResult } from './explorer'
import type { FlowQueryPlan } from './flowExplorer'

export interface FlowQueryDisplay {
  time_style?: 'line' | 'stacked_area' | 'stacked_columns' | 'percent_area' | 'horizon'
  percent_basis?: 'returned' | 'visible'
  horizon_scale?: 'shared' | 'lane'
  total_overlay?: boolean
  log_metrics?: string[]
  sync_axes?: boolean
  one_chart_per_series?: boolean
  charts_per_row?: number
  chart_height?: 'short' | 'medium' | 'tall'
}

export interface FlowQueryViewDefinition {
  name: string
  description?: string
  labels?: string[]
  visibility?: 'private' | 'tenant'
  plan?: FlowQueryPlan
  time?: { mode: 'absolute' | 'lookback'; lookback_seconds?: number }
  comparison?: { mode: 'absolute' | 'preceding'; from?: string; to?: string }
  auto_refresh_seconds?: 0 | 60 | 90 | 120
  display?: FlowQueryDisplay
}

export interface SavedFlowQueryView {
  id: string
  owner_id: string
  version: string
  definition: FlowQueryViewDefinition
  created_at: string
  updated_at: string
  favorite: boolean
  last_opened_at?: string
}

export interface FlowQueryViewPage {
  items: SavedFlowQueryView[]
  next?: string
}

export interface FlowQueryViewList {
  after?: string
  limit?: number
  search?: string
  label?: string
  visibility?: 'private' | 'tenant'
  owner?: string
  sort?: 'name' | 'created_at' | 'updated_at'
  tab?: 'all' | 'favorites' | 'recents'
}

export function useFlowQueryViews(filters: FlowQueryViewList = {}, identity: string) {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== '') params.set(key, String(value))
  }
  return useQuery({
    queryKey: ['explorer', 'flow-views', identity, 'list', filters],
    queryFn: () => apiFetch<FlowQueryViewPage>(`/explorer/flow-views?${params}`),
  })
}

export function useFlowQueryView(id: string | undefined, identity: string) {
  return useQuery({
    queryKey: ['explorer', 'flow-views', identity, 'item', id],
    queryFn: () => apiFetch<SavedFlowQueryView>(`/explorer/flow-views/${encodeURIComponent(id!)}`),
    enabled: Boolean(id),
  })
}

export function useSaveFlowQueryView() {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      ...body
    }: {
      id?: string
      version?: string
      definition: FlowQueryViewDefinition
    }) => {
      if (id)
        return apiFetch<SavedFlowQueryView>(`/explorer/flow-views/${encodeURIComponent(id)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })
      return apiFetch<SavedFlowQueryView>('/explorer/flow-views', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
    },
    onSuccess: () => cache.invalidateQueries({ queryKey: ['explorer', 'flow-views'] }),
  })
}

export function useDeleteFlowQueryView() {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: ({ id, version }: { id: string; version: string }) =>
      apiFetch<void>(
        `/explorer/flow-views/${encodeURIComponent(id)}?version=${encodeURIComponent(version)}`,
        { method: 'DELETE' },
      ),
    onSuccess: () => cache.invalidateQueries({ queryKey: ['explorer', 'flow-views'] }),
  })
}

export function useFlowQueryViewFavorite() {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: ({ id, favorite }: { id: string; favorite: boolean }) =>
      apiFetch<void>(`/explorer/flow-views/${encodeURIComponent(id)}/preferences`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ favorite }),
      }),
    onSuccess: () => cache.invalidateQueries({ queryKey: ['explorer', 'flow-views'] }),
  })
}

export function useRunFlowQueryView() {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<ExplorerResult | ExplorerComparisonResult>(
        `/explorer/flow-views/${encodeURIComponent(id)}/query`,
        { method: 'POST' },
      ),
    onSuccess: () => cache.invalidateQueries({ queryKey: ['explorer', 'flow-views'] }),
  })
}

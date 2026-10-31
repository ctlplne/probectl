// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { FlowQueryFilterGroup } from './flowExplorer'

export interface SavedFlowFilter {
  id: string
  name: string
  description: string
  expression: FlowQueryFilterGroup
  /** Use the exact text token, never the compatibility numeric version. */
  version_text: string
  updated_by: string
  created_at: string
  updated_at: string
}

export interface FlowFilterPage {
  items: SavedFlowFilter[]
  next?: string
}

export function useFlowFilters(after: string, identity: string) {
  return useQuery({
    queryKey: ['explorer', 'flow-filters', identity, after],
    queryFn: () =>
      apiFetch<FlowFilterPage>(
        `/explorer/flow-filters?limit=100&after=${encodeURIComponent(after)}`,
      ),
  })
}

export function useSaveFlowFilter() {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      ...body
    }: {
      id?: string
      version_text?: string
      name: string
      description: string
      expression: FlowQueryFilterGroup
    }) => {
      if (id)
        return apiFetch<SavedFlowFilter>(`/explorer/flow-filters/${encodeURIComponent(id)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })
      return apiFetch<SavedFlowFilter>('/explorer/flow-filters', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
    },
    onSuccess: () => cache.invalidateQueries({ queryKey: ['explorer', 'flow-filters'] }),
  })
}

export function useDeleteFlowFilter() {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: ({ id, version_text }: { id: string; version_text: string }) =>
      apiFetch<void>(
        `/explorer/flow-filters/${encodeURIComponent(id)}?version=${encodeURIComponent(version_text)}`,
        { method: 'DELETE' },
      ),
    onSuccess: () => cache.invalidateQueries({ queryKey: ['explorer', 'flow-filters'] }),
  })
}

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { TagDefinition, TagDefinitionList } from './sdk.gen'

export type { TagDefinition } from './sdk.gen'

const tagKey = (tenantID: string) => ['tenant-tags', tenantID] as const

export function useTagDefinitions(tenantID: string) {
  return useQuery({
    queryKey: tagKey(tenantID),
    enabled: Boolean(tenantID),
    queryFn: () => apiFetch<TagDefinitionList>('/tags'),
  })
}

export function useCreateTagDefinition(tenantID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (key: string) =>
      apiFetch<TagDefinition>('/tags', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: tagKey(tenantID) }),
  })
}

export function useRenameTagDefinition(tenantID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, key }: { id: string; key: string }) =>
      apiFetch<TagDefinition>(`/tags/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: tagKey(tenantID) }),
  })
}

export function useDeleteTagDefinition(tenantID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/tags/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => void client.invalidateQueries({ queryKey: tagKey(tenantID) }),
  })
}

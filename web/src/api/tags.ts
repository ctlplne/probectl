// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { TagDefinition, TagDefinitionList, TagRule, TagRuleInput, TagRulePage } from './sdk.gen'

export type { TagDefinition, TagRule, TagRuleInput } from './sdk.gen'

const tagKey = (tenantID: string) => ['tenant-tags', tenantID] as const
const ruleKey = (tenantID: string, contextID: string) => ['tenant-tag-rules', tenantID, contextID] as const

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
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: tagKey(tenantID) })
      // Deleting a key cascades to its context rules and manual assignments.
      void client.invalidateQueries({ queryKey: ['tenant-tag-rules', tenantID] })
    },
  })
}

export function useTagRules(tenantID: string, contextID: string) {
  return useInfiniteQuery({
    queryKey: ruleKey(tenantID, contextID),
    enabled: Boolean(tenantID && contextID),
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const query = new URLSearchParams({ limit: '100' })
      if (pageParam) query.set('cursor', pageParam)
      return apiFetch<TagRulePage>(`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules?${query}`)
    },
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
}

export function useCreateTagRule(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: TagRuleInput) =>
      apiFetch<TagRule>(`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ruleKey(tenantID, contextID) }),
  })
}

export function useUpdateTagRule(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: TagRuleInput }) =>
      apiFetch<TagRule>(`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules/${encodeURIComponent(id)}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ruleKey(tenantID, contextID) }),
  })
}

export function useDeleteTagRule(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ruleKey(tenantID, contextID) }),
  })
}

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type {
  ManualTagAssignmentInput,
  NetBoxTagPreview,
  NetBoxTagPreviewInput,
  NetBoxTagApplyInput,
  TagAssignment,
  TagAssignmentPage,
  TagDefinition,
  TagDefinitionList,
  TagRule,
  TagRuleInput,
  TagRulePage,
} from './sdk.gen'

export type {
  ManualTagAssignmentInput,
  NetBoxTagPreview,
  NetBoxTagPreviewInput,
  NetBoxTagApplyInput,
  TagAssignment,
  TagDefinition,
  TagRule,
  TagRuleInput,
} from './sdk.gen'

const tagKey = (tenantID: string) => ['tenant-tags', tenantID] as const
export const MAX_TAG_VALUE_CHARACTERS = 24_000
// Native maxlength counts UTF-16 units, while the API counts Unicode points.
export const MAX_TAG_VALUE_INPUT_UNITS = MAX_TAG_VALUE_CHARACTERS * 2

export function tagValueTooLong(value: string): boolean {
  return Array.from(value).length > MAX_TAG_VALUE_CHARACTERS
}
const ruleKey = (tenantID: string, contextID: string) =>
  ['tenant-tag-rules', tenantID, contextID] as const
const assignmentKey = (tenantID: string, contextID: string) =>
  ['tenant-tag-assignments', tenantID, contextID] as const

/** A fresh source read, held by the current form only. Never share a completed
 * preview through the tenant metadata query cache or use it as an assignment. */
export function useNetBoxTagPreview(tenantID: string, contextID: string) {
  return useMutation({
    mutationKey: ['tenant-netbox-tag-preview', tenantID, contextID],
    mutationFn: (input: NetBoxTagPreviewInput) =>
      apiFetch<NetBoxTagPreview>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-imports/netbox/preview`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Probectl-Tenant': tenantID },
          body: JSON.stringify(input),
        },
      ),
  })
}

export function useApplyNetBoxTag(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationKey: ['tenant-netbox-tag-apply', tenantID, contextID],
    mutationFn: (input: NetBoxTagApplyInput) =>
      apiFetch<TagAssignment>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-imports/netbox/apply`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Probectl-Tenant': tenantID },
          body: JSON.stringify(input),
        },
      ),
    onSuccess: () =>
      void client.invalidateQueries({ queryKey: assignmentKey(tenantID, contextID) }),
  })
}

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
      void client.invalidateQueries({ queryKey: ['tenant-tag-assignments', tenantID] })
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
      return apiFetch<TagRulePage>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-rules?${query}`,
      )
    },
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
}

export function useCreateTagRule(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: TagRuleInput) =>
      apiFetch<TagRule>(`/entity-contexts/${encodeURIComponent(contextID)}/tag-rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ruleKey(tenantID, contextID) }),
  })
}

export function useUpdateTagRule(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: TagRuleInput }) =>
      apiFetch<TagRule>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-rules/${encodeURIComponent(id)}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        },
      ),
    onSuccess: () => void client.invalidateQueries({ queryKey: ruleKey(tenantID, contextID) }),
  })
}

export function useDeleteTagRule(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-rules/${encodeURIComponent(id)}`,
        { method: 'DELETE' },
      ),
    onSuccess: () => void client.invalidateQueries({ queryKey: ruleKey(tenantID, contextID) }),
  })
}

export function useTagAssignments(tenantID: string, contextID: string) {
  return useInfiniteQuery({
    queryKey: assignmentKey(tenantID, contextID),
    enabled: Boolean(tenantID && contextID),
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const query = new URLSearchParams({ limit: '100' })
      if (pageParam) query.set('cursor', pageParam)
      return apiFetch<TagAssignmentPage>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments?${query}`,
      )
    },
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
}

export function useCreateTagAssignment(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: ManualTagAssignmentInput) =>
      apiFetch<TagAssignment>(`/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () =>
      void client.invalidateQueries({ queryKey: assignmentKey(tenantID, contextID) }),
  })
}

export function useUpdateTagAssignment(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: ManualTagAssignmentInput }) =>
      apiFetch<TagAssignment>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments/${encodeURIComponent(id)}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        },
      ),
    onSuccess: () =>
      void client.invalidateQueries({ queryKey: assignmentKey(tenantID, contextID) }),
  })
}

export function useDeleteTagAssignment(tenantID: string, contextID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(
        `/entity-contexts/${encodeURIComponent(contextID)}/tag-assignments/${encodeURIComponent(id)}`,
        { method: 'DELETE' },
      ),
    onSuccess: () =>
      void client.invalidateQueries({ queryKey: assignmentKey(tenantID, contextID) }),
  })
}

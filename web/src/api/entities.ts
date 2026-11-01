// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type {
  CreateCanonicalEntityInput,
  CreateEntityContextInput,
  EntityContext,
  EntityContextPage,
  EntityPathContextBinding,
  EntityEvidencePage,
  EntityLinkPage,
  EntityPage,
  EntityRecord,
  EntityResolution,
  EntitySourceAssignment,
} from './sdk.gen'

export type {
  EntityContext,
  EntityContextPage,
  EntityEvidencePage,
  EntityEvidenceRecord,
  EntityLinkPage,
  EntityLinkRecord,
  EntityPage,
  EntityRecord,
  EntityResolution,
  EntitySourceAssignment,
} from './sdk.gen'

const PAGE_SIZE = 100

function queryPath(path: string, values: Record<string, string>): string {
  const params = new URLSearchParams(values)
  return `${path}?${params.toString()}`
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

export function useEntityContexts(tenantID: string, enabled = true) {
  return useInfiniteQuery({
    queryKey: ['entity-contexts', tenantID],
    enabled,
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      apiFetch<EntityContextPage>(
        queryPath('/entity-contexts', {
          limit: String(PAGE_SIZE),
          ...(pageParam ? { cursor: pageParam } : {}),
        }),
      ),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
}

export function useAssignPathTestContext(tenantID: string, testID: string | undefined) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (contextID: string) =>
      apiFetch<EntityPathContextBinding>(
        `/tests/${encodeURIComponent(testID ?? '')}/entity-context`,
        jsonInit('PUT', { context_id: contextID }),
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['path-entities', tenantID, testID] })
    },
  })
}

export function useCanonicalEntities(tenantID: string, contextID: string) {
  return useInfiniteQuery({
    queryKey: ['canonical-entities', tenantID, contextID],
    enabled: Boolean(contextID),
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      apiFetch<EntityPage>(
        queryPath('/entities', {
          context_id: contextID,
          limit: String(PAGE_SIZE),
          ...(pageParam ? { cursor: pageParam } : {}),
        }),
      ),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
}

export function useCanonicalEntity(tenantID: string, contextID: string, id: string) {
  return useQuery({
    queryKey: ['canonical-entity', tenantID, contextID, id],
    enabled: Boolean(contextID && id),
    queryFn: () =>
      apiFetch<EntityRecord>(
        queryPath(`/entities/${encodeURIComponent(id)}`, {
          context_id: contextID,
        }),
      ),
  })
}

export function useCanonicalEvidence(tenantID: string, contextID: string, id: string) {
  return useInfiniteQuery({
    queryKey: ['canonical-evidence', tenantID, contextID, id],
    enabled: Boolean(contextID && id),
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      apiFetch<EntityEvidencePage>(
        queryPath(`/entities/${encodeURIComponent(id)}/evidence`, {
          context_id: contextID,
          limit: String(PAGE_SIZE),
          ...(pageParam ? { cursor: pageParam } : {}),
        }),
      ),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
}

export function useCanonicalLinks(tenantID: string, contextID: string, id: string) {
  return useInfiniteQuery({
    queryKey: ['canonical-links', tenantID, contextID, id],
    enabled: Boolean(contextID && id),
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      apiFetch<EntityLinkPage>(
        queryPath(`/entities/${encodeURIComponent(id)}/links`, {
          context_id: contextID,
          limit: String(PAGE_SIZE),
          ...(pageParam ? { cursor: pageParam } : {}),
        }),
      ),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
}

export function useEntityResolution(
  tenantID: string,
  contextID: string,
  kind: string,
  value: string,
) {
  return useQuery({
    queryKey: ['entity-resolution', tenantID, contextID, kind, value],
    enabled: Boolean(contextID && kind && value),
    queryFn: () =>
      apiFetch<EntityResolution>(
        queryPath('/entities/resolve', {
          context_id: contextID,
          kind,
          value,
        }),
      ),
  })
}

export function useCreateEntityContext(tenantID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateEntityContextInput) =>
      apiFetch<EntityContext>('/entity-contexts', jsonInit('POST', input)),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['entity-contexts', tenantID] }),
  })
}

export function useCreateCanonicalEntity(tenantID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateCanonicalEntityInput) =>
      apiFetch<EntityRecord>('/entities', jsonInit('POST', input)),
    onSuccess: (record) =>
      void client.invalidateQueries({
        queryKey: ['canonical-entities', tenantID, record.scope.context_id],
      }),
  })
}

export function useAssignEntitySource(tenantID: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: EntitySourceAssignment) =>
      apiFetch<EntitySourceAssignment>('/entity-source-contexts', jsonInit('PUT', input)),
    onSuccess: (assignment) => {
      void client.invalidateQueries({
        queryKey: ['canonical-entities', tenantID, assignment.context_id],
      })
      void client.invalidateQueries({
        queryKey: ['entity-resolution', tenantID, assignment.context_id],
      })
    },
  })
}

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useInfiniteQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from './client'
import type {
  EntityContextPage,
  EntityPage,
  PeeringEstimateInput,
  PeeringEstimateResponse,
} from './sdk.gen'

export function usePeeringContexts(identity: string) {
  return useInfiniteQuery({
    queryKey: ['peering-contexts', identity],
    initialPageParam: '',
    queryFn: ({ pageParam, signal }) => {
      const query = new URLSearchParams({ limit: '100' })
      if (pageParam) query.set('cursor', pageParam)
      return apiFetch<EntityContextPage>(`/entity-contexts?${query}`, { signal })
    },
    getNextPageParam: (page) => page.next_cursor || undefined,
  })
}

export function usePeeringInterfaces(identity: string, context: string) {
  return useInfiniteQuery({
    queryKey: ['peering-interfaces', identity, context],
    enabled: Boolean(context),
    initialPageParam: '',
    queryFn: ({ pageParam, signal }) => {
      const query = new URLSearchParams({ context_id: context, limit: '100' })
      if (pageParam) query.set('cursor', pageParam)
      return apiFetch<EntityPage>(`/entities?${query}`, { signal })
    },
    getNextPageParam: (page) => page.next_cursor || undefined,
  })
}

export function usePeeringEstimate(identity: string) {
  return useMutation({
    mutationKey: ['peering-estimate', identity],
    gcTime: 0,
    mutationFn: ({ input, signal }: { input: PeeringEstimateInput; signal: AbortSignal }) =>
      apiFetch<PeeringEstimateResponse>('/flows/peering-estimate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
        signal,
      }),
  })
}

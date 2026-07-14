// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch, ApiError } from './client'

export interface MPLSLabel {
  label: number
  tc: number
  s: boolean
  ttl: number
}

export interface HopNode {
  ip: string
  sent: number
  received: number
  loss_ratio: number
  rtt_min_ms: number
  rtt_avg_ms: number
  rtt_max_ms: number
  mpls?: MPLSLabel[]
}

export interface Hop {
  ttl: number
  nodes: HopNode[]
}

export interface Link {
  ttl: number
  from: string
  to: string
}

export interface Path {
  target: string
  target_ip: string
  mode: string
  max_hops: number
  trace_count: number
  destination_reached: boolean
  hops: Hop[]
  links: Link[]
}

export interface PathSnapshot {
  id: string
  observed_at: string
  path: Path
}

export interface PathHistoryOptions {
  from?: string
  to?: string
  roundIds?: string[]
}

/** usePath fetches the latest discovered path for a test; null when none exists. */
export function usePath(testId: string | undefined) {
  return useQuery({
    queryKey: ['path', testId],
    enabled: !!testId,
    queryFn: async (): Promise<Path | null> => {
      try {
        return await apiFetch<Path>(`/tests/${testId}/path`)
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return null
        throw e
      }
    },
  })
}

/** Bounded immutable rounds for the selected tenant-owned test. Opaque IDs are
 * selectors only; the server still scopes them by session tenant and target. */
export function usePathHistory(
  testId: string | undefined,
  options: PathHistoryOptions = {},
  enabled = true,
) {
  const roundIds = (options.roundIds ?? []).filter(Boolean).slice(0, 2)
  return useQuery({
    queryKey: ['path-history', testId, options.from, options.to, roundIds],
    enabled: !!testId && enabled,
    queryFn: async (): Promise<PathSnapshot[]> => {
      const params = new URLSearchParams({ limit: '50' })
      if (options.from) params.set('from', options.from)
      if (options.to) params.set('to', options.to)
      for (const id of roundIds) params.append('round_id', id)
      return apiFetch<{ items: PathSnapshot[] }>(
        `/tests/${testId}/path/history?${params.toString()}`,
      ).then((response) => response.items)
    },
  })
}

/** useDiscoverPath triggers a fresh discovery for a test. */
export function useDiscoverPath(testId: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<Path>(`/tests/${testId}/path`, { method: 'POST' }),
    onSuccess: (p) => {
      qc.setQueryData(['path', testId], p)
      void qc.invalidateQueries({ queryKey: ['path-history', testId] })
    },
  })
}

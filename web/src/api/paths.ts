// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
  /** Present only when the server enriched the hop from an operator-supplied
   * GeoIP source; private/unresolved responders carry no location. */
  geo?: { lat: number; lon: number; city?: string; country?: string; source?: string }
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

export interface PathMeasurementFidelity {
  version: 1
  probe_transport: 'icmp' | 'tcp' | 'mixed'
  acquisition_mode: 'raw_icmp' | 'icmp_datagram' | 'tcp_connect_raw_icmp' | 'tcp_connect' | 'mixed'
  timing_source: 'application_monotonic' | 'mixed'
  hop_visibility: 'full' | 'destination_only' | 'mixed'
  kernel_timestamping: boolean
  hardware_timestamping: boolean
}

export interface Path {
  target: string
  target_ip: string
  mode: string
  max_hops: number
  trace_count: number
  destination_reached: boolean
  /** Absent only for snapshots written before the fidelity receipt shipped. */
  measurement_fidelity?: PathMeasurementFidelity
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

function normalizePath(path: Path): Path {
  return {
    ...path,
    hops: (path.hops ?? []).map((hop) => ({ ...hop, nodes: hop.nodes ?? [] })),
    links: path.links ?? [],
  }
}

/** usePath fetches the latest discovered path for a test; null when none exists. */
export function usePath(testId: string | undefined) {
  return useQuery({
    queryKey: ['path', testId],
    enabled: !!testId,
    queryFn: async (): Promise<Path | null> => {
      try {
        return normalizePath(await apiFetch<Path>(`/tests/${testId}/path`))
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
      ).then((response) =>
        (response.items ?? []).map((snapshot) => ({
          ...snapshot,
          path: normalizePath(snapshot.path),
        })),
      )
    },
  })
}

/** useDiscoverPath triggers a fresh discovery for a test. */
export function useDiscoverPath(testId: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<Path>(`/tests/${testId}/path`, { method: 'POST' }).then(normalizePath),
    onSuccess: (p) => {
      qc.setQueryData(['path', testId], p)
      void qc.invalidateQueries({ queryKey: ['path-history', testId] })
    },
  })
}

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

/** useDiscoverPath triggers a fresh discovery for a test. */
export function useDiscoverPath(testId: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiFetch<Path>(`/tests/${testId}/path`, { method: 'POST' }),
    onSuccess: (p) => qc.setQueryData(['path', testId], p),
  })
}

import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The topology + what-if API (surface: S43 over the S30 graph). The graph is
 * layout-agnostic node/edge data — positioning happens client-side. ?at= asks
 * for the graph AS IT WAS (versioned); no at = the live graph. The coverage
 * block is the honesty contract: simulation accuracy depends on completeness,
 * so the UI shows the operator which planes are actually present.
 */

export interface TopoNode {
  id: string
  kind: string
  label: string
}

export interface TopoEdge {
  from: string
  to: string
  kind: string
  label?: string
}

export interface TopoCoverage {
  path_edges: number
  flow_edges: number
  routing_edges: number
  device_edges: number
  notes?: string[]
}

export interface TopologyResponse {
  topology_running: boolean
  at?: string
  nodes: TopoNode[]
  edges: TopoEdge[]
  coverage?: TopoCoverage
}

export interface PathImpact {
  from: string
  to: string
  status: 'broken' | 'rerouted'
  route: string[]
  alt_route?: string[]
}

export interface WhatIfImpact {
  target: string
  target_kind: string
  at: string
  broken_paths: PathImpact[]
  rerouted_paths: PathImpact[]
  impacted_services: string[]
  impacted_prefixes: string[]
  disconnected: string[]
  impacted_slos: string[]
  coverage: TopoCoverage
}

export function useTopology(at?: string) {
  const qs = at ? `?at=${encodeURIComponent(at)}` : ''
  return useQuery({
    queryKey: ['topology', at ?? 'live'],
    queryFn: () => apiFetch<TopologyResponse>(`/topology${qs}`),
  })
}

export function useWhatIf() {
  return useMutation({
    mutationFn: (req: { target: string; at?: string }) =>
      apiFetch<WhatIfImpact>('/topology/whatif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      }),
  })
}

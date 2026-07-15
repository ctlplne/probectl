// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch, apiURL } from './client'

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
  site?: string
  tags?: string[]
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

export interface TestImpact {
  agent_id: string
  target: string
  status: 'broken' | 'rerouted'
}

export interface SimulationConfidence {
  level: 'low' | 'medium' | 'high'
  score: number
  basis: string
}

export interface WhatIfImpact {
  target: string
  target_kind: string
  at: string
  broken_paths: PathImpact[]
  rerouted_paths: PathImpact[]
  impacted_tests: TestImpact[]
  impacted_services: string[]
  impacted_prefixes: string[]
  disconnected: string[]
  impacted_slos: string[]
  coverage: TopoCoverage
  confidence: SimulationConfidence
}

export function useTopology(at?: string, enabled = true) {
  const qs = at ? `?at=${encodeURIComponent(at)}` : ''
  return useQuery({
    queryKey: ['topology', at ?? 'live'],
    enabled,
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

export function topologyWhatIfExportHref(target: string, at?: string): string {
  const query = new URLSearchParams({ target })
  if (at) query.set('at', at)
  return apiURL(`/topology/whatif/export?${query.toString()}`)
}

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch, apiURL } from './client'
import type { A2AMeshTopology, TopologyFailureTraffic } from './sdk.gen'
import { useAuth } from '../auth/useAuth'

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
  canonical_entity_id?: string
  canonical_status?: 'resolved' | 'conflict' | 'unresolved'
  kubernetes?: { cluster_id: string; namespace: string; uid: string; observed_at: string }
  cloud?: CloudTopologyObject
  site?: string
  tags?: string[]
}

interface CloudTopologyObject {
  provider: 'aws' | 'azure' | 'gcp'
  account: string
  location: string
  resource_id: string
  type: string
  observed_at: string
  cidrs?: string[]
  state?: string
  external?: boolean
}

export interface TopoEdge {
  from: string
  to: string
  kind: string
  label?: string
  observed_at?: string
}

export interface TopoCoverage {
  path_edges: number
  flow_edges: number
  routing_edges: number
  device_edges: number
  physical_edges?: number
  notes?: string[]
}

export interface TopologyResponse {
  topology_running: boolean
  at?: string
  nodes: TopoNode[]
  edges: TopoEdge[]
  coverage?: TopoCoverage
  canonical_context_id?: string
  canonical_projection_current_at?: string
  canonical_projection_truncated?: boolean
  cloud_latest_only?: boolean
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
  traffic?: TopologyFailureTraffic
}

export interface TopologyTrafficRequest {
  context_id: string
  failure_interface_id?: string
  traffic_from: string
  traffic_to: string
  maximum_poll_gap: string
  runout_until?: string
}

type WhatIfRequest = { target: string; at?: string } & Partial<TopologyTrafficRequest>

export function useTopology(
  at?: string,
  enabled = true,
  contextID = '',
  includeKubernetes = false,
  includeCloud = false,
) {
  const { tenant } = useAuth()
  const query = new URLSearchParams()
  if (at) query.set('at', at)
  if (contextID) query.set('context_id', contextID)
  const kubernetes = Boolean(contextID) && includeKubernetes
  if (kubernetes) query.set('include_kubernetes', 'true')
  if (includeCloud) query.set('include_cloud', 'true')
  const qs = query.size ? `?${query.toString()}` : ''
  return useQuery({
    // The same routing-context UUID may exist in different tenants. Keep
    // canonical projections and raw graphs in separate tenant cache lanes.
    queryKey: ['topology', tenant.id, at ?? 'live', contextID, kubernetes, includeCloud],
    enabled,
    queryFn: ({ signal }) =>
      apiFetch<TopologyResponse>(`/topology${qs}`, {
        signal,
        headers: { 'X-Probectl-Tenant': tenant.id },
      }),
  })
}

export function useWhatIf() {
  const { tenant } = useAuth()
  return useMutation({
    mutationFn: (req: WhatIfRequest) =>
      apiFetch<WhatIfImpact>('/topology/whatif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Probectl-Tenant': tenant.id },
        body: JSON.stringify(req),
      }),
  })
}

export function useA2AMeshTopology() {
  const { tenant, user } = useAuth()
  return useQuery({
    queryKey: ['a2a-mesh-topology', tenant.id, user.id],
    queryFn: async ({ signal }) => {
      const result = await apiFetch<A2AMeshTopology>('/a2a/mesh', {
        signal,
        headers: { 'X-Probectl-Tenant': tenant.id },
      })
      if (result.topology.some((edge) => edge.tenant_id !== tenant.id)) {
        throw new Error('Mesh response did not match the current tenant.')
      }
      return result
    },
    refetchInterval: (query) => {
      const edges = query.state.data?.topology
      if (!edges?.length) return false
      return edges.some((edge) => edge.status === 'pending') ? 10_000 : 30_000
    },
  })
}

export function topologyWhatIfExportHref(
  target: string,
  at?: string,
  traffic?: TopologyTrafficRequest,
): string {
  const query = new URLSearchParams({ target })
  if (at) query.set('at', at)
  for (const [name, value] of Object.entries(traffic ?? {})) {
    if (typeof value === 'string' && value) query.set(name, value)
  }
  return apiURL(`/topology/whatif/export?${query.toString()}`)
}

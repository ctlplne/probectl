// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { apiFetch } from './client'

export interface BGPRoutingBinding {
  id?: string
  context_id: string
  router_id: string
  distinguisher: string
  bgp_identifier: string
  families: (1 | 2)[]
  source_format?: '' | 'frr_loc_rib_v1'
}

export interface BGPRoutingBindingConfiguration {
  collector_agent_id: string
  source_ref: string
  context_id: string
  router_id: string
  manifest: {
    epoch: string
    assigned_at: string
    bindings: BGPRoutingBinding[]
  } | null
}

export function readBGPRoutingBindings(
  context: string,
  collector: string,
  source: string,
  signal: AbortSignal,
) {
  const query = new URLSearchParams({ collector_agent_id: collector, source_ref: source })
  return apiFetch<BGPRoutingBindingConfiguration>(
    `/entity-contexts/${encodeURIComponent(context)}/bgp-routing-bindings?${query.toString()}`,
    { signal },
  )
}

export function replaceBGPRoutingBindings(
  context: string,
  current: BGPRoutingBindingConfiguration,
  bindings: BGPRoutingBinding[],
  signal: AbortSignal,
) {
  return apiFetch<BGPRoutingBindingConfiguration>(
    `/entity-contexts/${encodeURIComponent(context)}/bgp-routing-bindings`,
    {
      method: 'PUT',
      signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        collector_agent_id: current.collector_agent_id,
        source_ref: current.source_ref,
        expected_epoch: current.manifest?.epoch ?? '',
        bindings,
      }),
    },
  )
}

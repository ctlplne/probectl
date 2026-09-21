// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { HonestDataStateKind } from './classifySurfaceTruth'

/**
 * Audit inventory for native tenant-data routes. A new data route is not done
 * until it names the server truth used for readiness, ingest recency, coverage,
 * and its authorization-safe next action. The surface-coverage gate prevents
 * this inventory from silently drifting behind the route registry.
 */
export interface NativeDataTruthContract {
  route: string
  producer: string
  serverTruth: string
  lastSuccessfulIngest: string
  coverageLimitation: string
  authorizedNextAction: string
  states: readonly HonestDataStateKind[]
}

export const ALL_HONEST_DATA_STATES = [
  'ready-no-data',
  'blocked',
  'permission-denied',
  'degraded',
  'quiet',
  'demo',
] as const satisfies readonly HonestDataStateKind[]

const contract = (
  route: string,
  producer: string,
  serverTruth: string,
  lastSuccessfulIngest: string,
  coverageLimitation: string,
  authorizedNextAction: string,
): NativeDataTruthContract => ({
  route,
  producer,
  serverTruth,
  lastSuccessfulIngest,
  coverageLimitation,
  authorizedNextAction,
  states: ALL_HONEST_DATA_STATES,
})

export const NATIVE_DATA_SURFACE_TRUTH: readonly NativeDataTruthContract[] = [
  contract(
    '/onboarding',
    'producer readiness service',
    '/agents/onboarding readiness fields',
    'first finding observed_at',
    'per-plane readiness detail',
    'open the server-provided next_action',
  ),
  contract(
    '/targets',
    'test registry and result collector',
    '/tests success/error plus result collector_running',
    'latest result observed_at',
    'configured test and collector coverage',
    'create a test when authorized, otherwise retry',
  ),
  contract(
    '/path',
    'path discovery engine',
    '/path discovery and history responses',
    'path round observed_at',
    'vantage and round availability',
    'discover or retry the selected test path',
  ),
  contract(
    '/incidents',
    'incident correlator',
    '/incidents result and HTTP authority status',
    'incident updated_at',
    'correlated planes and missing evidence',
    'adjust the window or retry',
  ),
  contract(
    '/alerts',
    'alert evaluator and dispatcher',
    'evaluator_running, persistence_running, connector_running',
    'alert last_seen_at',
    'evaluator, persistence, and connector readiness',
    'open the one relevant setup or retry action',
  ),
  contract(
    '/security',
    'threat and TLS collectors',
    'detections_running and collector_running',
    'detection observed_at or certificate observed_at',
    'feed, detector, and collector readiness',
    'configure or retry the affected producer',
  ),
  contract(
    '/endpoints',
    'endpoint and RUM collectors',
    'collector_running and rum_running',
    'endpoint last_seen_at',
    'endpoint, RUM, and synthetic blind spots',
    'register or retry the affected collector',
  ),
  contract(
    '/ask',
    'tenant-scoped AI adapter',
    'answer degraded/grounding and HTTP authority status',
    'answer receipt timestamp when reported',
    'grounding planes, citations, and adapter degradation',
    'ask, download the current cited handoff, or retry',
  ),
  contract(
    '/explore',
    'semantic query engine',
    'schema/query HTTP result and authority status',
    'query observation window',
    'selected source and returned row coverage',
    'edit or rerun the query',
  ),
  contract(
    '/dashboards',
    'cross-plane dashboard queries',
    'per-widget query and running fields',
    'latest timestamp per widget',
    'per-widget producer and plane coverage',
    'open the affected evidence surface',
  ),
  contract(
    '/admin',
    'fleet and control-plane diagnostics',
    'agent readiness and diagnostics status',
    'agent last_seen_at or diagnostics checked_at',
    'capability and rollout evidence availability',
    'open the one relevant setup or retry action',
  ),
  contract(
    '/topology',
    'topology builder',
    'topology_running and coverage counts',
    'topology at',
    'path, flow, routing, and device edge counts',
    'configure a producer or adjust the view',
  ),
  contract(
    '/cost',
    'cost and carbon engines',
    'cost_running and carbon_running',
    'pricing_as_of or carbon observation time',
    'pricing, zone mapping, and carbon-factor coverage',
    'configure or retry the affected engine',
  ),
  contract(
    '/slos',
    'SLO evaluator',
    'slo_running and returned definitions',
    'latest evaluation window when reported',
    'definition and source-event coverage',
    'import a definition or retry',
  ),
  contract(
    '/compliance',
    'compliance validator',
    'compliance_running and coverage object',
    'latest violation sample at',
    'observed flow/eBPF zones only',
    'recheck validator status',
  ),
  contract(
    '/outages',
    'outage correlation service',
    'outage_running and feed health',
    'feed last_success',
    'tenant vantage points plus enabled public feeds',
    'refresh the observed window',
  ),
  contract(
    '/provider',
    'provider operations APIs',
    'provider tenant/exception/usage responses',
    'usage period or operation timestamp',
    'licensed provider-plane and tenant-band coverage',
    'retry the authorized provider operation',
  ),
  contract(
    '/planes/bgp',
    'BGP analyzer',
    'topology and BGP event responses',
    'routing event observed_at',
    'configured peers and routing evidence',
    'open BGP setup or retry',
  ),
  contract(
    '/planes/flow',
    'flow collector',
    'flow query responses and errors',
    'capacity sample ts',
    'exporter and interface coverage',
    'register a flow collector or retry',
  ),
  contract(
    '/planes/device',
    'device collector',
    'device collector, physical-neighbor, identity-conflict, syslog, and config archive responses',
    'device/neighbor/identity/syslog/config observed timestamp',
    'collector protocol, LLDP/CDP freshness, identity provenance, and archive coverage',
    'register a device collector, enable bounded neighbor reads, inspect identity evidence, or retry',
  ),
  contract(
    '/planes/ebpf',
    'eBPF collector',
    'topology and service-map responses',
    'service edge observed_at when reported',
    'host/kernel and L7 edge coverage',
    'register an eBPF collector or retry',
  ),
  contract(
    '/audit',
    'tamper-evident audit store',
    'audit query and HTTP authority status',
    'event timestamp',
    'selected window and provider/tenant stream boundary',
    'adjust the window or retry',
  ),
]

/** Native routes that contain documentation/developer UI, not tenant data. */
export const NON_DATA_NATIVE_ROUTES = new Set(['/docs/api'])

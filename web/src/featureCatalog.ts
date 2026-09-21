// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

/**
 * Product-feature denominator for the surface-coverage gate.
 *
 * Source of truth: docs/contract/product-contract.json — the machine-readable
 * product contract committed beside the code, holding the feature delivery matrix
 * (`features`) and the telemetry planes (`planes`). The gate checks this catalog
 * against that contract, so a feature the contract declares but no surface serves
 * is a test failure rather than an invisible omission from SURFACES.
 */

export type RequiredFeatureStatus = 'delivered' | 'partial' | 'future' | 'removed'

export interface RequiredFeature {
  id: string
  name: string
  status: RequiredFeatureStatus
  source: 'contract:planes' | 'contract:features'
}

export const REQUIRED_FEATURES: RequiredFeature[] = [
  {
    id: 'PLANE_ACTIVE_SYNTHETIC',
    name: 'Active/synthetic telemetry plane',
    status: 'delivered',
    source: 'contract:planes',
  },
  {
    id: 'PLANE_BGP_ROUTING',
    name: 'BGP/routing telemetry plane',
    status: 'delivered',
    source: 'contract:planes',
  },
  {
    id: 'PLANE_FLOW_ANALYTICS',
    name: 'Flow analytics telemetry plane',
    status: 'delivered',
    source: 'contract:planes',
  },
  {
    id: 'PLANE_DEVICE_TELEMETRY',
    name: 'Device telemetry plane',
    status: 'delivered',
    source: 'contract:planes',
  },
  {
    id: 'PLANE_EBPF_HOST_L7',
    name: 'eBPF host/L7 telemetry plane',
    status: 'delivered',
    source: 'contract:planes',
  },
  { id: 'F1', name: 'Canary agent', status: 'delivered', source: 'contract:features' },
  {
    id: 'F2',
    name: 'Network tests (agent-to-service and agent-to-agent)',
    status: 'delivered',
    source: 'contract:features',
  },
  { id: 'F3', name: 'Path visualization', status: 'delivered', source: 'contract:features' },
  { id: 'F4', name: 'HTTP tests', status: 'delivered', source: 'contract:features' },
  { id: 'F5', name: 'DNS tests', status: 'delivered', source: 'contract:features' },
  { id: 'F6', name: 'BGP monitoring', status: 'delivered', source: 'contract:features' },
  {
    id: 'F7',
    name: 'Open-data enrichment',
    status: 'delivered',
    source: 'contract:features',
  },
  { id: 'F8', name: 'Alerting', status: 'delivered', source: 'contract:features' },
  {
    id: 'F9',
    name: 'Dashboards and incident timeline',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F10',
    name: 'Control plane, REST/gRPC, CLI',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F11',
    name: 'eBPF host/L7 agent',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F12',
    name: 'OTel-aligned data model and OTLP',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F13',
    name: 'AI RCA and natural-language query',
    status: 'delivered',
    source: 'contract:features',
  },
  { id: 'F14', name: 'MCP server', status: 'delivered', source: 'contract:features' },
  {
    id: 'F15',
    name: 'Browser synthetic',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F16',
    name: 'Endpoint agent (DEM)',
    status: 'delivered',
    source: 'contract:features',
  },
  { id: 'F17', name: 'Flow analytics', status: 'delivered', source: 'contract:features' },
  {
    id: 'F18',
    name: 'Device telemetry',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F19',
    name: 'Internet-outage view',
    status: 'delivered',
    source: 'contract:features',
  },
  { id: 'F20', name: 'RUM', status: 'delivered', source: 'contract:features' },
  { id: 'F21', name: 'Voice/RTP', status: 'delivered', source: 'contract:features' },
  {
    id: 'F22',
    name: 'SSO and role model',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F23',
    name: 'Audit foundation',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F24',
    name: 'Tenant to org/team/project hierarchy',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F25',
    name: 'SCIM, ABAC, and delegated admin',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F26',
    name: 'SIEM integration',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F27',
    name: 'On-call and ITSM',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F28',
    name: 'Zero-downtime lifecycle and fleet rollout',
    status: 'delivered',
    source: 'contract:features',
  },
  { id: 'F29', name: 'IaC and GitOps', status: 'delivered', source: 'contract:features' },
  {
    id: 'F30',
    name: 'CMDB, Grafana, and Prometheus federation',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F31',
    name: 'Secrets integration',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F32',
    name: 'FIPS-mode crypto',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F33',
    name: 'Multi-region and HA',
    status: 'partial',
    source: 'contract:features',
  },
  {
    id: 'F34',
    name: 'Advanced governance',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F35',
    name: 'Supportability',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F36',
    name: 'TLS/cert observability',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F37',
    name: 'NDR-lite detection engine',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F38',
    name: 'Threat-intel enrichment',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F39',
    name: 'Change intelligence',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F40',
    name: 'Live topology graph',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F41',
    name: 'FinOps/egress cost',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F42',
    name: 'SLO and business impact',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F43',
    name: 'Segmentation validation',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F44',
    name: 'Guarded remediation',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F45',
    name: 'AI authoring and discovery',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F46',
    name: 'Last-mile/WiFi/ISP diagnostics',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F47',
    name: 'Network chaos',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F48',
    name: 'Carbon/power',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F49',
    name: 'Plugin/detection marketplace',
    status: 'future',
    source: 'contract:features',
  },
  {
    id: 'F50',
    name: 'Tenancy and hard isolation',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F51',
    name: 'Provider/MSP plane',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F52',
    name: 'Pooled/siloed/hybrid isolation modes',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F53',
    name: 'Metering/billing export',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F54',
    name: 'Per-tenant rebranding (removed by design)',
    status: 'removed',
    source: 'contract:features',
  },
  {
    id: 'F55',
    name: 'Export/residency/verifiable deletion',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F56',
    name: 'Per-tenant keys/BYOK',
    status: 'delivered',
    source: 'contract:features',
  },
  {
    id: 'F57',
    name: 'Tenant fairness',
    status: 'delivered',
    source: 'contract:features',
  },
]

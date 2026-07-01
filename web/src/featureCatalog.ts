/**
 * Product-feature denominator for the surface-coverage gate.
 *
 * Source of truth: probectl-PRD-v1.0.md, section 2.1 ("The five planes") and
 * section 3 ("Feature delivery matrix (v0.5 F-numbers)"). The gate uses
 * this committed catalog so a missing PRD feature is a test failure, not an
 * invisible omission from SURFACES.
 */

export type RequiredFeatureStatus = 'delivered' | 'partial' | 'future'

export interface RequiredFeature {
  id: string
  name: string
  status: RequiredFeatureStatus
  source: 'prd-v1.0:2.1' | 'prd-v1.0:3'
}

export const REQUIRED_FEATURES: RequiredFeature[] = [
  {
    id: 'PLANE_ACTIVE_SYNTHETIC',
    name: 'Active/synthetic telemetry plane',
    status: 'delivered',
    source: 'prd-v1.0:2.1',
  },
  {
    id: 'PLANE_BGP_ROUTING',
    name: 'BGP/routing telemetry plane',
    status: 'delivered',
    source: 'prd-v1.0:2.1',
  },
  {
    id: 'PLANE_FLOW_ANALYTICS',
    name: 'Flow analytics telemetry plane',
    status: 'delivered',
    source: 'prd-v1.0:2.1',
  },
  {
    id: 'PLANE_DEVICE_TELEMETRY',
    name: 'Device telemetry plane',
    status: 'delivered',
    source: 'prd-v1.0:2.1',
  },
  {
    id: 'PLANE_EBPF_HOST_L7',
    name: 'eBPF host/L7 telemetry plane',
    status: 'delivered',
    source: 'prd-v1.0:2.1',
  },
  { id: 'F1', name: 'Canary agent', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F2',
    name: 'Network tests (agent-to-service and agent-to-agent)',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  { id: 'F3', name: 'Path visualization', status: 'delivered', source: 'prd-v1.0:3' },
  { id: 'F4', name: 'HTTP tests', status: 'delivered', source: 'prd-v1.0:3' },
  { id: 'F5', name: 'DNS tests', status: 'delivered', source: 'prd-v1.0:3' },
  { id: 'F6', name: 'BGP monitoring', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F7',
    name: 'Open-data enrichment',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  { id: 'F8', name: 'Alerting', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F9',
    name: 'Dashboards and incident timeline',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F10',
    name: 'Control plane, REST/gRPC, CLI/TUI',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F11',
    name: 'eBPF host/L7 agent',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F12',
    name: 'OTel-aligned data model and OTLP',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F13',
    name: 'AI RCA and natural-language query',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  { id: 'F14', name: 'MCP server', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F15',
    name: 'Browser synthetic',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F16',
    name: 'Endpoint agent (DEM)',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  { id: 'F17', name: 'Flow analytics', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F18',
    name: 'Device telemetry',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F19',
    name: 'Internet-outage view',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  { id: 'F20', name: 'RUM', status: 'delivered', source: 'prd-v1.0:3' },
  { id: 'F21', name: 'Voice/RTP', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F22',
    name: 'SSO and role model',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F23',
    name: 'Audit foundation',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F24',
    name: 'Tenant to org/team/project hierarchy',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F25',
    name: 'SCIM, ABAC, and delegated admin',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F26',
    name: 'SIEM integration',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F27',
    name: 'On-call and ITSM',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F28',
    name: 'Zero-downtime lifecycle and fleet rollout',
    status: 'partial',
    source: 'prd-v1.0:3',
  },
  { id: 'F29', name: 'IaC and GitOps', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F30',
    name: 'CMDB, Grafana, and Prometheus federation',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F31',
    name: 'Secrets integration',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F32',
    name: 'FIPS-mode crypto',
    status: 'partial',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F33',
    name: 'Multi-region and HA',
    status: 'partial',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F34',
    name: 'Advanced governance',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F35',
    name: 'Supportability',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F36',
    name: 'TLS/cert observability',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F37',
    name: 'NDR-lite detection engine',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F38',
    name: 'Threat-intel enrichment',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F39',
    name: 'Change intelligence',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F40',
    name: 'Live topology graph',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F41',
    name: 'FinOps/egress cost',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F42',
    name: 'SLO and business impact',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F43',
    name: 'Segmentation validation',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F44',
    name: 'Guarded remediation',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F45',
    name: 'AI authoring and discovery',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F46',
    name: 'Last-mile/WiFi/ISP diagnostics',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F47',
    name: 'Network chaos',
    status: 'partial',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F48',
    name: 'Carbon/power',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F49',
    name: 'Plugin/detection marketplace',
    status: 'future',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F50',
    name: 'Tenancy and hard isolation',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F51',
    name: 'Provider/MSP plane',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F52',
    name: 'Pooled/siloed/hybrid isolation modes',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F53',
    name: 'Metering/billing export',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  { id: 'F54', name: 'White-label', status: 'delivered', source: 'prd-v1.0:3' },
  {
    id: 'F55',
    name: 'Export/residency/verifiable deletion',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F56',
    name: 'Per-tenant keys/BYOK',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
  {
    id: 'F57',
    name: 'Tenant fairness',
    status: 'delivered',
    source: 'prd-v1.0:3',
  },
]

// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const TENANT_ID = '00000000-0000-4000-8000-000000000001'
const EDGE_DNS_TEST_ID = '10000000-0000-4000-8000-000000000001'
const API_GATEWAY_TEST_ID = '10000000-0000-4000-8000-000000000002'
const AGENT_ID = '20000000-0000-4000-8000-000000000001'
const INCIDENT_ID = '30000000-0000-4000-8000-000000000001'

const sampleTests = [
  {
    id: EDGE_DNS_TEST_ID,
    tenant_id: TENANT_ID,
    name: 'edge-dns',
    type: 'dns',
    target: '1.1.1.1',
    interval_seconds: 30,
    timeout_seconds: 3,
    params: {},
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: API_GATEWAY_TEST_ID,
    tenant_id: TENANT_ID,
    name: 'api-gw',
    type: 'tcp',
    target: 'api.example.com:443',
    interval_seconds: 60,
    timeout_seconds: 3,
    params: {},
    enabled: false,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
]

const sampleAgents = [
  {
    id: AGENT_ID,
    tenant_id: TENANT_ID,
    name: 'agent-1',
    hostname: 'host-a',
    agent_version: '0.1.0',
    status: 'online',
    capabilities: ['icmp', 'tcp', 'flow', 'device', 'ebpf', 'endpoint'],
    labels: { region: 'us-east', site: 'iad-1' },
    spiffe_id: `spiffe://probectl/tenant/${TENANT_ID}/agent/${AGENT_ID}`,
    registered_at: '2026-01-01T00:00:00Z',
    last_seen_at: '2026-06-04T12:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    heartbeat_age_seconds: 30,
    heartbeat_state: 'ready',
    heartbeat_reason: 'Authenticated heartbeat is inside the five-minute health gate.',
    version_state: 'current',
    version_reason: 'Agent matches the control-plane version.',
    readiness_state: 'ready',
    readiness_reason: 'Heartbeat, version policy, and reported capabilities are ready.',
    rollout_halted: false,
    last_failure: '',
    next_safe_action: {
      kind: 'inspect_evidence',
      label: 'Inspect agent evidence',
      reason: 'Review the tenant-scoped registry evidence; no fleet change is performed.',
      href: '/docs/api#rollouts',
    },
  },
]

const sampleIncident = {
  id: INCIDENT_ID,
  tenant_id: TENANT_ID,
  status: 'open',
  severity: 'warning',
  title: 'checkout latency burn',
  target: 'https://checkout.probectl.test',
  started_at: '2026-06-04T11:45:00Z',
  last_seen_at: '2026-06-04T12:00:00Z',
  signal_count: 3,
  signals: [
    {
      plane: 'synthetic',
      kind: 'http.latency',
      severity: 'warning',
      title: 'HTTP latency above SLO',
      target: 'https://checkout.probectl.test',
      occurred_at: '2026-06-04T11:55:00Z',
    },
    {
      plane: 'flow',
      kind: 'capacity.anomaly',
      severity: 'warning',
      title: 'edge-r1 throughput spike',
      target: 'edge-r1',
      occurred_at: '2026-06-04T11:58:00Z',
    },
  ],
}

const sampleChange = {
  id: '50000000-0000-4000-8000-000000000001',
  source: 'git',
  kind: 'deployment',
  title: 'DNS edge route update',
  summary: 'A reviewed route configuration changed inside the selected path window.',
  target: '1.1.1.1',
  actor: 'network-automation',
  ref: 'change-42',
  occurred_at: '2026-06-04T12:00:00Z',
}

/** Discovered path for edge-dns (→ 1.1.1.1): an ECMP fan at TTL 2–4 with
 * an MPLS label on one branch, a loss hotspot on the other, reconverging
 * before the destination — enough story for the J4 hero to demonstrate
 * branches, labels, loss encoding, and round comparison. */
function pathNode(
  ip: string,
  rtt: number,
  loss = 0,
  mpls?: { label: number; tc: number; s: boolean; ttl: number }[],
) {
  return {
    ip,
    sent: 12,
    received: Math.round(12 * (1 - loss)),
    loss_ratio: loss,
    rtt_min_ms: Math.max(0, rtt - 1),
    rtt_avg_ms: rtt,
    rtt_max_ms: rtt + 2,
    ...(mpls ? { mpls } : {}),
  }
}

function samplePath(withSecondBranch: boolean) {
  const hops = [
    { ttl: 1, nodes: [pathNode('10.0.0.1', 1)] },
    {
      ttl: 2,
      nodes: [pathNode('10.0.2.1', 3), ...(withSecondBranch ? [pathNode('10.0.2.2', 4)] : [])],
    },
    {
      ttl: 3,
      nodes: [
        pathNode('172.16.3.1', 8, 0, [{ label: 16259, tc: 0, s: true, ttl: 1 }]),
        ...(withSecondBranch ? [pathNode('172.16.3.2', 11, 0.12)] : []),
      ],
    },
    {
      ttl: 4,
      nodes: [
        {
          ...pathNode('192.0.2.9', 14),
          geo: { lat: 38.95, lon: -77.45, city: 'Ashburn', country: 'US', source: 'fixture' },
        },
      ],
    },
    {
      ttl: 5,
      nodes: [
        {
          ...pathNode('1.1.1.1', 18),
          geo: {
            lat: 37.77,
            lon: -122.41,
            city: 'San Francisco',
            country: 'US',
            source: 'fixture',
          },
        },
      ],
    },
  ]
  const links = [
    { ttl: 1, from: '10.0.0.1', to: '10.0.2.1' },
    ...(withSecondBranch ? [{ ttl: 1, from: '10.0.0.1', to: '10.0.2.2' }] : []),
    { ttl: 2, from: '10.0.2.1', to: '172.16.3.1' },
    ...(withSecondBranch ? [{ ttl: 2, from: '10.0.2.2', to: '172.16.3.2' }] : []),
    { ttl: 3, from: '172.16.3.1', to: '192.0.2.9' },
    ...(withSecondBranch ? [{ ttl: 3, from: '172.16.3.2', to: '192.0.2.9' }] : []),
    { ttl: 4, from: '192.0.2.9', to: '1.1.1.1' },
  ]
  return {
    target: '1.1.1.1',
    target_ip: '1.1.1.1',
    mode: 'icmp',
    max_hops: 30,
    trace_count: 12,
    destination_reached: true,
    measurement_fidelity: {
      version: 1,
      probe_transport: 'icmp',
      acquisition_mode: 'raw_icmp',
      timing_source: 'application_monotonic',
      hop_visibility: 'full',
      kernel_timestamping: false,
      hardware_timestamping: false,
    },
    hops,
    links,
  }
}

const samplePathRounds = [
  { id: 'round-3', observed_at: '2026-06-04T12:00:00Z', path: samplePath(true) },
  { id: 'round-2', observed_at: '2026-06-04T11:30:00Z', path: samplePath(false) },
  { id: 'round-1', observed_at: '2026-06-04T11:00:00Z', path: samplePath(false) },
]

const sampleAnswer = {
  id: 'ans-fixture',
  tenant: TENANT_ID,
  question: '',
  root_cause: 'Most likely root cause: "edge-r1 throughput spike" saturating the checkout path.',
  root_cause_citations: [{ evidence_id: 'E1' }],
  root_cause_grounded: true,
  degraded: false,
  confidence: 'medium',
  model: 'builtin',
  reasoning: {
    adapter: 'builtin',
    execution: 'builtin_local',
    egress_consent: 'not_required',
  },
  insufficient_evidence: false,
  investigation_plan: [
    {
      step: 1,
      domain: 'entities',
      goal: 'Check correlated incidents and their stitched cross-plane signals.',
      limit: 50,
      read_only: true,
      status: 'queried',
      evidence_count: 2,
    },
    {
      step: 2,
      domain: 'events',
      goal: 'Check change and flow records near the question window.',
      limit: 50,
      read_only: true,
      status: 'queried',
      evidence_count: 1,
    },
  ],
  findings: [
    {
      statement: 'The flow plane shows an edge-r1 throughput spike inside the incident window.',
      citations: [{ evidence_id: 'E1' }],
    },
    {
      statement: 'Synthetic HTTP latency crossed the SLO threshold three minutes later.',
      citations: [{ evidence_id: 'E2' }],
    },
  ],
  evidence: [
    {
      id: 'E1',
      domain: 'entities',
      plane: 'flow',
      severity: 'warning',
      title: 'edge-r1 throughput spike',
      summary: 'capacity.anomaly at 85 Mbps against a 35 Mbps baseline',
      ref: `incident:${INCIDENT_ID}`,
      occurred_at: '2026-06-04T11:58:00Z',
    },
    {
      id: 'E2',
      domain: 'entities',
      plane: 'synthetic',
      severity: 'warning',
      title: 'HTTP latency above SLO',
      summary: 'checkout p95 above objective',
      ref: `incident:${INCIDENT_ID}`,
      occurred_at: '2026-06-04T11:55:00Z',
    },
  ],
}

const sampleIntelStatus = {
  open_data_enabled: true,
  threat_intel_enabled: true,
  ioc_count: 1200,
  open_data_sources: [
    {
      name: 'test_cymru',
      kind: 'asn',
      cadence_seconds: 86_400,
      aup: {
        license: 'public lookup',
        url: 'https://terms.example/opendata',
        attribution: 'Example Data',
        commercial_use: 'allowed-with-attribution',
        redistribution: 'cached lookup only',
      },
      enabled: true,
      status: 'ok',
      last_success: '2026-06-04T12:00:00Z',
      last_error: '',
    },
  ],
  threat_intel_feeds: [
    {
      name: 'feodo_tracker',
      kind: 'threat_intel',
      cadence_seconds: 3600,
      aup: {
        license: 'abuse.ch CC0',
        url: 'https://abuse.ch/',
        attribution: '',
        commercial_use: 'allowed',
        redistribution: '',
      },
      enabled: true,
      status: 'ok',
      last_success: '2026-06-04T12:00:00Z',
      last_error: '',
      ioc_count: 1200,
    },
  ],
}

const sampleLatestResults = [
  {
    agent_id: AGENT_ID,
    type: 'dns',
    target: '1.1.1.1',
    success: true,
    duration_ms: 21,
    metrics: { 'dns.query.ms': 21 },
    observed_at: '2026-06-04T12:00:00Z',
  },
  {
    agent_id: AGENT_ID,
    type: 'http',
    target: 'https://checkout.probectl.test',
    success: true,
    duration_ms: 184,
    metrics: { 'http.total.ms': 184, 'http.status': 200 },
    observed_at: '2026-06-04T12:00:00Z',
  },
  {
    agent_id: AGENT_ID,
    type: 'dns',
    target: 'checkout.probectl.test',
    success: true,
    duration_ms: 18,
    metrics: { 'dns.query.ms': 18 },
    observed_at: '2026-06-04T12:00:00Z',
  },
]

export const sampleExplorerTemplates = [
  [
    'top-talkers-site',
    'Show top talkers by site',
    'flow',
    ['site', 'interface'],
    ['site'],
    ['bps', 'pps'],
    'bar',
    '/planes/flow',
  ],
  [
    'asn-before-incident',
    'Which ASN change preceded this incident?',
    'changes',
    ['source', 'prefix', 'target'],
    ['source'],
    ['events'],
    'timeline',
    '/incidents',
  ],
  [
    'loss-by-hop',
    'Show loss by hop for this test',
    'path',
    ['target', 'hop', 'node'],
    ['hop'],
    ['loss_ratio', 'rtt_avg_ms'],
    'line',
    '/path',
  ],
  [
    'service-dependencies',
    'Show service dependencies',
    'topology',
    ['from', 'to', 'kind'],
    ['kind'],
    ['edges'],
    'topology',
    '/topology',
  ],
  [
    'saturated-interface',
    'Which device interface is saturated?',
    'flow',
    ['site', 'interface'],
    ['site', 'interface'],
    ['bps', 'pps'],
    'line',
    '/planes/device',
  ],
  [
    'outage-endpoints',
    'Which endpoints are affected by this outage?',
    'endpoints',
    ['endpoint', 'cause', 'summary'],
    ['cause'],
    ['affected_endpoints'],
    'table',
    '/endpoints',
  ],
  [
    'certificates-expiring',
    'Which certificates expire in the next 30 days?',
    'tls',
    ['target', 'subject', 'issuer'],
    ['issuer'],
    ['days_remaining'],
    'table',
    '/security',
  ],
  [
    'cross-az-cost',
    'Show cross-AZ network cost',
    'cost',
    ['from_zone', 'to_zone', 'service'],
    ['from_zone', 'to_zone'],
    ['bytes', 'usd'],
    'bar',
    '/cost',
  ],
  [
    'slo-budget-burn',
    'Which SLO error budgets are burning?',
    'slo',
    ['slo', 'service', 'team'],
    ['service'],
    ['burn_rate', 'budget_remaining'],
    'bar',
    '/slos',
  ],
  [
    'deployments-before-incident',
    'Which deployments immediately preceded this incident?',
    'changes',
    ['source', 'actor', 'target'],
    ['source'],
    ['events'],
    'timeline',
    '/incidents',
  ],
].map(([id, question, source, dimensions, groupings, measures, visualization, evidence_path]) => ({
  id,
  question,
  source,
  dimensions,
  groupings,
  measures,
  visualization,
  evidence_path,
}))

interface FixtureExplorerQuery {
  template?: string
  source: string
  from: string
  to: string
  dimensions: string[]
  filters: Record<string, string>
  groupings: string[]
  measures: string[]
  limit: number
}

function explorerExecution(query: FixtureExplorerQuery, returnedRows: number, truncated = false) {
  return {
    contract_version: 'explorer-execution/v1',
    recipe: query.template ?? 'custom',
    source: query.source,
    tenant_scoped: true,
    bounds: {
      from: query.from,
      to: query.to,
      row_limit: query.limit,
    },
    projection: {
      dimensions: query.dimensions,
      groupings: query.groupings,
      measures: query.measures,
    },
    filter_keys: Object.keys(query.filters).sort(),
    source_rows: returnedRows,
    returned_rows: returnedRows,
    truncated,
    truncation_reason: truncated ? 'row_limit' : 'none',
    timings: {
      source_ms: 2,
      shaping_ms: 1,
      total_ms: 3,
    },
  }
}

/**
 * pathOf parses a fetched URL to its PATHNAME (no query, no origin) so stub
 * routes match by exact path, not substring. RED-006/UX-006: matching with
 * url.endsWith()/url.includes() let a double-prefixed '/v1/v1/topology' satisfy
 * a '/v1/topology' route and render green despite the bug. Exact-pathname
 * matching plus the assertNoDoublePrefix guard below close that.
 */
function urlOf(input: RequestInfo | URL): URL {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : String(input)
  // Resolve against a dummy origin so relative paths ('/v1/me') parse too.
  return new URL(raw, 'http://t.invalid')
}

export function pathOf(input: RequestInfo | URL): string {
  return urlOf(input).pathname
}

/** RED-006: a fetched URL must NEVER carry a doubled '/v1/v1' segment — that is
 *  the exact double-prefix bug (UX-001). Any stub call that sees it throws, so a
 *  regression fails the suite loudly instead of passing on a lenient match. */
export function assertNoDoublePrefix(input: RequestInfo | URL): void {
  const p = pathOf(input)
  if (p.includes('/v1/v1')) {
    throw new Error(`double /v1 prefix in fetched URL: ${p} (UX-001/RED-006)`)
  }
}

export type FixtureProfile = 'populated' | 'cold'

export interface FixtureOptions {
  /** Provider routes are commercial and hidden in the ordinary core fixture. */
  providerPlane?: boolean
}

type FlowFixtureGroupBy =
  | 'src'
  | 'dst'
  | 'pair'
  | 'src_asn'
  | 'dst_asn'
  | 'as_name'
  | 'src_country'
  | 'dst_country'
  | 'port'
  | 'protocol'
  | 'exporter'

interface FlowFixtureObservation {
  ts: string
  src: string
  srcDetail: string
  dst: string
  dstDetail: string
  srcASN: number
  dstASN: number
  srcASName: string
  dstASName: string
  srcCountry: string
  dstCountry: string
  srcPort: number
  dstPort: number
  protocol: string
  exporter: string
  bytes: number
  packets: number
  flows: number
}

interface FlowFixtureFilter {
  field: string
  value: string
}

interface FlowFixtureAggregate {
  key: string
  detail?: string
  bytes: number
  packets: number
  flows: number
  exporters: Set<string>
}

const flowFixtureObservations: FlowFixtureObservation[] = [
  {
    ts: '2026-06-04T11:55:00Z',
    src: '10.0.0.10',
    srcDetail: 'checkout',
    dst: '10.0.1.20',
    dstDetail: 'payments',
    srcASN: 64510,
    dstASN: 64520,
    srcASName: 'Acme Commerce',
    dstASName: 'Acme Payments',
    srcCountry: 'US',
    dstCountry: 'DE',
    srcPort: 51_240,
    dstPort: 443,
    protocol: 'tcp',
    exporter: 'edge-r1',
    bytes: 314_572_800,
    packets: 70_000,
    flows: 24,
  },
  {
    ts: '2026-06-04T12:00:00Z',
    src: '10.0.0.10',
    srcDetail: 'checkout',
    dst: '10.0.1.20',
    dstDetail: 'payments',
    srcASN: 64510,
    dstASN: 64520,
    srcASName: 'Acme Commerce',
    dstASName: 'Acme Payments',
    srcCountry: 'US',
    dstCountry: 'DE',
    srcPort: 51_241,
    dstPort: 443,
    protocol: 'tcp',
    exporter: 'edge-r2',
    bytes: 209_715_200,
    packets: 50_000,
    flows: 18,
  },
  {
    ts: '2026-06-04T11:55:00Z',
    src: '10.0.0.20',
    srcDetail: 'payments',
    dst: '10.0.1.30',
    dstDetail: 'ledger',
    srcASN: 64520,
    dstASN: 64530,
    srcASName: 'Acme Payments',
    dstASName: 'Acme Data',
    srcCountry: 'DE',
    dstCountry: 'US',
    srcPort: 52_120,
    dstPort: 5432,
    protocol: 'tcp',
    exporter: 'edge-r1',
    bytes: 62_914_560,
    packets: 13_400,
    flows: 10,
  },
  {
    ts: '2026-06-04T12:00:00Z',
    src: '10.0.0.20',
    srcDetail: 'payments',
    dst: '10.0.1.30',
    dstDetail: 'ledger',
    srcASN: 64520,
    dstASN: 64530,
    srcASName: 'Acme Payments',
    dstASName: 'Acme Data',
    srcCountry: 'DE',
    dstCountry: 'US',
    srcPort: 52_121,
    dstPort: 5432,
    protocol: 'tcp',
    exporter: 'edge-r1',
    bytes: 41_943_040,
    packets: 9_000,
    flows: 8,
  },
]

const flowFixtureGroupBys = new Set<FlowFixtureGroupBy>([
  'src',
  'dst',
  'pair',
  'src_asn',
  'dst_asn',
  'as_name',
  'src_country',
  'dst_country',
  'port',
  'protocol',
  'exporter',
])

function parseFlowFixtureFilters(url: URL): FlowFixtureFilter[] {
  return url.searchParams.getAll('filter').flatMap((raw) => {
    const separator = raw.indexOf(':')
    if (separator <= 0 || separator === raw.length - 1) return []
    return [{ field: raw.slice(0, separator), value: raw.slice(separator + 1) }]
  })
}

function fallbackASName(row: FlowFixtureObservation): string {
  return row.dstASName || row.srcASName
}

function fallbackPort(row: FlowFixtureObservation): number {
  return row.dstPort || row.srcPort
}

function flowFixtureMatches(row: FlowFixtureObservation, filter: FlowFixtureFilter): boolean {
  switch (filter.field) {
    case 'src':
      return row.src === filter.value
    case 'dst':
      return row.dst === filter.value
    case 'src_asn':
      return String(row.srcASN) === filter.value
    case 'dst_asn':
      return String(row.dstASN) === filter.value
    case 'as_name':
      return row.srcASName === filter.value || row.dstASName === filter.value
    case 'group_as_name':
      return fallbackASName(row) === filter.value
    case 'src_country':
      return row.srcCountry === filter.value
    case 'dst_country':
      return row.dstCountry === filter.value
    case 'port':
      return String(row.srcPort) === filter.value || String(row.dstPort) === filter.value
    case 'group_port':
      return String(fallbackPort(row)) === filter.value
    case 'protocol':
      return row.protocol === filter.value
    case 'exporter':
      return row.exporter === filter.value
    default:
      return false
  }
}

function flowFixtureGroup(
  row: FlowFixtureObservation,
  by: FlowFixtureGroupBy,
): { key: string; detail?: string } {
  switch (by) {
    case 'src':
      return { key: row.src, detail: row.srcDetail }
    case 'dst':
      return { key: row.dst, detail: row.dstDetail }
    case 'pair':
      return { key: row.src, detail: row.dst }
    case 'src_asn':
      return { key: String(row.srcASN), detail: row.srcASName }
    case 'dst_asn':
      return { key: String(row.dstASN), detail: row.dstASName }
    case 'as_name':
      return { key: fallbackASName(row) }
    case 'src_country':
      return { key: row.srcCountry }
    case 'dst_country':
      return { key: row.dstCountry }
    case 'port':
      return { key: String(fallbackPort(row)) }
    case 'protocol':
      return { key: row.protocol }
    case 'exporter':
      return { key: row.exporter }
  }
}

function addFlowFixtureObservation(
  aggregates: Map<string, FlowFixtureAggregate>,
  row: FlowFixtureObservation,
  by: FlowFixtureGroupBy,
) {
  const group = flowFixtureGroup(row, by)
  const mapKey = `${group.key}\u0000${group.detail ?? ''}`
  const aggregate = aggregates.get(mapKey) ?? {
    ...group,
    bytes: 0,
    packets: 0,
    flows: 0,
    exporters: new Set<string>(),
  }
  aggregate.bytes += row.bytes
  aggregate.packets += row.packets
  aggregate.flows += row.flows
  aggregate.exporters.add(row.exporter)
  aggregates.set(mapKey, aggregate)
}

function flowFixtureTop(input: RequestInfo | URL) {
  const url = urlOf(input)
  const requestedBy = url.searchParams.get('by') as FlowFixtureGroupBy | null
  const by = requestedBy && flowFixtureGroupBys.has(requestedBy) ? requestedBy : 'src'
  const filters = parseFlowFixtureFilters(url)
  const observations = flowFixtureObservations.filter((row) =>
    filters.every((filter) => flowFixtureMatches(row, filter)),
  )
  const parsedLimit = Number.parseInt(url.searchParams.get('limit') ?? '8', 10)
  const limit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 50) : 8

  const totals = new Map<string, FlowFixtureAggregate>()
  for (const row of observations) addFlowFixtureObservation(totals, row, by)
  const items = [...totals.values()]
    .sort((left, right) => right.bytes - left.bytes || left.key.localeCompare(right.key))
    .slice(0, limit)
  const visible = new Set(items.map((item) => `${item.key}\u0000${item.detail ?? ''}`))

  const seriesTotals = new Map<string, FlowFixtureAggregate & { ts: string }>()
  for (const row of observations) {
    const group = flowFixtureGroup(row, by)
    const groupKey = `${group.key}\u0000${group.detail ?? ''}`
    if (!visible.has(groupKey)) continue
    const mapKey = `${row.ts}\u0000${groupKey}`
    const aggregate = seriesTotals.get(mapKey) ?? {
      ...group,
      ts: row.ts,
      bytes: 0,
      packets: 0,
      flows: 0,
      exporters: new Set<string>(),
    }
    aggregate.bytes += row.bytes
    aggregate.packets += row.packets
    aggregate.flows += row.flows
    aggregate.exporters.add(row.exporter)
    seriesTotals.set(mapKey, aggregate)
  }

  const serialize = (aggregate: FlowFixtureAggregate) => ({
    key: aggregate.key,
    ...(aggregate.detail ? { detail: aggregate.detail } : {}),
    bytes: aggregate.bytes,
    packets: aggregate.packets,
    flows: aggregate.flows,
    exporter_count: aggregate.exporters.size,
  })

  return {
    items: items.map(serialize),
    series: [...seriesTotals.values()]
      .sort(
        (left, right) =>
          left.ts.localeCompare(right.ts) ||
          right.bytes - left.bytes ||
          left.key.localeCompare(right.key),
      )
      .map((aggregate) => ({ ts: aggregate.ts, ...serialize(aggregate) })),
    effective_limit: limit,
    series_limit: Math.min(limit, 6),
    window: url.searchParams.get('window') ?? '1h',
    bucket: url.searchParams.get('bucket') ?? '3m',
    filters,
  }
}

/** The install-day truth: what a freshly deployed control plane answers
 * before any agent enrolls. Only DATA endpoints appear here — identity,
 * branding, editions, schemas fall through to the shared catalog. Flags are
 * honest per the six-state contract: consumers that run on a fresh control
 * plane say running:true with zero items (ready-no-data/quiet), producers
 * that need setup keep their populated defaults (rum/carbon already report
 * running:false) or say so here. */
function coldFixture(path: string): Response | null {
  switch (path) {
    case '/v1/tests':
    case '/v1/incidents':
    case '/v1/flows/top':
    case '/v1/flows/capacity':
    case '/v1/flows/anomalies':
    case '/v1/inventory/views':
      return jsonResponse({ items: [] })
    case '/v1/flows/ingest-quality':
      return jsonResponse({
        contract_version: 'probectl.flow-ingest-quality/v1',
        items: [],
        ingest_running: true,
        effective_limit: 100,
        truncated: false,
        as_of: '2026-06-04T12:00:00Z',
        stale_after_seconds: 180,
        retention: { max_per_tenant: 4096, retention_days: 30 },
      })
    case '/v1/agents':
      return jsonResponse({ items: [], control_version: '0.1.0', rollouts_available: true })
    case '/v1/results/latest':
      return jsonResponse({ items: [], collector_running: true })
    case '/v1/coverage/vantages':
      return jsonResponse({
        items: [],
        as_of: '2026-06-04T12:00:00Z',
        evidence_running: true,
        candidate_limit: 5000,
        truncated: false,
      })
    case '/v1/coverage/debt':
      return jsonResponse({
        items: [],
        producers: [
          {
            plane: 'synthetic',
            registered_count: 0,
            runtime_running: true,
            evidence_count: 0,
            status: 'unregistered',
          },
          {
            plane: 'path',
            registered_count: 0,
            runtime_running: true,
            evidence_count: 0,
            status: 'unregistered',
          },
          {
            plane: 'flow',
            registered_count: 0,
            runtime_running: true,
            evidence_count: 0,
            status: 'unregistered',
          },
          {
            plane: 'routing',
            registered_count: 0,
            runtime_running: true,
            evidence_count: 0,
            status: 'unregistered',
          },
          {
            plane: 'device',
            registered_count: 0,
            runtime_running: true,
            evidence_count: 0,
            status: 'unregistered',
          },
        ],
        as_of: '2026-06-04T12:00:00Z',
        stale_after_seconds: 900,
        entity_limit: 500,
        candidate_limit: 5000,
        candidates_truncated: false,
        results_truncated: false,
        entities_truncated: false,
        topology_truncated: false,
        partial_reasons: [],
      })
    case '/v1/results/history':
      return jsonResponse({ items: [], collector_running: true, window: '1h0m0s' })
    case '/v1/alerts/active':
      return jsonResponse({ items: [], evaluator_running: true })
    case '/v1/threat/detections':
      return jsonResponse({ items: [], detections_running: true })
    case '/v1/endpoints':
      return jsonResponse({ items: [], collector_running: true })
    case '/v1/device/identity-conflicts':
      return jsonResponse({
        items: [],
        topology_running: true,
        as_of: '2026-06-04T12:00:00Z',
        stale_after_seconds: 3600,
        effective_limit: 100,
        filtered_count: 0,
        store_truncated: false,
        response_truncated: false,
        truncated: false,
        partial_reasons: [],
      })
    case '/v1/device/neighbors':
      return jsonResponse({
        contract_version: 'probectl.device-neighbors/v1',
        items: [],
        collection_running: true,
        effective_limit: 100,
        truncated: false,
        as_of: '2026-06-04T12:00:00Z',
        retention: { max_per_device: 256, max_per_tenant: 16384, stale_retention_hours: 24 },
      })
    case '/v1/device/collection-outcomes':
      return jsonResponse({
        contract_version: 'probectl.device-collection-outcomes/v1',
        items: [],
        collection_running: true,
        effective_limit: 100,
        truncated: false,
        as_of: '2026-06-04T12:00:00Z',
        retention: { max_per_tenant: 4096, retention_days: 30 },
      })
    case '/v1/device/syslog':
      return jsonResponse({ items: [], syslog_running: true })
    case '/v1/device/configs':
      return jsonResponse({ items: [], archive_running: true })
    case '/v1/slos':
      return jsonResponse({ slo_running: true, items: [] })
    case '/v1/compliance':
      return jsonResponse({ compliance_running: true, items: [] })
    case '/v1/cost/summary':
      // Fresh install: flow attribution is not configured yet — blocked, not a zero.
      return jsonResponse({ cost_running: false })
    case '/v1/topology':
      return jsonResponse({
        topology_running: true,
        at: '2026-06-04T12:00:00Z',
        nodes: [],
        edges: [],
        coverage: {
          path_edges: 0,
          flow_edges: 0,
          routing_edges: 0,
          device_edges: 0,
          physical_edges: 0,
        },
      })
    default:
      return null
  }
}

/** A read-only fetch covering the list endpoints, so any screen renders with
 *  data. Pure (no vitest): the unit suite wraps it in vi.fn (fetchStub.ts) and
 *  the dev-only Vite fixture middleware serves it for the design loop. CRUD
 *  tests install their own stateful stub. Profile 'cold' answers the data
 *  endpoints as a freshly installed deployment (the install-day design/test
 *  surface); everything else falls through to the populated catalog. */
/** DPR-027: tenant people & roles. Each fixtureFetch instance gets its own copy so a
 * test that adds, grants or revokes never leaks into another test. */
function seedDirectoryUsers() {
  return [
  {
    id: 'fixture-user-operator',
    tenant_id: '00000000-0000-0000-0000-000000000001',
    email: 'operator@probectl.test',
    display_name: 'Test Operator',
    status: 'active',
    roles: ['admin'],
    created_at: '2026-06-04T12:00:00Z',
    updated_at: '2026-06-04T12:00:00Z',
  },
  {
    id: 'fixture-user-viewer',
    tenant_id: '00000000-0000-0000-0000-000000000001',
    email: 'viewer@probectl.test',
    display_name: 'Read Only',
    status: 'active',
    roles: ['viewer'],
    created_at: '2026-06-04T12:00:00Z',
    updated_at: '2026-06-04T12:00:00Z',
  },
]
}
const fixtureDirectoryRoles = [
  { id: 'role-admin', tenant_id: '00000000-0000-0000-0000-000000000001', slug: 'admin', name: 'Administrator', description: 'Full access within the tenant', is_system: true, permissions: ['agent.read', 'agent.write', 'directory.write'], members: 1 },
  { id: 'role-editor', tenant_id: '00000000-0000-0000-0000-000000000001', slug: 'editor', name: 'Editor', description: 'Manage tests, alerts, incidents', is_system: true, permissions: ['test.read', 'test.write'], members: 0 },
  { id: 'role-viewer', tenant_id: '00000000-0000-0000-0000-000000000001', slug: 'viewer', name: 'Viewer', description: 'Read-only', is_system: true, permissions: ['test.read'], members: 1 },
]

export function fixtureFetch(
  profile: FixtureProfile = 'populated',
  options: FixtureOptions = {},
): typeof fetch {
  let fixtureDirectoryUsers = seedDirectoryUsers()
  // The fixture-backed design loop is stateful for the write steps used by
  // documented journeys. Every value is obviously synthetic and lives only in
  // this factory closure; a browser refresh of the dev server cannot mutate a
  // real control plane or another test's fixture state.
  let fixtureTests = sampleTests.map((test) => ({ ...test }))
  let enrollmentTokenCreated = false
  let firstTestCreated = false
  let scimTokenCreated = false
  let remediationProposals: Array<Record<string, unknown>> = []
  let lifecycleRetention: Record<string, unknown> = {
    flow_retention_days: null,
    isolation_model: 'pooled',
  }
  const providerOperator = {
    id: 'operator-fixture',
    email: 'operator@provider.probectl.test',
    name: 'Fixture Provider Operator',
    role: 'admin',
    status: 'active',
    enrolled: true,
  }
  // DPR-038: one operator request awaiting THIS tenant's decision.
  let pendingConsent = [
    {
      id: 'grant-fixture-1',
      operator_id: 'operator-fixture',
      operator_email: 'operator@provider.probectl.test',
      tenant_id: TENANT_ID,
      reason: 'INC-4821: cross-plane RCA for the checkout latency incident',
      scope: 'read',
      granted_by: 'operator@provider.probectl.test',
      granted_at: '2026-06-04T11:40:00Z',
      expires_at: '2026-06-04T12:40:00Z',
      use_count: 0,
    },
  ]
  let providerTenants = [
    {
      id: TENANT_ID,
      slug: 'acme-industries',
      name: 'Acme Industries',
      status: 'active',
      isolation_model: 'pooled',
    },
  ]

  return async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = String(init?.method ?? 'GET').toUpperCase()
    if (profile === 'cold') {
      const cold = coldFixture(path)
      if (cold) return cold
    }
    // SEC-001: the app resolves identity from /v1/me; serve a default
    // authenticated session so any screen renders as a signed-in operator.
    // Exclude the provider console's /provider/v1/me (different shape).
    if (path === '/v1/me')
      return jsonResponse({
        tenant_id: TENANT_ID,
        tenant_name: 'Acme Industries',
        tenant_slug: 'acme-industries',
        user_id: 'u_test',
        email: 'operator@probectl.test',
        display_name: 'Test Operator',
        mfa_satisfied: true,
        permissions: [
          'agent.write',
          'test.write',
          'directory.write',
          'incident.read',
          'incident.write',
          'ai.query',
          'metrics.read',
          'metrics.write',
        ],
      })
    if (path === '/v1/onboarding/progress') {
      const operational = firstTestCreated
      const producerReadiness = (
        id: string,
        state: 'ready' | 'quiet' | 'blocked',
        detail: string,
        nextAction: string,
      ) => ({ id, state, detail, next_action: nextAction })
      return jsonResponse({
        agent_enroll_token_created: enrollmentTokenCreated,
        agent_registered: operational,
        agent_connected: operational,
        producer_healthy: operational,
        first_test_created: firstTestCreated,
        first_result_received: operational,
        first_finding_visible: operational,
        scim_token_created: scimTokenCreated,
        readiness_steps_complete: operational ? 4 : 0,
        readiness_steps_total: 4,
        ...(operational
          ? {
              first_finding: {
                title: 'ICMP check healthy — 127.0.0.1',
                type: 'icmp',
                target: '127.0.0.1',
                success: true,
                observed_at: '2026-06-04T12:00:00Z',
                href: '/targets',
              },
            }
          : {}),
        producers: [
          producerReadiness(
            'synthetic',
            operational ? 'ready' : 'blocked',
            operational ? 'fixture producer heartbeat is current' : 'producer is not registered',
            operational ? '/targets' : '/onboarding#first-run-agent',
          ),
          ...['flow', 'bgp', 'device', 'ebpf', 'endpoint'].map((id) =>
            producerReadiness(
              id,
              'blocked',
              'fixture producer is not registered',
              `/admin?register_collector=${id}`,
            ),
          ),
        ],
        engines: [
          producerReadiness(
            'synthetic-results',
            operational ? 'ready' : 'quiet',
            operational ? 'fixture engine has tenant data' : 'engine is waiting for tenant data',
            '/targets',
          ),
        ],
      })
    }
    if (path === '/v1/agents/enroll-tokens' && method === 'POST') {
      enrollmentTokenCreated = true
      return jsonResponse(
        {
          token: 'pjt_fixture_only_not_a_real_secret',
          id: 'fixture-enrollment-token',
          tenant_id: TENANT_ID,
          expires_at: '2026-06-04T13:00:00Z',
          server_cert_pin: 'sha256:fixture-only-pin',
        },
        201,
      )
    }
    if (path === '/v1/tests' && method === 'POST') {
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : {}
      const created = {
        ...body,
        id: '10000000-0000-4000-8000-000000000099',
        tenant_id: TENANT_ID,
        created_at: '2026-06-04T12:00:00Z',
        updated_at: '2026-06-04T12:00:00Z',
      }
      fixtureTests = [...fixtureTests, created]
      firstTestCreated = true
      return jsonResponse(created, 201)
    }
    if (path === '/v1/directory/users' && method === 'POST') {
      const body = init?.body ? (JSON.parse(String(init.body)) as { email: string; display_name?: string; role?: string }) : { email: '' }
      const created = {
        id: `fixture-user-${fixtureDirectoryUsers.length + 1}`,
        tenant_id: '00000000-0000-0000-0000-000000000001',
        email: body.email.toLowerCase(),
        display_name: body.display_name || body.email,
        status: 'active',
        roles: body.role ? [body.role] : [],
        created_at: '2026-06-04T12:00:00Z',
        updated_at: '2026-06-04T12:00:00Z',
      }
      fixtureDirectoryUsers = [...fixtureDirectoryUsers, created]
      return jsonResponse(created, 201)
    }
    const bindMatch = /^\/v1\/directory\/users\/([^/]+)\/roles$/.exec(path)
    if (bindMatch && method === 'POST') {
      const body = init?.body ? (JSON.parse(String(init.body)) as { role: string }) : { role: '' }
      const user = fixtureDirectoryUsers.find((u) => u.id === bindMatch[1])
      if (!user) return jsonResponse({ error: { code: 'not_found', message: 'user not found' } }, 404)
      if (!user.roles.includes(body.role)) user.roles = [...user.roles, body.role].sort()
      return jsonResponse(user)
    }
    const unbindMatch = /^\/v1\/directory\/users\/([^/]+)\/roles\/([^/]+)$/.exec(path)
    if (unbindMatch && method === 'DELETE') {
      const user = fixtureDirectoryUsers.find((u) => u.id === unbindMatch[1])
      if (!user) return jsonResponse({ error: { code: 'not_found', message: 'user not found' } }, 404)
      if (unbindMatch[2] === 'admin' && fixtureDirectoryUsers.filter((u) => u.roles.includes('admin')).length === 1)
        return jsonResponse({ error: { code: 'conflict', message: 'cannot remove the last administrator of the tenant; grant another administrator first' } }, 409)
      user.roles = user.roles.filter((r) => r !== unbindMatch[2])
      return new Response(null, { status: 204 })
    }
    if (path === '/v1/directory/scim-tokens' && method === 'POST') {
      scimTokenCreated = true
      return jsonResponse(
        {
          id: 'fixture-scim-token',
          name: 'first-run-teammates',
          token: 'psc_fixture_only_not_a_real_secret',
          created_at: '2026-06-04T12:00:00Z',
        },
        201,
      )
    }
    if (path === '/v1/tests') return jsonResponse({ items: fixtureTests })
    if (path === '/v1/coverage/vantages')
      return jsonResponse({
        items: [
          {
            test_id: EDGE_DNS_TEST_ID,
            test_name: 'edge-dns',
            region: 'us-east',
            site: 'iad-1',
            agent_readiness: 'ready',
            agent_count: 1,
            ready_agent_count: 1,
            probe_family: 'dns',
            target: '1.1.1.1',
            last_evidence_at: '2026-06-04T12:00:00Z',
            independent_vantage_count: 1,
            stale_after_seconds: 300,
            status: 'non_redundant',
            execution_cadence: {
              state: 'on_cadence',
              reason: 'on_cadence',
              attribution: 'exact_test_id',
              configured_interval_seconds: 60,
              window_seconds: 360,
              expected_rounds: 6,
              observed_rounds: 6,
              missed_rounds: 0,
              max_gap_seconds: 60,
              observed_agent_count: 1,
              history_complete: true,
              current_assignment_verified: false,
            },
            next_action: {
              kind: 'author_test',
              label: 'Author another test',
              href: '/targets?create=test',
            },
          },
        ],
        as_of: '2026-06-04T12:00:00Z',
        evidence_running: true,
        candidate_limit: 5000,
        truncated: false,
      })
    if (path === '/v1/coverage/debt')
      return jsonResponse({
        items: [
          {
            entity_id: 'site:us-east:iad-1',
            entity_kind: 'site',
            label: 'iad-1',
            region: 'us-east',
            site: 'iad-1',
            plane: 'synthetic',
            state: 'covered',
            observed_at: '2026-06-04T12:00:00Z',
            evidence_age_seconds: 0,
            stale_after_seconds: 300,
            evidence_basis: 'latest_test_result',
            evidence_ref: `${EDGE_DNS_TEST_ID}/agent-a`,
            next_action: { kind: 'navigate', label: 'Inspect tests', href: '/targets' },
          },
          {
            entity_id: 'service:checkout',
            entity_kind: 'service',
            label: 'checkout',
            plane: 'flow',
            state: 'stale',
            observed_at: '2026-06-04T10:00:00Z',
            evidence_age_seconds: 7200,
            stale_after_seconds: 900,
            evidence_basis: 'topology_flow_edge',
            evidence_ref: 'service:checkout|flow|service:payments',
            next_action: { kind: 'navigate', label: 'Inspect topology', href: '/topology' },
          },
          {
            entity_id: 'service:checkout',
            entity_kind: 'service',
            label: 'checkout',
            plane: 'routing',
            state: 'unknown',
            stale_after_seconds: 900,
            evidence_basis: 'no_exact_entity_correlation',
            next_action: { kind: 'navigate', label: 'Inspect topology', href: '/topology' },
          },
        ],
        producers: [
          {
            plane: 'synthetic',
            registered_count: 2,
            runtime_running: true,
            evidence_count: 1,
            status: 'observed',
          },
          {
            plane: 'path',
            registered_count: 2,
            runtime_running: true,
            evidence_count: 0,
            status: 'idle',
          },
          {
            plane: 'flow',
            registered_count: 1,
            runtime_running: true,
            evidence_count: 1,
            status: 'observed',
          },
          {
            plane: 'routing',
            registered_count: 0,
            runtime_running: true,
            evidence_count: 0,
            status: 'unregistered',
          },
          {
            plane: 'device',
            registered_count: 0,
            runtime_running: true,
            evidence_count: 0,
            status: 'unregistered',
          },
        ],
        as_of: '2026-06-04T12:00:00Z',
        stale_after_seconds: 900,
        entity_limit: 500,
        candidate_limit: 5000,
        candidates_truncated: false,
        results_truncated: false,
        entities_truncated: false,
        topology_truncated: false,
        partial_reasons: [],
      })
    // UX-004: useAgents pages with ?after=&limit=; the query is dropped by
    // pathOf, so the exact path matches regardless. Return one (final) page.
    if (path === '/v1/agents')
      return jsonResponse({
        items: sampleAgents,
        control_version: '0.1.0',
        rollouts_available: true,
      })
    if (path === '/v1/rollouts') return jsonResponse({ items: [] })
    if (path === '/v1/dashboards') return jsonResponse({ items: [] })
    if (path === '/v1/dashboard-report-schedules')
      return jsonResponse({
        items: [],
        destinations: [
          {
            id: 'tenant-report-inbox',
            name: 'Tenant report inbox',
            kind: 'local',
            outbound: false,
            ready: true,
          },
        ],
        outbound_default: false,
      })
    if (path === '/v1/dashboard-report-artifacts') return jsonResponse({ items: [] })
    if (path === '/v1/ai/discover') return jsonResponse({ proposals: [] })
    if (path === '/v1/explorer/schema')
      return jsonResponse({
        templates: sampleExplorerTemplates,
        visualizations: ['table', 'bar', 'line', 'timeline', 'topology'],
        comparison_sources: ['flow', 'changes', 'topology', 'endpoints', 'tls'],
        max_rows: 500,
      })
    if (path === '/v1/explorer/compare') {
      const request = JSON.parse(String(init?.body)) as {
        query: {
          template?: string
          question: string
          source: string
          from: string
          to: string
          dimensions: string[]
          filters: Record<string, string>
          groupings: string[]
          measures: string[]
          visualization: string
          limit: number
        }
        previous_from: string
        previous_to: string
      }
      const template = sampleExplorerTemplates.find((item) => item.id === request.query.template)
      return jsonResponse({
        contract_version: 'explorer-comparison/v1',
        current: request.query,
        previous: {
          ...request.query,
          from: request.previous_from,
          to: request.previous_to,
        },
        current_preview: `FROM ${request.query.source} | TIME ${request.query.from} .. ${request.query.to}`,
        previous_preview: `FROM ${request.query.source} | TIME ${request.previous_from} .. ${request.previous_to}`,
        groupings: request.query.groupings,
        rows: request.query.measures.map((measure) => ({
          group: Object.fromEntries(
            request.query.groupings.map((grouping) => [grouping, `${grouping}-value`]),
          ),
          measure,
          aggregation: ['events', 'edges', 'affected_endpoints', 'bytes', 'usd'].includes(measure)
            ? 'sum'
            : 'mean',
          current_value: 14,
          previous_value: 7,
          delta: 7,
          percent_change: 100,
          delta_state: 'comparable',
        })),
        suggestions: Object.fromEntries(
          request.query.dimensions.map((key) => [key, [`${key}-value`]]),
        ),
        evidence_path: template?.evidence_path ?? '/explore',
        state: 'comparable',
        current_truncated: false,
        previous_truncated: false,
        rows_truncated: false,
        execution: {
          contract_version: 'explorer-comparison-execution/v1',
          tenant_scoped: true,
          current: explorerExecution(request.query, request.query.measures.length),
          previous: explorerExecution(
            {
              ...request.query,
              from: request.previous_from,
              to: request.previous_to,
            },
            request.query.measures.length,
          ),
          alignment: {
            row_limit: request.query.limit,
            returned_rows: request.query.measures.length,
            truncated: false,
            truncation_reason: 'none',
            elapsed_ms: 1,
          },
          total_ms: 7,
        },
      })
    }
    if (path === '/v1/explorer/query') {
      const query = JSON.parse(String(init?.body)) as {
        template?: string
        question: string
        source: string
        from: string
        to: string
        dimensions: string[]
        filters: Record<string, string>
        groupings: string[]
        measures: string[]
        visualization: string
        limit: number
      }
      // Timeline/line results carry a real time column (mirrors the server,
      // which adds the bucket timestamp for time visualizations) so the S11
      // TimeSeries upgrade path renders in the design loop.
      const wantsTime = query.visualization === 'line' || query.visualization === 'timeline'
      const makeRow = (index: number): Record<string, unknown> => {
        const row: Record<string, unknown> = {}
        if (wantsTime) row.occurred_at = `2026-06-04T1${index}:00:00Z`
        for (const dimension of query.dimensions) row[dimension] = `${dimension}-value`
        for (const measure of query.measures) row[measure] = (index + 1) * 7
        return row
      }
      const rows = wantsTime ? [makeRow(0), makeRow(1), makeRow(2)] : [makeRow(0)]
      const template = sampleExplorerTemplates.find((item) => item.id === query.template)
      return jsonResponse({
        query,
        preview: `FROM ${query.source} | GROUP BY ${query.groupings.join(', ')} | MEASURE ${query.measures.join(', ')} | VIEW ${query.visualization}`,
        columns: [
          ...(wantsTime ? [{ key: 'occurred_at', label: 'occurred at' }] : []),
          ...query.dimensions.map((key) => ({ key, label: key.replace(/_/g, ' ') })),
          ...query.measures.map((key) => ({ key, label: key.replace(/_/g, ' '), numeric: true })),
        ],
        rows,
        suggestions: Object.fromEntries(
          query.dimensions.map((key) => [key, [String(rows[0][key])]]),
        ),
        evidence_path: template?.evidence_path ?? '/explore',
        truncated: false,
        execution: explorerExecution(query, rows.length),
      })
    }
    if (path === '/v1/incidents') return jsonResponse({ items: [sampleIncident] })
    if (path === '/v1/changes') return jsonResponse({ items: [sampleChange] })
    if (path === '/v1/incidents/30000000-0000-4000-8000-000000000001')
      return jsonResponse(sampleIncident)
    if (path === '/v1/incidents/30000000-0000-4000-8000-000000000001/journal')
      return jsonResponse({ items: [], truncated: false, limit: 200 })
    if (path === '/v1/incidents/30000000-0000-4000-8000-000000000001/changes')
      return jsonResponse({
        items: [
          {
            event: sampleChange,
            score: 0.92,
            reason: 'same target and immediately before the first affected signal',
          },
        ],
      })
    if (path === '/v1/incidents/30000000-0000-4000-8000-000000000001/shares' && method === 'POST') {
      const request = typeof init?.body === 'string' ? JSON.parse(init.body) : {}
      return jsonResponse(
        {
          id: 'share_0123456789abcdef0123456789abcdef',
          incident: sampleIncident,
          context: {
            from: '2026-06-04T11:00:00Z',
            to: '2026-06-04T12:00:00Z',
            filters: {},
            ...(request.context ?? {}),
          },
          answer: { ...sampleAnswer, tenant: '' },
          created_at: '2026-06-04T12:06:00Z',
          expires_at: '2026-06-11T12:06:00Z',
        },
        201,
      )
    }
    if (path === '/v1/incident-shares/share_0123456789abcdef0123456789abcdef')
      return jsonResponse({
        id: 'share_0123456789abcdef0123456789abcdef',
        incident: sampleIncident,
        context: {
          from: '2026-06-04T11:00:00Z',
          to: '2026-06-04T12:00:00Z',
          filters: {},
        },
        answer: { ...sampleAnswer, tenant: '' },
        created_at: '2026-06-04T12:06:00Z',
        expires_at: '2026-06-11T12:06:00Z',
      })
    if (path === '/v1/alerts') return jsonResponse({ items: [] })
    if (path === '/v1/alerts/maintenance')
      return jsonResponse({ items: [], evaluator_running: true })
    if (path === '/v1/alerts/active')
      return jsonResponse({
        items: [
          {
            fingerprint: 'fp-dashboard',
            evaluation_fingerprint: 'eval:checkout-series',
            rule_id: '40000000-0000-4000-8000-000000000001',
            rule_name: 'checkout latency burn',
            severity: 'warning',
            metric: 'probectl_result_duration_ms',
            labels: { target: 'checkout', service: 'checkout' },
            value: 184,
            reason: 'p95 latency above objective',
            since: '2026-06-04T11:45:00Z',
            last_seen_at: '2026-06-04T12:00:00Z',
          },
        ],
        evaluator_running: true,
      })
    if (path === '/v1/alerts/40000000-0000-4000-8000-000000000001/evaluations')
      return jsonResponse({
        contract_version: 'probectl.alert-evaluations/v1',
        items: [
          {
            contract_version: 'probectl.alert-evaluation/v1',
            fingerprint: 'eval:checkout-series',
            rule_id: '40000000-0000-4000-8000-000000000001',
            rule_revision: '2026-06-04T11:00:00Z',
            state: 'firing',
            observed_at: '2026-06-04T12:00:00Z',
            observed_value: 184,
            expectation: { kind: 'threshold', comparison: 'gt', threshold: 150 },
            breach_count: 2,
            required_breaches: 2,
            reason: 'probectl_result_duration_ms=184 gt 150',
            labels: { target: 'checkout', service: 'checkout' },
          },
        ],
        truncated: false,
        limit: 64,
        freshness: 'current',
        latest_at: '2026-06-04T12:00:00Z',
        evaluator_running: true,
        persistence_running: true,
        retention: { max_per_series: 64, max_per_rule: 256, expires_days: 7 },
      })
    if (path === '/v1/tls/posture') return jsonResponse({ items: [], collector_running: true })
    // DPR-165: the Security page reads the detection catalogue, and the fixture
    // did not serve it — so J3 failed on a bare console 404 in a gate nobody had
    // run. Shapes follow ThreatRuleList/ThreatRule in the OpenAPI spec.
    if (path === '/v1/threat/rules')
      return jsonResponse({
        rules_running: true,
        overlay_dir: '', // only the embedded defaults are in force
        rules: [
          {
            id: 'ndr-beaconing-default',
            version: 3,
            kind: 'beaconing',
            name: 'Periodic beaconing to a low-reputation destination',
            description:
              'Regular, low-variance egress intervals to one destination, scored against the tenant own baseline.',
            severity: 'medium',
            enabled: true,
          },
          {
            id: 'ndr-dns-dga-default',
            version: 2,
            kind: 'dns_dga',
            name: 'Algorithmically generated domain lookups',
            description: 'High-entropy NXDOMAIN bursts from one host.',
            severity: 'high',
            enabled: true,
          },
          {
            id: 'ndr-egress-intel-default',
            version: 5,
            kind: 'egress_intel',
            name: 'Egress to a threat-intel indicator',
            description: 'An observed destination matches a loaded intel feed.',
            severity: 'high',
            enabled: true,
          },
        ],
      })
    if (path === '/v1/threat/intel/status') return jsonResponse(sampleIntelStatus)
    if (path === '/v1/threat/detections')
      return jsonResponse({
        items: [
          {
            id: 'det-dashboard',
            kind: 'ioc_match',
            plane: 'threat',
            severity: 'warning',
            confidence: 82,
            source: 'test-intel',
            category: 'scanner',
            indicator: '10.0.0.20',
            entity: '10.0.0.20',
            title: 'Known scanner contact',
            summary: 'Flow evidence matched a locally cached threat-intel indicator.',
            observed_at: '2026-06-04T12:00:00Z',
            incident_id: INCIDENT_ID,
          },
        ],
        detections_running: true,
      })
    if (path === '/v1/remediation/proposals' && method === 'GET')
      return jsonResponse({ items: remediationProposals, approvals_enabled: false })
    if (path === '/v1/remediation/proposals' && method === 'POST') {
      const request = typeof init?.body === 'string' ? JSON.parse(init.body) : {}
      const created = {
        id: 'remediation-fixture-1',
        tenant_id: TENANT_ID,
        ...request,
        dry_run: {
          blast_radius: 0,
          note: 'Fixture proposal records human review only; no executor exists.',
        },
        state: 'proposed',
        proposed_by: 'user:operator@probectl.test',
        created_at: '2026-06-04T12:06:00Z',
      }
      remediationProposals = [...remediationProposals, created]
      return jsonResponse(created, 201)
    }
    if (path === '/v1/endpoints')
      return jsonResponse({
        items: [
          {
            agent_id: 'endpoint-1',
            last_seen_at: '2026-06-04T12:00:00Z',
            cause: 'none',
            summary: 'healthy last-mile path',
            confidence: 0.93,
            slow: false,
          },
        ],
        collector_running: true,
      })
    if (path === '/v1/results/latest')
      return jsonResponse({ items: sampleLatestResults, collector_running: true })
    if (path === '/v1/device/identity-conflicts')
      return jsonResponse({
        items: [
          {
            id: 'identity:device_name:MTAuMC4wLjE',
            kind: 'device_name',
            subject: '10.0.0.1',
            status: 'active',
            confidence: 'high',
            basis: 'distinct_values_for_one_tenant_local_identity_key',
            first_seen: '2026-06-04T11:55:00Z',
            last_seen: '2026-06-04T12:00:00Z',
            claims: [
              {
                value: 'edge-r1',
                source: 'snmp',
                agent_id: 'device-snmp-1',
                basis: 'device.metric.device_name',
                first_seen: '2026-06-04T11:55:00Z',
                last_seen: '2026-06-04T12:00:00Z',
                age_seconds: 0,
                freshness: 'fresh',
              },
              {
                value: 'edge-router-1',
                source: 'gnmi',
                agent_id: 'device-gnmi-1',
                basis: 'device.metric.device_name',
                first_seen: '2026-06-04T11:56:00Z',
                last_seen: '2026-06-04T11:59:00Z',
                age_seconds: 60,
                freshness: 'fresh',
              },
            ],
            affected_correlations: [
              {
                plane: 'topology',
                kind: 'device_node',
                ref: 'device:10.0.0.1',
                reason: 'Device label attribution may name the wrong node.',
                href: '/topology?topo_q=10.0.0.1',
              },
              {
                plane: 'flow',
                kind: 'exporter',
                ref: '10.0.0.1',
                reason: 'Exporter attribution may inherit the wrong device name.',
                href: '/topology?topo_q=10.0.0.1',
              },
            ],
            review_proposal: {
              mode: 'read_only',
              instruction:
                'Compare source ownership and freshness, then correct the authoritative producer outside probectl.',
              merge_supported: false,
            },
          },
        ],
        topology_running: true,
        as_of: '2026-06-04T12:00:00Z',
        stale_after_seconds: 3600,
        effective_limit: 100,
        filtered_count: 1,
        store_truncated: false,
        response_truncated: false,
        truncated: false,
        partial_reasons: [],
      })
    if (path === '/v1/device/neighbors')
      return jsonResponse({
        contract_version: 'probectl.device-neighbors/v1',
        items: [
          {
            id: 'neighbor:0123456789abcdef01234567',
            agent_id: 'device-agent-1',
            local_device_address: '10.0.0.1',
            local_device_name: 'edge-r1',
            local_if_index: 1,
            local_port_id: 'Gi0/1',
            remote_chassis_id: '00:11:22:33:44:55',
            remote_device_name: 'leaf-1',
            remote_port_id: 'Ethernet1',
            remote_platform: 'switch-os',
            capabilities: ['bridge', 'router'],
            protocol: 'lldp',
            confidence: 0.95,
            observed_at: '2026-06-04T12:00:00Z',
            fresh_until: '2026-06-04T12:02:00Z',
            freshness: 'current',
            age_seconds: 0,
          },
        ],
        collection_running: true,
        effective_limit: 100,
        truncated: false,
        as_of: '2026-06-04T12:00:00Z',
        latest_at: '2026-06-04T12:00:00Z',
        retention: { max_per_device: 256, max_per_tenant: 16384, stale_retention_hours: 24 },
      })
    if (path === '/v1/device/collection-outcomes')
      return jsonResponse({
        contract_version: 'probectl.device-collection-outcomes/v1',
        items: [
          {
            agent_id: 'device-agent-1',
            configured_target: 'edge-r1.internal',
            protocol: 'lldp',
            last_attempt_at: '2026-06-04T12:00:00Z',
            last_success_at: '2026-06-04T11:55:00Z',
            state: 'failed',
            reason: 'poll_failed',
            row_count: 0,
            next_action: 'verify_configured_target_access',
          },
          {
            agent_id: 'device-agent-1',
            configured_target: 'edge-r1.internal',
            protocol: 'cdp',
            last_attempt_at: '2026-06-04T12:00:00Z',
            last_success_at: '2026-06-04T12:00:00Z',
            state: 'healthy_empty',
            reason: 'no_rows_observed',
            row_count: 0,
            next_action: 'review_target_neighbor_configuration',
          },
        ],
        collection_running: true,
        effective_limit: 100,
        truncated: false,
        as_of: '2026-06-04T12:00:00Z',
        retention: { max_per_tenant: 4096, retention_days: 30 },
      })
    if (path === '/v1/flows/ingest-quality')
      return jsonResponse({
        contract_version: 'probectl.flow-ingest-quality/v1',
        items: [
          {
            agent_id:
              'flow-agent-at-a-very-long-sovereign-site-name-that-must-wrap-without-overflow',
            exporter_address: '2001:db8:100:200::1234',
            protocol: 'ipfix',
            window_started_at: '2026-06-04T11:59:00Z',
            window_ended_at: '2026-06-04T12:00:00Z',
            last_packet_at: '2026-06-04T11:59:58Z',
            last_valid_record_at: '2026-06-04T11:59:58Z',
            packets_received: 128,
            records_decoded: 2048,
            decode_error_packets: 0,
            template_misses: 0,
            queue_dropped_records: 0,
            emit_dropped_records: 0,
            template_state: 'ready',
            sampling_state: 'sampled',
            state: 'healthy',
            reason: 'receiving_valid_records',
            next_action: 'continue_monitoring',
          },
          {
            agent_id: 'flow-agent-1',
            exporter_address: '192.0.2.44',
            protocol: 'netflow9',
            window_started_at: '2026-06-04T11:59:00Z',
            window_ended_at: '2026-06-04T12:00:00Z',
            last_packet_at: '2026-06-04T11:59:57Z',
            last_valid_record_at: null,
            packets_received: 9,
            records_decoded: 0,
            decode_error_packets: 0,
            template_misses: 9,
            queue_dropped_records: 0,
            emit_dropped_records: 0,
            template_state: 'missing',
            sampling_state: 'unknown',
            state: 'degraded',
            reason: 'template_missing',
            next_action: 'verify_exporter_templates',
          },
        ],
        ingest_running: true,
        effective_limit: 100,
        truncated: false,
        as_of: '2026-06-04T12:00:00Z',
        stale_after_seconds: 180,
        retention: { max_per_tenant: 4096, retention_days: 30 },
      })
    if (path === '/v1/device/syslog')
      return jsonResponse({
        items: [
          {
            id: 'syslog-1',
            device: 'edge-r1',
            severity_text: 'warning',
            message: 'Interface Gi0/1 down',
            observed_at: '2026-06-04T12:00:00Z',
          },
        ],
        syslog_running: true,
      })
    if (path === '/v1/device/configs')
      return jsonResponse({
        items: [
          {
            id: 'config-2',
            device: 'edge-r1',
            source: 'running-config',
            version: 2,
            content:
              'hostname edge-r1\ninterface Gi0/1\n description payments uplink\n no shutdown\nsnmp-server community [REDACTED]',
            content_hash: '0123456789abcdef',
            previous_hash: 'abcdef0123456789',
            drifted: true,
            archived_at: '2026-06-04T12:00:00Z',
          },
          {
            id: 'config-1',
            device: 'edge-r1',
            source: 'running-config',
            version: 1,
            content:
              'hostname edge-r1\ninterface Gi0/1\n description checkout uplink\n shutdown\nsnmp-server community [REDACTED]',
            content_hash: 'abcdef0123456789',
            drifted: false,
            archived_at: '2026-06-03T12:00:00Z',
          },
        ],
        archive_running: true,
        redaction_policy: 'device-secrets-v1',
      })
    if (path === '/v1/topology')
      return jsonResponse({
        topology_running: true,
        at: '2026-06-04T12:00:00Z',
        nodes: [
          { id: 'as:64500', kind: 'as', label: 'AS64500' },
          { id: 'prefix:203.0.113.0/24', kind: 'prefix', label: '203.0.113.0/24' },
          { id: 'service:checkout', kind: 'service', label: 'checkout' },
          { id: 'service:payments', kind: 'service', label: 'payments' },
          { id: 'device:10.0.0.1', kind: 'device', label: 'edge-r1' },
          {
            id: 'device:lldp:00:11:22:33:44:55',
            kind: 'device',
            label: 'leaf-1',
          },
          { id: 'hop:10.0.0.1', kind: 'hop', label: '10.0.0.1' },
        ],
        edges: [
          { from: 'as:64500', to: 'prefix:203.0.113.0/24', kind: 'routing' },
          { from: 'service:checkout', to: 'service:payments', kind: 'flow', label: 'http' },
          { from: 'device:10.0.0.1', to: 'hop:10.0.0.1', kind: 'device' },
          {
            from: 'device:10.0.0.1',
            to: 'device:lldp:00:11:22:33:44:55',
            kind: 'physical',
            label: 'Gi0/1 ↔ Ethernet1',
          },
        ],
        coverage: {
          path_edges: 0,
          flow_edges: 1,
          routing_edges: 1,
          device_edges: 1,
          physical_edges: 1,
        },
      })
    if (path === '/v1/inventory/views') return jsonResponse({ items: [] })
    if (path === '/v1/results/history')
      return jsonResponse({
        collector_running: true,
        window: '1h0m0s',
        items: [18, 21, 24, 20, 31, 26].map((duration, index) => ({
          agent_id: AGENT_ID,
          type: 'http',
          target: 'https://checkout.probectl.test',
          success: true,
          duration_ms: duration,
          metrics: { 'http.total.ms': duration },
          observed_at: [
            '2026-06-04T11:10:00Z',
            '2026-06-04T11:20:00Z',
            '2026-06-04T11:30:00Z',
            '2026-06-04T11:40:00Z',
            '2026-06-04T11:50:00Z',
            '2026-06-04T12:00:00Z',
          ][index],
        })),
      })
    if (
      path === '/v1/tests/10000000-0000-4000-8000-000000000001/path' &&
      (init?.method ?? 'GET') === 'GET'
    )
      return jsonResponse(samplePath(true))
    if (path === '/v1/tests/10000000-0000-4000-8000-000000000001/path/history')
      return jsonResponse({ items: samplePathRounds })
    if (path === '/v1/ai/ask' && init?.method === 'POST') {
      const request =
        typeof init.body === 'string' ? (JSON.parse(init.body) as { question?: string }) : {}
      return jsonResponse({ ...sampleAnswer, question: request.question ?? '' })
    }
    if (path === '/v1/topology/whatif' && init?.method === 'POST') {
      const request =
        typeof init.body === 'string' ? (JSON.parse(init.body) as { target?: string }) : {}
      const target = request.target ?? 'service:checkout'
      return jsonResponse({
        target,
        target_kind: target.split(':')[0] ?? 'service',
        at: '2026-06-04T12:00:00Z',
        broken_paths: [
          {
            from: 'service:checkout',
            to: 'service:payments',
            status: 'broken',
            route: ['service:checkout', 'service:payments'],
          },
        ],
        rerouted_paths: [],
        impacted_tests: [{ agent_id: AGENT_ID, target: 'api.example.com:443', status: 'broken' }],
        impacted_services: ['payments'],
        impacted_prefixes: [],
        disconnected: ['service:payments'],
        impacted_slos: ['slo:checkout-availability'],
        coverage: { path_edges: 0, flow_edges: 1, routing_edges: 1, device_edges: 1 },
        confidence: {
          level: 'medium',
          score: 62,
          basis: 'Flow edges observed in the last hour; no path-plane coverage.',
        },
      })
    }
    if (path === '/v1/flows/top') return jsonResponse(flowFixtureTop(input))
    if (path === '/v1/flows/capacity')
      return jsonResponse({
        items: [
          {
            ts: '2026-06-04T12:00:00Z',
            exporter: 'edge-r1',
            iface: 1,
            bps: 85_000_000,
            pps: 12_000,
          },
        ],
      })
    if (path === '/v1/flows/anomalies')
      return jsonResponse({
        items: [
          {
            exporter: 'edge-r1',
            iface: 1,
            ts: '2026-06-04T12:00:00Z',
            current_bps: 85_000_000,
            baseline_bps: 35_000_000,
            stddev_bps: 8_000_000,
            sigma: 6.2,
            model: 'local-zscore-v1',
            training_window: {
              start: '2026-06-04T11:15:00Z',
              end: '2026-06-04T11:55:00Z',
              samples: 9,
            },
            feature_citations: [
              {
                ref: 'flow:capacity:edge-r1:if1:1780574400',
                plane: 'flow',
                source: 'edge-r1',
                metric: 'bps',
              },
            ],
            features: {
              'flow.bps': 85_000_000,
              'flow.pps': 12_000,
            },
          },
        ],
      })
    if (path === '/v1/cost/summary')
      return jsonResponse({
        cost_running: true,
        summary: {
          priced: true,
          zones_mapped: true,
          pricing_source: 'test',
          pricing_as_of: '2026-06-01',
          total_bytes: 17 * 2 ** 30,
          total_usd: 0.38,
          by_class: { inter_az: { bytes: 10 * 2 ** 30, usd: 0.1 } },
          by_service: { checkout: { bytes: 12 * 2 ** 30, usd: 0.38 } },
          by_team: { payments: { bytes: 12 * 2 ** 30, usd: 0.38 } },
          chatty_pairs: [],
          trend: [
            { hour: '2026-06-04T10:00:00Z', bytes: 4 * 2 ** 30, usd: 0.08 },
            { hour: '2026-06-04T11:00:00Z', bytes: 7 * 2 ** 30, usd: 0.16 },
            { hour: '2026-06-04T12:00:00Z', bytes: 17 * 2 ** 30, usd: 0.38 },
          ],
          budgets: [
            { kind: 'team', name: 'payments', monthly_usd: 500, spent_usd: 0.38, exceeded: false },
          ],
        },
      })
    if (path === '/v1/slos')
      return jsonResponse({
        slo_running: true,
        items: [
          {
            name: 'checkout-availability',
            display_name: 'Checkout availability',
            service: 'checkout',
            team: 'payments',
            objective: 0.99,
            window: '30d',
            attainment: 0.982,
            error_budget_remaining: 0.12,
            total_events: 300,
            cold_start: false,
            burn_rates: [
              {
                window: 'fast',
                long: '1h0m0s',
                short: '5m0s',
                burn: 16.2,
                limit: 14.4,
                firing: true,
              },
            ],
          },
        ],
      })
    if (path === '/v1/compliance')
      return jsonResponse({
        compliance_running: true,
        items: [
          {
            policy: 'pci-east-west',
            rule_id: 'deny-checkout-db',
            description: 'Checkout must not talk directly to cardholder database',
            from: 'checkout',
            to: 'cardholder-db',
            ports: '5432',
            verdict: 'violation',
            violations: 2,
            observed_pairs: 1,
          },
        ],
        coverage: {
          flow_observed: true,
          ebpf_observed: true,
          observations: 3,
          zones_seen: 2,
          zones_total: 2,
          notes: [],
        },
      })
    if (path === '/v1/outages')
      return jsonResponse({
        outage_running: true,
        feeds_enabled: false,
        scope_resolution: false,
        events: [],
        vantage_events: [],
        coverage_notes: [
          'coverage = your vantage points + public open-data feeds — probectl does not operate a global probe fleet',
        ],
      })
    if (path === '/v1/rum') return jsonResponse({ rum_running: false })
    if (path === '/v1/carbon')
      return jsonResponse({
        carbon_running: true,
        summary: {
          total_bytes: 12 * 2 ** 30,
          total_kwh: 0.22,
          total_gco2e: 88,
          by_class: { inter_az: { bytes: 10 * 2 ** 30, kwh: 0.1, gco2e: 40 } },
          by_service: { checkout: { bytes: 10 * 2 ** 30, kwh: 0.1, gco2e: 40 } },
          by_team: { payments: { bytes: 10 * 2 ** 30, kwh: 0.1, gco2e: 40 } },
          trend: [],
          methodology: {
            measured: false,
            grid_gco2e_per_kwh: 400,
            source: 'fixture coefficient model',
            note: 'coefficient-based estimate; not measured device power',
          },
        },
      })
    if (path === '/v1/secrets/health')
      return jsonResponse({
        resolver_running: true,
        backends: [{ scheme: 'env', configured: true, resolves: 0, failures: 0, cached_leases: 0 }],
      })
    if (path === '/v1/identity/settings')
      return jsonResponse({
        source: 'environment',
        configured: true,
        valid: true,
        issuer: 'https://idp.probectl.test',
        client_id: 'probectl-fixture',
        client_secret_configured: true,
        redirect_url: 'https://probectl.test/auth/callback',
        scopes: ['openid', 'email', 'profile'],
        enabled: true,
        flags: {},
      })
    if (path === '/v1/directory/scim-tokens') return jsonResponse({ items: [] })
    if (path === '/v1/directory/users')
      return jsonResponse({ items: fixtureDirectoryUsers, total: fixtureDirectoryUsers.length })
    if (path === '/v1/directory/roles') return jsonResponse({ items: fixtureDirectoryRoles })
    if (path === '/v1/abac/policies') return jsonResponse({ items: [] })
    if (path === '/v1/diagnostics')
      return jsonResponse({
        status: 'degraded',
        checked_at: '2026-06-06T00:00:00Z',
        self_metrics: {
          goroutines: 12,
          mem_alloc_bytes: 1_048_576,
          mem_sys_bytes: 8_388_608,
          num_gc: 9,
          uptime_seconds: 7200,
          max_procs: 8,
        },
        build: {
          version: '1.1.0',
          commit: 'abc1234',
          date: '2026-06-05T12:00:00Z',
          go_version: 'go1.26.0',
          os: 'linux',
          arch: 'arm64',
        },
        checks: [
          { name: 'database', status: 'ok' },
          {
            name: 'cluster',
            status: 'degraded',
            detail: 'writes are fenced while the local writer is not usable',
            finding: {
              id: 'readiness.cluster',
              component: 'cluster',
              scope: 'deployment',
              severity: 'warning',
              observed_at: '2026-06-06T00:00:00Z',
              summary: 'Control-plane writes are temporarily fenced',
              evidence:
                'The local cluster check cannot prove that the configured writer is the current writable primary.',
              next_action: {
                label: 'Download redacted support bundle',
                href: '/v1/diagnostics/bundle',
                kind: 'download',
              },
            },
          },
        ],
      })
    if (path === '/branding') return jsonResponse({ product_name: 'probectl' })
    if (path === '/v1/security/keys')
      return jsonResponse({
        items: [
          {
            version: 1,
            mode: 'managed',
            state: 'active',
            created_at: '2026-06-04T12:00:00Z',
          },
        ],
      })
    if (path === '/v1/lifecycle/retention' && method === 'PUT') {
      const request = typeof init?.body === 'string' ? JSON.parse(init.body) : {}
      lifecycleRetention = { ...lifecycleRetention, ...request }
      return jsonResponse(lifecycleRetention)
    }
    if (path === '/v1/lifecycle/retention') return jsonResponse(lifecycleRetention)
    if (path === '/v1/editions')
      return jsonResponse({
        tier: 'core',
        state: 'community',
        features: [
          { name: 'fips', tier: 'enterprise', licensed: false, mode: 'off' },
          { name: 'byok', tier: 'enterprise', licensed: false, mode: 'off' },
          { name: 'governance', tier: 'enterprise', licensed: false, mode: 'off' },
          { name: 'remediation', tier: 'enterprise', licensed: false, mode: 'off' },
          {
            name: 'ha_support',
            display_name: 'HA support/SLA',
            tier: 'enterprise',
            licensed: false,
            mode: 'off',
          },
          { name: 'siloed_isolation', tier: 'enterprise', licensed: false, mode: 'off' },
          { name: 'provider_plane', tier: 'msp', licensed: false, mode: 'off' },
          { name: 'metering', tier: 'msp', licensed: false, mode: 'off' },
        ],
      })
    if (options.providerPlane && path === '/provider/v1/me')
      return jsonResponse({ operator: providerOperator })
    if (options.providerPlane && path === '/provider/v1/license')
      return jsonResponse({
        tier: 'msp',
        state: 'active',
        customer: 'Fixture MSP',
        tenant_band: 25,
      })
    if (options.providerPlane && path === '/provider/v1/tenants' && method === 'GET')
      return jsonResponse({ items: providerTenants })
    if (options.providerPlane && path === '/provider/v1/tenants' && method === 'POST') {
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : {}
      const created = {
        ...body,
        id: '00000000-0000-4000-8000-000000000099',
        status: 'active',
      }
      providerTenants = [...providerTenants, created]
      return jsonResponse(created, 201)
    }
    // DPR-165: the provider console's activity section reads its own
    // hash-chained operator stream. Missing from the fixture, so J4 failed the
    // same way J3 did. Shape per ee/provider/openapi.json: items with
    // seq/actor/action/target/data/prev_hash/hash/created_at, plus a cursor.
    if (options.providerPlane && path === '/provider/v1/audit') {
      const rows = [
        { seq: 3, actor: 'ops@probectl.example', action: 'provider.tenant.provision', target: 'globex-eu' },
        { seq: 2, actor: 'ops@probectl.example', action: 'provider.operator.login', target: 'ops@probectl.example' },
        { seq: 1, actor: 'system:bootstrap', action: 'provider.bootstrap', target: 'provider-plane' },
      ]
      return jsonResponse({
        items: rows.map((row, index) => ({
          ...row,
          data: {},
          // A chain a reader can actually follow: each row names its
          // predecessor, oldest first has none.
          prev_hash: index === rows.length - 1 ? '' : `sha256:fixture-${row.seq - 1}`,
          hash: `sha256:fixture-${row.seq}`,
          created_at: new Date(Date.UTC(2026, 0, 1, 9, 30 + row.seq)).toISOString(),
        })),
        next: 1,
        order: 'desc',
      })
    }
    if (options.providerPlane && path === '/provider/v1/fleet')
      return jsonResponse({
        items: providerTenants.map((tenant) => ({
          tenant_id: tenant.id,
          tenant_slug: tenant.slug,
          tenant_name: tenant.name,
          tenant_status: tenant.status,
          agents_total: tenant.id === TENANT_ID ? 3 : 0,
          agents_online: tenant.id === TENANT_ID ? 2 : 0,
          agents_stale: tenant.id === TENANT_ID ? 1 : 0,
          versions: tenant.id === TENANT_ID ? { '0.1.0': 3 } : {},
        })),
      })
    if (options.providerPlane && path === '/provider/v1/breakglass')
      return jsonResponse({ items: [] })
    if (options.providerPlane && path === '/provider/v1/consent')
      return jsonResponse({ items: pendingConsent })
    if (options.providerPlane && path.startsWith('/provider/v1/consent/') && method === 'POST') {
      const id = path.slice('/provider/v1/consent/'.length)
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : {}
      const grant = pendingConsent.find((g) => g.id === id)
      if (!grant) return jsonResponse({ error: { code: 'not_found', message: 'grant not found' } }, 404)
      if (body.decision !== 'approve' && body.decision !== 'deny')
        return jsonResponse({ error: { code: 'bad_request', message: 'decision must be approve or deny' } }, 400)
      pendingConsent = pendingConsent.filter((g) => g.id !== id)
      const decidedAt = '2026-06-04T11:45:00Z'
      return jsonResponse(
        body.decision === 'approve'
          ? { ...grant, consented_by: 'admin@probectl.test', consented_at: decidedAt }
          : { ...grant, denied_by: 'admin@probectl.test', denied_at: decidedAt },
      )
    }
    if (options.providerPlane && path === '/provider/v1/fairness')
      return jsonResponse({ items: [] })
    if (options.providerPlane && path === '/provider/v1/operators')
      return jsonResponse({ items: [providerOperator] })
    if (
      options.providerPlane &&
      (path === '/provider/v1/usage' || path.startsWith('/provider/v1/usage/'))
    )
      return jsonResponse({
        items: providerTenants.map((tenant) => ({
          tenant_id: tenant.id,
          tenant_slug: tenant.slug,
          meter: 'agents',
          kind: 'gauge',
          period_start: '2026-06-01T00:00:00Z',
          period_end: '2026-06-04T12:00:00Z',
          value: tenant.id === TENANT_ID ? 3 : 0,
          unit: 'count',
        })),
      })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }
}

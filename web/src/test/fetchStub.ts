import { vi } from 'vitest'

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const sampleTests = [
  {
    id: 't1',
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
    id: 't2',
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
    id: 'a1',
    name: 'agent-1',
    hostname: 'host-a',
    agent_version: '0.1.0',
    status: 'online',
    capabilities: ['icmp', 'tcp', 'flow', 'device', 'ebpf', 'endpoint'],
  },
]

const sampleIncident = {
  id: 'inc-dashboard',
  tenant_id: '00000000-0000-0000-0000-000000000001',
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
    agent_id: 'a1',
    type: 'dns',
    target: '1.1.1.1',
    success: true,
    duration_ms: 21,
    metrics: { 'dns.query.ms': 21 },
    observed_at: '2026-06-04T12:00:00Z',
  },
  {
    agent_id: 'a1',
    type: 'http',
    target: 'https://checkout.probectl.test',
    success: true,
    duration_ms: 184,
    metrics: { 'http.total.ms': 184, 'http.status': 200 },
    observed_at: '2026-06-04T12:00:00Z',
  },
  {
    agent_id: 'a1',
    type: 'dns',
    target: 'checkout.probectl.test',
    success: true,
    duration_ms: 18,
    metrics: { 'dns.query.ms': 18 },
    observed_at: '2026-06-04T12:00:00Z',
  },
]

/**
 * pathOf parses a fetched URL to its PATHNAME (no query, no origin) so stub
 * routes match by exact path, not substring. RED-006/UX-006: matching with
 * url.endsWith()/url.includes() let a double-prefixed '/v1/v1/topology' satisfy
 * a '/v1/topology' route and render green despite the bug. Exact-pathname
 * matching plus the assertNoDoublePrefix guard below close that.
 */
export function pathOf(input: RequestInfo | URL): string {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : String(input)
  // Resolve against a dummy origin so relative paths ('/v1/me') parse too.
  return new URL(raw, 'http://t.invalid').pathname
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

/** A read-only default fetch covering the list endpoints, so any screen renders
 *  with data in tests. CRUD tests install their own stateful stub. */
export function defaultFetch(): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    // SEC-001: the app resolves identity from /v1/me; serve a default
    // authenticated session so any screen renders as a signed-in operator.
    // Exclude the provider console's /provider/v1/me (different shape).
    if (path === '/v1/me')
      return jsonResponse({
        tenant_id: '00000000-0000-0000-0000-000000000001',
        user_id: 'u_test',
        email: 'operator@probectl.test',
        display_name: 'Test Operator',
        mfa_satisfied: true,
        permissions: [],
      })
    if (path === '/v1/tests') return jsonResponse({ items: sampleTests })
    // UX-004: useAgents pages with ?after=&limit=; the query is dropped by
    // pathOf, so the exact path matches regardless. Return one (final) page.
    if (path === '/v1/agents') return jsonResponse({ items: sampleAgents })
    if (path === '/v1/ai/discover') return jsonResponse({ proposals: [] })
    if (path === '/v1/incidents') return jsonResponse({ items: [sampleIncident] })
    if (path === '/v1/incidents/inc-dashboard') return jsonResponse(sampleIncident)
    if (path === '/v1/alerts') return jsonResponse({ items: [] })
    if (path === '/v1/alerts/maintenance')
      return jsonResponse({ items: [], evaluator_running: true })
    if (path === '/v1/alerts/active')
      return jsonResponse({
        items: [
          {
            fingerprint: 'fp-dashboard',
            rule_id: 'r-dashboard',
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
    if (path === '/v1/tls/posture') return jsonResponse({ items: [], collector_running: true })
    if (path === '/v1/threat/intel/status') return jsonResponse(sampleIntelStatus)
    if (path === '/v1/threat/detections')
      return jsonResponse({
        items: [
          {
            id: 'det-dashboard',
            kind: 'ioc_match',
            plane: 'threat',
            severity: 'warning',
            confidence: 0.82,
            source: 'test-intel',
            category: 'scanner',
            indicator: '10.0.0.20',
            entity: '10.0.0.20',
            title: 'Known scanner contact',
            summary: 'Flow evidence matched a locally cached threat-intel indicator.',
            observed_at: '2026-06-04T12:00:00Z',
          },
        ],
        detections_running: true,
      })
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
          { id: 'hop:10.0.0.1', kind: 'hop', label: '10.0.0.1' },
        ],
        edges: [
          { from: 'as:64500', to: 'prefix:203.0.113.0/24', kind: 'routing' },
          { from: 'service:checkout', to: 'service:payments', kind: 'flow', label: 'http' },
          { from: 'device:10.0.0.1', to: 'hop:10.0.0.1', kind: 'device' },
        ],
        coverage: { path_edges: 0, flow_edges: 1, routing_edges: 1, device_edges: 1 },
      })
    if (path === '/v1/flows/top')
      return jsonResponse({
        items: [
          {
            key: '10.0.0.10',
            detail: 'checkout',
            bytes: 524_288_000,
            packets: 120_000,
            flows: 42,
          },
          {
            key: '10.0.0.20',
            detail: 'payments',
            bytes: 104_857_600,
            packets: 22_400,
            flows: 18,
          },
        ],
        effective_limit: 8,
        window: '1h',
      })
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
    if (path === '/v1/carbon') return jsonResponse({ carbon_running: false })
    if (path === '/v1/secrets/health')
      return jsonResponse({
        resolver_running: true,
        backends: [{ scheme: 'env', configured: true, resolves: 0, failures: 0, cached_leases: 0 }],
      })
    if (path === '/v1/directory/scim-tokens') return jsonResponse({ items: [] })
    if (path === '/v1/abac/policies') return jsonResponse({ items: [] })
    if (path === '/v1/diagnostics')
      return jsonResponse({
        status: 'degraded',
        checked_at: '2026-06-06T00:00:00Z',
        checks: [
          { name: 'database', status: 'ok' },
          {
            name: 'cluster',
            status: 'degraded',
            detail: 'writer endpoint points at a read-only standby (failover in progress)',
          },
        ],
      })
    if (path === '/branding') return jsonResponse({ product_name: 'probectl' })
    if (path === '/v1/security/keys') return jsonResponse({ error: { message: 'not found' } }, 404)
    if (path === '/v1/lifecycle/retention')
      return jsonResponse({ flow_retention_days: null, isolation_model: 'pooled' })
    if (path === '/v1/editions')
      return jsonResponse({
        tier: 'community',
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
          { name: 'provider_plane', tier: 'provider', licensed: false, mode: 'off' },
          { name: 'siloed_isolation', tier: 'provider', licensed: false, mode: 'off' },
          { name: 'metering', tier: 'provider', licensed: false, mode: 'off' },
          { name: 'white_label', tier: 'provider', licensed: false, mode: 'off' },
        ],
      })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  })
}

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
    capabilities: ['icmp', 'tcp'],
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
    if (path === '/v1/alerts') return jsonResponse({ items: [] })
    if (path === '/v1/alerts/active') return jsonResponse({ items: [], evaluator_running: true })
    if (path === '/v1/tls/posture') return jsonResponse({ items: [], collector_running: true })
    if (path === '/v1/threat/detections')
      return jsonResponse({ items: [], detections_running: true })
    if (path === '/v1/endpoints') return jsonResponse({ items: [], collector_running: true })
    if (path === '/v1/results/latest') return jsonResponse({ items: [], collector_running: true })
    if (path === '/v1/topology')
      return jsonResponse({
        topology_running: true,
        at: '2026-06-04T12:00:00Z',
        nodes: [],
        edges: [],
        coverage: { path_edges: 0, flow_edges: 0, routing_edges: 0, device_edges: 0 },
      })
    if (path === '/v1/cost/summary')
      return jsonResponse({
        cost_running: true,
        summary: {
          priced: true,
          zones_mapped: true,
          pricing_source: 'test',
          pricing_as_of: '2026-06-01',
          total_bytes: 0,
          total_usd: 0,
          by_class: {},
          by_service: {},
          by_team: {},
          chatty_pairs: [],
          trend: [],
          budgets: [],
        },
      })
    if (path === '/v1/slos') return jsonResponse({ slo_running: true, items: [] })
    if (path === '/v1/compliance')
      return jsonResponse({
        compliance_running: true,
        items: [],
        coverage: {
          flow_observed: false,
          ebpf_observed: false,
          observations: 0,
          zones_seen: 0,
          zones_total: 0,
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
          { name: 'ha_support', tier: 'enterprise', licensed: false, mode: 'off' },
          { name: 'provider_plane', tier: 'provider', licensed: false, mode: 'off' },
          { name: 'siloed_isolation', tier: 'provider', licensed: false, mode: 'off' },
          { name: 'metering', tier: 'provider', licensed: false, mode: 'off' },
          { name: 'white_label', tier: 'provider', licensed: false, mode: 'off' },
        ],
      })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  })
}

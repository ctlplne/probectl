import { vi } from 'vitest'

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const sampleTests = [
  {
    id: 't1', name: 'edge-dns', type: 'dns', target: '1.1.1.1',
    interval_seconds: 30, timeout_seconds: 3, params: {}, enabled: true,
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 't2', name: 'api-gw', type: 'tcp', target: 'api.example.com:443',
    interval_seconds: 60, timeout_seconds: 3, params: {}, enabled: false,
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  },
]

const sampleAgents = [
  { id: 'a1', name: 'agent-1', hostname: 'host-a', agent_version: '0.1.0', status: 'online', capabilities: ['icmp', 'tcp'] },
]

/** A read-only default fetch covering the list endpoints, so any screen renders
 *  with data in tests. CRUD tests install their own stateful stub. */
export function defaultFetch(): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/tests')) return jsonResponse({ items: sampleTests })
    if (url.endsWith('/v1/agents')) return jsonResponse({ items: sampleAgents })
    if (url.endsWith('/v1/ai/discover')) return jsonResponse({ proposals: [] })
    if (url.endsWith('/v1/alerts')) return jsonResponse({ items: [] })
    if (url.endsWith('/v1/alerts/active')) return jsonResponse({ items: [], evaluator_running: true })
    if (url.endsWith('/v1/tls/posture')) return jsonResponse({ items: [], collector_running: true })
    if (url.endsWith('/v1/threat/detections')) return jsonResponse({ items: [], detections_running: true })
    if (url.endsWith('/v1/endpoints')) return jsonResponse({ items: [], collector_running: true })
    if (url.endsWith('/v1/results/latest')) return jsonResponse({ items: [], collector_running: true })
    if (url.includes('/v1/topology') && !url.includes('whatif'))
      return jsonResponse({ topology_running: true, at: '2026-06-04T12:00:00Z', nodes: [], edges: [], coverage: { path_edges: 0, flow_edges: 0, routing_edges: 0, device_edges: 0 } })
    if (url.endsWith('/v1/cost/summary'))
      return jsonResponse({
        cost_running: true,
        summary: {
          priced: true, zones_mapped: true, pricing_source: 'test', pricing_as_of: '2026-06-01',
          total_bytes: 0, total_usd: 0, by_class: {}, by_service: {}, by_team: {},
          chatty_pairs: [], trend: [], budgets: [],
        },
      })
    if (url.endsWith('/v1/slos')) return jsonResponse({ slo_running: true, items: [] })
    if (url.endsWith('/v1/compliance'))
      return jsonResponse({ compliance_running: true, items: [], coverage: { flow_observed: false, ebpf_observed: false, observations: 0, zones_seen: 0, zones_total: 0, notes: [] } })
    if (url.endsWith('/v1/outages'))
      return jsonResponse({
        outage_running: true, feeds_enabled: false, scope_resolution: false,
        events: [], vantage_events: [],
        coverage_notes: ['coverage = your vantage points + public open-data feeds — probectl does not operate a global probe fleet'],
      })
    if (url.endsWith('/v1/rum')) return jsonResponse({ rum_running: false })
    if (url.endsWith('/v1/carbon')) return jsonResponse({ carbon_running: false })
    if (url.endsWith('/v1/secrets/health'))
      return jsonResponse({
        resolver_running: true,
        backends: [{ scheme: 'env', configured: true, resolves: 0, failures: 0, cached_leases: 0 }],
      })
    if (url.endsWith('/v1/diagnostics'))
      return jsonResponse({
        status: 'degraded',
        checked_at: '2026-06-06T00:00:00Z',
        checks: [
          { name: 'database', status: 'ok' },
          { name: 'cluster', status: 'degraded', detail: 'writer endpoint points at a read-only standby (failover in progress)' },
        ],
      })
    if (url.endsWith('/branding')) return jsonResponse({ product_name: 'probectl' })
    if (url.endsWith('/v1/security/keys'))
      return jsonResponse({ error: { message: 'not found' } }, 404)
    if (url.endsWith('/v1/lifecycle/retention'))
      return jsonResponse({ flow_retention_days: null, isolation_model: 'pooled' })
    if (url.endsWith('/v1/editions'))
      return jsonResponse({
        tier: 'community', state: 'community',
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
  }) as unknown as typeof fetch
}

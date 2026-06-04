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
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

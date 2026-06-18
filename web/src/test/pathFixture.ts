import { vi } from 'vitest'
import { jsonResponse, pathOf } from './fetchStub'
import type { Path } from '../api/paths'

// A path with an ECMP branch at hop 2 where one branch is lossy + carries MPLS.
export const samplePath: Path = {
  target: '9.9.9.9',
  target_ip: '9.9.9.9',
  mode: 'icmp',
  max_hops: 30,
  trace_count: 3,
  destination_reached: true,
  hops: [
    {
      ttl: 1,
      nodes: [
        {
          ip: '10.0.0.1',
          sent: 3,
          received: 3,
          loss_ratio: 0,
          rtt_min_ms: 1,
          rtt_avg_ms: 1.2,
          rtt_max_ms: 2,
        },
      ],
    },
    {
      ttl: 2,
      nodes: [
        {
          ip: '10.0.0.2',
          sent: 3,
          received: 1,
          loss_ratio: 0.66,
          rtt_min_ms: 10,
          rtt_avg_ms: 12,
          rtt_max_ms: 14,
          mpls: [{ label: 16001, tc: 0, s: true, ttl: 1 }],
        },
        {
          ip: '10.0.0.3',
          sent: 3,
          received: 3,
          loss_ratio: 0,
          rtt_min_ms: 11,
          rtt_avg_ms: 13,
          rtt_max_ms: 15,
        },
      ],
    },
    {
      ttl: 3,
      nodes: [
        {
          ip: '9.9.9.9',
          sent: 3,
          received: 3,
          loss_ratio: 0,
          rtt_min_ms: 20,
          rtt_avg_ms: 21,
          rtt_max_ms: 22,
        },
      ],
    },
  ],
  links: [
    { ttl: 1, from: '10.0.0.1', to: '10.0.0.2' },
    { ttl: 1, from: '10.0.0.1', to: '10.0.0.3' },
    { ttl: 2, from: '10.0.0.2', to: '9.9.9.9' },
    { ttl: 2, from: '10.0.0.3', to: '9.9.9.9' },
  ],
}

const sampleTest = {
  id: 't1',
  name: 'edge',
  type: 'icmp',
  target: '9.9.9.9',
  interval_seconds: 30,
  timeout_seconds: 3,
  params: {},
  enabled: true,
  created_at: '',
  updated_at: '',
}

export function stubPathFetch(path: Path | null = samplePath) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const pathName = pathOf(input)
      const method = init?.method ?? 'GET'
      if (pathName === '/v1/tests' && method === 'GET')
        return jsonResponse({ items: [sampleTest] })
      if (pathName === '/v1/tests/t1/path') {
        return path
          ? jsonResponse(path)
          : jsonResponse({ error: { code: 'not_found', message: 'no path' } }, 404)
      }
      return jsonResponse({ error: { code: 'not_found', message: 'no route' } }, 404)
    }),
  )
}

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { vi } from 'vitest'
import type { Incident, ChangeEvent } from '../api/incidents'
import type { Path, PathSnapshot } from '../api/paths'
import { samplePath } from './pathFixture'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'
import type { MeasuredRequest } from './journeys/measurement'

export const previousPath: Path = {
  ...samplePath,
  hops: samplePath.hops.map((hop) => {
    if (hop.ttl !== 2) return hop
    return {
      ...hop,
      nodes: [
        {
          ...hop.nodes[0],
          received: 3,
          loss_ratio: 0,
          rtt_avg_ms: 8,
        },
        {
          ...hop.nodes[1],
          ip: '10.0.0.4',
          rtt_avg_ms: 9,
        },
      ],
    }
  }),
  links: [
    { ttl: 1, from: '10.0.0.1', to: '10.0.0.2' },
    { ttl: 1, from: '10.0.0.1', to: '10.0.0.4' },
    { ttl: 2, from: '10.0.0.2', to: '9.9.9.9' },
    { ttl: 2, from: '10.0.0.4', to: '9.9.9.9' },
  ],
}

export const pathRounds: PathSnapshot[] = [
  { id: 'round-current', observed_at: '2026-07-14T12:05:00Z', path: samplePath },
  { id: 'round-previous', observed_at: '2026-07-14T12:00:00Z', path: previousPath },
]

export const pathIncident: Incident = {
  id: 'inc-path',
  tenant_id: '00000000-0000-0000-0000-000000000001',
  status: 'open',
  severity: 'critical',
  title: 'loss on one ECMP branch',
  target: '9.9.9.9',
  started_at: '2026-07-14T12:04:00Z',
  last_seen_at: '2026-07-14T12:06:00Z',
  signal_count: 1,
  signals: [
    {
      plane: 'network',
      kind: 'path.loss',
      severity: 'critical',
      title: 'branch 10.0.0.2 is lossy',
      target: '9.9.9.9',
      occurred_at: '2026-07-14T12:05:00Z',
    },
  ],
}

export const pathChange: ChangeEvent = {
  id: 'change-path',
  source: 'git',
  kind: 'routing.policy',
  title: 'edge route policy deployed',
  target: '9.9.9.9',
  occurred_at: '2026-07-14T12:05:00Z',
}

const pathTest = {
  id: 't1',
  name: 'edge',
  type: 'icmp',
  target: '9.9.9.9',
  interval_seconds: 30,
  timeout_seconds: 3,
  params: {},
  enabled: true,
  created_at: '2026-07-14T11:00:00Z',
  updated_at: '2026-07-14T11:00:00Z',
}

export function stubPathHistoryFetch(requests: MeasuredRequest[] = []) {
  const base = defaultFetch()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      assertNoDoublePrefix(input)
      const url = new URL(String(input), 'https://probectl.invalid')
      const pathname = pathOf(input)
      const method = init?.method ?? 'GET'
      requests.push({
        url: String(input),
        method,
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        body: init?.body,
      })

      if (pathname === '/v1/tests' && method === 'GET') {
        return jsonResponse({ items: [pathTest] })
      }
      if (pathname === '/v1/tests/t1/path' && method === 'GET') {
        return jsonResponse(samplePath)
      }
      if (pathname === '/v1/tests/t1/path/history' && method === 'GET') {
        const ids = url.searchParams.getAll('round_id')
        return jsonResponse({
          items: ids.length > 0 ? pathRounds.filter((round) => ids.includes(round.id)) : pathRounds,
        })
      }
      if (pathname === '/v1/incidents' && method === 'GET') {
        return jsonResponse({ items: [pathIncident] })
      }
      if (pathname === '/v1/incidents/inc-path' && method === 'GET') {
        return jsonResponse(pathIncident)
      }
      if (pathname === '/v1/incidents/inc-path/changes' && method === 'GET') {
        return jsonResponse({ items: [] })
      }
      if (pathname === '/v1/changes' && method === 'GET') {
        return jsonResponse({ items: [pathChange] })
      }
      return base(input, init)
    }),
  )
}

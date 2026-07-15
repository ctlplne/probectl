#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Loopback-only screenshot fixture for docs/ops/fleet-rollout.md.
 *
 * Vite serves the real application on upstreamPort. This tiny reverse proxy
 * supplies deterministic tenant API responses on the same origin so browser
 * screenshots exercise the production React surface without a live database,
 * credentials, or outbound traffic.
 */

import http from 'node:http'

const port = Number.parseInt(process.env.PORT ?? '4175', 10)
const upstreamPort = Number.parseInt(process.env.VITE_PORT ?? '4174', 10)

let rollout = {
  id: 'rollout-2026-07-15',
  target: 'v1.4.0',
  digest: 'sha256:68d68d9250f9d7a98a581f9f5c1d00d278a9a53c45c83d31f932e4c49661fb91',
  halted: false,
  halt_reason: '',
  done: false,
  progress: 'rollout to v1.4.0: canary[2]=applying early[8]=pending main[30]=pending',
  waves: [
    { cohort: 'canary', agents: 2, status: 'applying' },
    { cohort: 'early', agents: 8, status: 'pending' },
    { cohort: 'main', agents: 30, status: 'pending' },
  ],
}

const agents = [
  {
    id: 'agent-canary-1',
    name: 'edge-canary-1',
    hostname: 'iad-edge-01',
    agent_version: 'v1.4.0',
    status: 'online',
    capabilities: ['flow', 'ebpf', 'path'],
    heartbeat_age_seconds: 21,
    heartbeat_state: 'ready',
    heartbeat_reason: 'Authenticated heartbeat is inside the five-minute health gate.',
    version_state: 'current',
    version_reason: 'Agent reports the verified rollout target v1.4.0.',
    readiness_state: 'ready',
    readiness_reason: 'Heartbeat, version policy, and reported capabilities are ready.',
    rollout_id: rollout.id,
    rollout_target: rollout.target,
    rollout_cohort: 'canary',
    rollout_state: 'applying',
    rollout_halted: false,
    last_failure: '',
    next_safe_action: {
      kind: 'verify_rollout_wave',
      label: 'Review rollout health gate',
      reason: 'Confirm the signed target and fresh registry heartbeat before advancing.',
      href: '/docs/api#rollouts',
    },
  },
  {
    id: 'agent-canary-2',
    name: 'edge-canary-2',
    hostname: 'fra-edge-01',
    agent_version: 'v1.3.0',
    status: 'online',
    capabilities: ['flow', 'ebpf', 'path'],
    heartbeat_age_seconds: 74,
    heartbeat_state: 'ready',
    heartbeat_reason: 'Authenticated heartbeat is inside the five-minute health gate.',
    version_state: 'supported_skew',
    version_reason: 'Agent remains on v1.3.0 while the canary wave converges.',
    readiness_state: 'version_skew',
    readiness_reason: 'Agent has not reported the rollout target v1.4.0 yet.',
    rollout_id: rollout.id,
    rollout_target: rollout.target,
    rollout_cohort: 'canary',
    rollout_state: 'applying',
    rollout_halted: false,
    last_failure: 'Waiting for target v1.4.0 heartbeat.',
    next_safe_action: {
      kind: 'verify_rollout_wave',
      label: 'Review rollout health gate',
      reason: 'Wait for the external orchestrator, then verify the live registry again.',
      href: '/docs/api#rollouts',
    },
  },
]

function json(response, status, body) {
  const encoded = JSON.stringify(body)
  response.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(encoded),
    'Cache-Control': 'no-store',
  })
  response.end(encoded)
}

function readJSON(request) {
  return new Promise((resolve, reject) => {
    let raw = ''
    request.setEncoding('utf8')
    request.on('data', (chunk) => {
      raw += chunk
    })
    request.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {})
      } catch (error) {
        reject(error)
      }
    })
    request.on('error', reject)
  })
}

async function fixture(request, response, pathname) {
  if (pathname === '/v1/me') {
    json(response, 200, {
      tenant_id: '00000000-0000-0000-0000-000000000001',
      user_id: 'operator-docs',
      email: 'operator@acme.example',
      display_name: 'Acme Operator',
      mfa_satisfied: true,
      permissions: ['agent.read', 'agent.write'],
    })
    return true
  }
  if (pathname === '/v1/agents') {
    json(response, 200, {
      items: agents.map((agent) => ({
        ...agent,
        rollout_state: rollout.halted ? 'halted' : agent.rollout_state,
        rollout_halted: rollout.halted,
        rollout_halt_reason: rollout.halt_reason,
      })),
      control_version: 'v1.4.0',
      rollouts_available: true,
    })
    return true
  }
  if (pathname === '/v1/rollouts' && request.method === 'GET') {
    json(response, 200, { items: [rollout] })
    return true
  }
  if (pathname === `/v1/rollouts/${rollout.id}/halt` && request.method === 'POST') {
    const body = await readJSON(request)
    rollout = {
      ...rollout,
      halted: true,
      halt_reason: body.reason,
      progress: `rollout to v1.4.0 — HALTED: ${body.reason}`,
      waves: rollout.waves.map((wave) =>
        wave.status === 'applying' ? { ...wave, status: 'halted' } : wave,
      ),
    }
    json(response, 200, rollout)
    return true
  }
  if (pathname === `/v1/rollouts/${rollout.id}/resume` && request.method === 'POST') {
    rollout = {
      ...rollout,
      halted: false,
      halt_reason: '',
      progress: 'rollout to v1.4.0: canary[2]=applying early[8]=pending main[30]=pending',
      waves: rollout.waves.map((wave) =>
        wave.status === 'halted' ? { ...wave, status: 'applying' } : wave,
      ),
    }
    json(response, 200, rollout)
    return true
  }
  if (pathname === `/v1/rollouts/${rollout.id}/verify` && request.method === 'POST') {
    json(response, 200, rollout)
    return true
  }
  if (pathname === '/v1/secrets/health') {
    json(response, 200, { resolver_running: true, backends: [] })
    return true
  }
  if (pathname === '/v1/directory/scim-tokens' || pathname === '/v1/abac/policies') {
    json(response, 200, { items: [] })
    return true
  }
  if (pathname === '/v1/diagnostics') {
    json(response, 200, { status: 'ok', checked_at: '2026-07-15T05:00:00Z', checks: [] })
    return true
  }
  if (pathname === '/v1/lifecycle/retention') {
    json(response, 200, { flow_retention_days: null, isolation_model: 'pooled' })
    return true
  }
  if (pathname === '/v1/editions') {
    json(response, 200, { tier: 'core', state: 'community', features: [] })
    return true
  }
  if (pathname === '/v1/security/keys' || pathname === '/v1/remediation/proposals') {
    json(response, 404, { error: { code: 'not_found', message: 'not found' } })
    return true
  }
  return false
}

const server = http.createServer(async (request, response) => {
  const pathname = new URL(request.url ?? '/', `http://${request.headers.host}`).pathname
  try {
    if (await fixture(request, response, pathname)) return
  } catch (error) {
    json(response, 400, { error: { code: 'bad_request', message: String(error) } })
    return
  }

  const upstream = http.request(
    {
      hostname: '127.0.0.1',
      port: upstreamPort,
      path: request.url,
      method: request.method,
      headers: { ...request.headers, host: `127.0.0.1:${upstreamPort}` },
    },
    (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers)
      upstreamResponse.pipe(response)
    },
  )
  upstream.on('error', (error) => json(response, 502, { error: { message: String(error) } }))
  request.pipe(upstream)
})

server.listen(port, '127.0.0.1', () => {
  console.log(`rollout screenshot fixture: http://127.0.0.1:${port}/admin`)
})

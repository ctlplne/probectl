// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import { fixtureFetch } from './fixtureApi'

async function body(response: Response) {
  return (await response.json()) as Record<string, unknown>
}

describe('fixture-backed documented journeys', () => {
  test('J1 progresses from credential setup to a named first finding', async () => {
    const fetch = fixtureFetch()

    const before = await body(await fetch('/v1/onboarding/progress'))
    expect(before.agent_enroll_token_created).toBe(false)
    expect(before.first_finding_visible).toBe(false)

    const token = await fetch('/v1/agents/enroll-tokens', {
      method: 'POST',
      body: JSON.stringify({ name: 'edge-canary-1', ttl_seconds: 3600 }),
    })
    expect(token.status).toBe(201)
    expect((await body(token)).token).toBe('pjt_fixture_only_not_a_real_secret')

    const created = await fetch('/v1/tests', {
      method: 'POST',
      body: JSON.stringify({
        name: 'first-loopback-check',
        type: 'icmp',
        target: '127.0.0.1',
        interval_seconds: 60,
        timeout_seconds: 3,
        params: {},
        enabled: true,
      }),
    })
    expect(created.status).toBe(201)

    const after = await body(await fetch('/v1/onboarding/progress'))
    expect(after.agent_connected).toBe(true)
    expect(after.producer_healthy).toBe(true)
    expect(after.first_result_received).toBe(true)
    expect(after.first_finding_visible).toBe(true)
    expect(after.first_finding).toMatchObject({
      title: 'ICMP check healthy — 127.0.0.1',
      href: '/targets',
    })
  })

  test('J4 provisions a siloed tenant without changing probectl identity', async () => {
    const fetch = fixtureFetch('populated', { providerPlane: true })
    const created = await fetch('/provider/v1/tenants', {
      method: 'POST',
      body: JSON.stringify({
        slug: 'silo-co',
        name: 'Silo Co',
        isolation_model: 'siloed',
        residency: 'eu',
      }),
    })
    expect(created.status).toBe(201)
    expect(await body(created)).toMatchObject({
      slug: 'silo-co',
      isolation_model: 'siloed',
      residency: 'eu',
    })

    const tenants = (await body(await fetch('/provider/v1/tenants'))) as {
      items: Array<Record<string, unknown>>
    }
    expect(tenants.items).toHaveLength(2)
    expect(await body(await fetch('/branding'))).toEqual({ product_name: 'probectl' })
  })

  test('J2 produces a replayable, tenant-redacted incident share', async () => {
    const fetch = fixtureFetch()
    const created = await fetch('/v1/incidents/30000000-0000-4000-8000-000000000001/shares', {
      method: 'POST',
      body: JSON.stringify({ context: { selected_evidence_id: 'E1' } }),
    })
    expect(created.status).toBe(201)
    const share = await body(created)
    expect(share.id).toBe('share_0123456789abcdef0123456789abcdef')
    expect(share.answer).toMatchObject({ tenant: '', root_cause_grounded: true })

    const replay = await fetch('/v1/incident-shares/share_0123456789abcdef0123456789abcdef')
    expect(replay.status).toBe(200)
    expect(await body(replay)).toMatchObject({
      id: 'share_0123456789abcdef0123456789abcdef',
    })
  })

  test('J3 creates an observe-only proposal and never an executed action', async () => {
    const fetch = fixtureFetch()
    const created = await fetch('/v1/remediation/proposals', {
      method: 'POST',
      body: JSON.stringify({
        kind: 'open_ticket',
        title: 'Investigate known scanner contact',
        target: '10.0.0.20',
      }),
    })
    expect(created.status).toBe(201)
    expect(await body(created)).toMatchObject({
      state: 'proposed',
      dry_run: { blast_radius: 0 },
    })

    const proposals = (await body(await fetch('/v1/remediation/proposals'))) as {
      items: Array<Record<string, unknown>>
      approvals_enabled: boolean
    }
    expect(proposals.approvals_enabled).toBe(false)
    expect(proposals.items).toHaveLength(1)
  })

  test('J5 persists governed retention while carbon remains explicitly estimated', async () => {
    const fetch = fixtureFetch()
    const saved = await fetch('/v1/lifecycle/retention', {
      method: 'PUT',
      body: JSON.stringify({ flow_retention_days: 30, audit_retention_days: 365 }),
    })
    expect(await body(saved)).toMatchObject({
      flow_retention_days: 30,
      audit_retention_days: 365,
      isolation_model: 'pooled',
    })

    const carbon = await body(await fetch('/v1/carbon'))
    expect(carbon).toMatchObject({
      carbon_running: true,
      summary: { methodology: { measured: false } },
    })
  })

  test('each fixtureFetch call owns isolated journey state', async () => {
    const first = fixtureFetch()
    const second = fixtureFetch()
    await first('/v1/tests', {
      method: 'POST',
      body: JSON.stringify({ name: 'only-first' }),
    })

    const firstTests = (await body(await first('/v1/tests'))) as { items: unknown[] }
    const secondTests = (await body(await second('/v1/tests'))) as { items: unknown[] }
    expect(firstTests.items).toHaveLength(secondTests.items.length + 1)
  })
})

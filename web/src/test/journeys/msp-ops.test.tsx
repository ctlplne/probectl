// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '../renderApp'
import { jsonResponse } from '../fetchStub'
import { JourneyRecorder } from './measurement'

function providerJourneyStub() {
  const operator = {
    id: 'operator-1',
    email: 'root@msp.example',
    name: 'Root Operator',
    role: 'admin',
    status: 'active',
    enrolled: true,
  }
  const tenant = {
    id: 'tenant-acme',
    slug: 'acme',
    name: 'Acme',
    status: 'active',
    isolation_model: 'pooled',
  }
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.endsWith('/provider/v1/me')) return jsonResponse({ operator })
    if (url.endsWith('/provider/v1/license')) {
      return jsonResponse({
        tier: 'msp',
        pricing_model: 'consumption',
        state: 'active',
        tenant_band: 25,
      })
    }
    if (url.endsWith('/provider/v1/fleet')) {
      return jsonResponse({
        items: [
          {
            tenant_id: tenant.id,
            tenant_slug: tenant.slug,
            tenant_name: tenant.name,
            tenant_status: tenant.status,
            agents_total: 3,
            agents_online: 2,
            agents_stale: 1,
            versions: { 'v1.4.0': 2, 'v1.3.0': 1 },
          },
        ],
      })
    }
    if (url.endsWith('/provider/v1/tenants') && method === 'GET') {
      return jsonResponse({ items: [tenant] })
    }
    if (url.endsWith('/provider/v1/tenants') && method === 'POST') {
      return jsonResponse(
        {
          id: 'tenant-silo-co',
          slug: 'silo-co',
          name: 'Silo Co',
          status: 'active',
          isolation_model: 'siloed',
          residency: 'eu',
        },
        201,
      )
    }
    if (url.endsWith('/provider/v1/breakglass') && method === 'GET') {
      return jsonResponse({
        items: [
          {
            id: 'grant-pending',
            operator_email: operator.email,
            tenant_id: tenant.id,
            reason: 'tenant-requested incident review',
            expires_at: '2026-07-14T13:00:00Z',
            use_count: 0,
            state: 'pending',
          },
        ],
      })
    }
    if (url.includes('/provider/v1/usage') && method === 'GET') {
      return jsonResponse({
        items: [
          {
            tenant_id: tenant.id,
            tenant_slug: tenant.slug,
            meter: 'agents',
            kind: 'gauge',
            period_start: '2026-07-01T00:00:00Z',
            period_end: '2026-07-14T00:00:00Z',
            value: 3,
            unit: 'count',
          },
        ],
      })
    }
    if (url.endsWith('/provider/v1/fairness')) return jsonResponse({ items: [] })
    if (url.endsWith('/provider/v1/operators')) return jsonResponse({ items: [operator] })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('J6 one-page MSP operations', () => {
  test('triages, provisions a siloed tenant, and opens showback within eight interactions', async () => {
    const user = userEvent.setup()
    const stub = providerJourneyStub()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')

    const nav = await screen.findByRole('navigation', { name: 'Provider tasks' })
    expect(screen.getByText(/probectl · provider plane/i)).toBeInTheDocument()
    expect(screen.getByText(/operator domain — no tenant context/i)).toBeInTheDocument()

    let interactions = 0
    let typed = ''

    const fleet = await screen.findByRole('table', { name: /fleet across tenants/i })
    await user.click(within(fleet).getByRole('button', { name: /triage acme exception/i }))
    interactions += 1
    expect(await screen.findByText(/grants no tenant telemetry access/i)).toBeInTheDocument()

    await user.click(within(nav).getByRole('link', { name: /provision & lifecycle/i }))
    interactions += 1
    await user.selectOptions(screen.getByLabelText('Isolation'), 'siloed')
    interactions += 1

    await user.type(await screen.findByLabelText(/residency/i), 'eu')
    interactions += 1
    typed += 'eu'
    await user.type(screen.getByLabelText(/new tenant slug/i), 'silo-co')
    interactions += 1
    typed += 'silo-co'
    await user.type(screen.getByLabelText(/display name/i), 'Silo Co')
    interactions += 1
    typed += 'Silo Co'
    await user.click(screen.getByRole('button', { name: /^provision$/i }))
    interactions += 1

    const exportLink = within(nav).getByRole('link', { name: /export usage csv/i })
    let openedExport = ''
    exportLink.addEventListener(
      'click',
      (event) => {
        event.preventDefault()
        openedExport = exportLink.getAttribute('href') ?? ''
      },
      { once: true },
    )
    await user.click(exportLink)
    interactions += 1
    expect(openedExport).toBe('/provider/v1/usage/export?format=csv&rollup=day')

    const post = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      ([url, init]) =>
        String(url).endsWith('/provider/v1/tenants') &&
        (init as RequestInit | undefined)?.method === 'POST',
    )
    expect(post).toBeTruthy()
    expect(JSON.parse(String((post![1] as RequestInit).body))).toEqual({
      slug: 'silo-co',
      name: 'Silo Co',
      isolation_model: 'siloed',
      residency: 'eu',
    })

    for (const link of within(nav).getAllByRole('link')) {
      expect(link.tabIndex).toBeGreaterThanOrEqual(0)
    }
    expect(within(nav).getByRole('link', { name: /fleet exceptions/i })).toHaveAttribute(
      'aria-keyshortcuts',
      'Alt+X',
    )
    expect(screen.getByRole('button', { name: /^provision$/i }).tagName).toBe('BUTTON')

    const measurement = new JourneyRecorder('J6', 'MSP multi-tenant operations under probectl')
      .pointer(interactions)
      .typed(typed)
      .activeTimeProxy({
        min_ms: 30_000,
        max_ms: 120_000,
        basis:
          'after MFA: triage one metadata-only exception, open provisioning, enter the silo contract, then activate the direct usage export',
      })
      .complete(
        'fleet exception triaged without implicit tenant telemetry access',
        'siloed tenant provisioned with explicit EU residency',
        'usage CSV opened from the sticky task rail',
        'all controls are native keyboard targets and task shortcuts are visible',
      )
      .snapshot()

    expect(measurement.pointer_interactions).toBeLessThanOrEqual(8)
    expect(measurement.active_time_proxy.max_ms).toBeLessThanOrEqual(120_000)
    expect(measurement.context_breaks).toBe(0)
    expect(measurement.outcome.status).toBe('complete')
  })
})

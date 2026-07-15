// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

describe('tenant-safe dashboard reporting', () => {
  test('saves, shares, exports, and schedules only inside the configured tenant inbox', async () => {
    const fallback = defaultFetch()
    const requests: Array<{ path: string; method: string; body?: Record<string, unknown> }> = []
    const views: Array<Record<string, unknown>> = []
    const schedules: Array<Record<string, unknown>> = []
    const artifacts: Array<Record<string, unknown>> = []

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        const body = init?.body
          ? (JSON.parse(String(init.body)) as Record<string, unknown>)
          : undefined
        requests.push({ path, method, body })
        if (path === '/v1/dashboards') {
          if (method === 'POST') {
            const view = {
              id: 'view-1',
              tenant_id: '00000000-0000-0000-0000-000000000001',
              owner_id: 'u_test',
              ...body,
              created_at: '2026-07-14T12:00:00Z',
              updated_at: '2026-07-14T12:00:00Z',
            }
            views.push(view)
            return jsonResponse(view, 201)
          }
          return jsonResponse({ items: views })
        }
        if (path === '/v1/dashboard-report-schedules') {
          if (method === 'POST') {
            const schedule = {
              id: 'schedule-1',
              tenant_id: '00000000-0000-0000-0000-000000000001',
              owner_id: 'u_test',
              enabled: true,
              next_run_at: body?.first_run_at,
              ...body,
              created_at: '2026-07-14T12:00:00Z',
              updated_at: '2026-07-14T12:00:00Z',
            }
            schedules.push(schedule)
            return jsonResponse(schedule, 201)
          }
          return jsonResponse({
            items: schedules,
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
        }
        if (path === '/v1/dashboard-reports' && method === 'POST') {
          const artifact = {
            id: 'artifact-1',
            dashboard_id: body?.dashboard_id,
            format: body?.format,
            media_type: 'application/pdf',
            filename: 'cross-plane-posture.pdf',
            generated_by: 'operator@probectl.test',
            generated_at: '2026-07-14T12:01:00Z',
            absolute_from: '2026-07-14T11:00:00Z',
            absolute_to: '2026-07-14T12:00:00Z',
            provenance: ['tenant-scoped control-plane APIs'],
            redaction_state: 'secrets removed',
            coverage_limitations: ['offline collectors omitted'],
            download_url: '/v1/dashboard-report-artifacts/artifact-1',
          }
          artifacts.push(artifact)
          return jsonResponse(artifact, 201)
        }
        if (path === '/v1/dashboard-report-artifacts') return jsonResponse({ items: artifacts })
        return fallback(input, init)
      }),
    )

    renderApp('/dashboards')
    const user = userEvent.setup()
    const scope = await screen.findByRole('region', { name: /dashboard scope and preset/i })
    expect(within(scope).getByText('Acme Industries')).toBeInTheDocument()
    expect(within(scope).getByText('00000000-0000-0000-0000-000000000001')).toBeInTheDocument()
    expect(within(scope).getByText(/absolute time · utc/i)).toBeInTheDocument()
    expect(within(scope).getByText(/1 hour coordinated/i)).toBeInTheDocument()

    const operator = within(scope).getByRole('button', { name: 'Operator' })
    const executive = within(scope).getByRole('button', { name: 'Executive' })
    expect(operator).toHaveAttribute('aria-pressed', 'true')
    await user.click(executive)
    expect(executive).toHaveAttribute('aria-pressed', 'true')
    await user.click(within(scope).getByText(/coverage, provenance, and redaction details/i))
    expect(within(scope).getByText('Coverage gaps')).toBeVisible()

    expect(screen.getByRole('table', { name: /active tests dashboard/i })).toBeInTheDocument()
    expect(screen.getByRole('img', { name: /cost trend/i })).toBeInTheDocument()

    await user.click(screen.getByRole('checkbox', { name: /share inside this tenant/i }))
    await user.click(screen.getByRole('button', { name: /save dashboard/i }))
    expect(await screen.findByText(/tenant-authenticated share link/i)).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /selected saved snapshot/i })).toHaveTextContent(
      'Cross-plane posture',
    )
    const saved = requests.find(
      (request) => request.path === '/v1/dashboards' && request.method === 'POST',
    )
    expect(saved?.body).toMatchObject({ preset: 'executive', shared: true })
    expect(saved?.body).not.toHaveProperty('tenant_id')
    expect(saved?.body?.definition).toMatchObject({
      provenance: expect.any(Array),
      redaction_state: expect.any(String),
      coverage_limitations: expect.any(Array),
      metrics: expect.objectContaining({ 'Active tests': '1' }),
    })

    await user.click(screen.getByRole('button', { name: /generate pdf/i }))
    expect(await screen.findByRole('link', { name: 'cross-plane-posture.pdf' })).toHaveAttribute(
      'href',
      '/v1/dashboard-report-artifacts/artifact-1',
    )
    await user.click(screen.getByRole('button', { name: /schedule delivery/i }))
    expect(await screen.findByText(/cross-plane posture weekly/i)).toBeInTheDocument()

    const scheduled = requests.find(
      (request) => request.path === '/v1/dashboard-report-schedules' && request.method === 'POST',
    )
    expect(scheduled?.body).toMatchObject({
      dashboard_id: 'view-1',
      format: 'pdf',
      cadence: 'weekly',
      destination_id: 'tenant-report-inbox',
    })
    expect(
      requests.every((request) => request.path.startsWith('/v1/') || request.path === '/branding'),
    ).toBe(true)
  })

  test('opens only a tenant-authorized shared view from its stable link', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) !== '/v1/dashboards') return fallback(input, init)
        return jsonResponse({
          items: [
            {
              id: 'view-shared',
              tenant_id: '00000000-0000-0000-0000-000000000001',
              owner_id: 'another-operator',
              name: 'Executive weekly evidence',
              preset: 'executive',
              shared: true,
              definition: {
                absolute_from: '2026-07-14T11:00:00Z',
                absolute_to: '2026-07-14T12:00:00Z',
                provenance: ['tenant-scoped control-plane APIs'],
                redaction_state: 'secrets removed',
                coverage_limitations: ['offline collectors omitted'],
                metrics: { 'Active tests': '7', 'Open incidents': '1' },
              },
              created_at: '2026-07-14T12:00:00Z',
              updated_at: '2026-07-14T12:00:00Z',
            },
          ],
        })
      }),
    )

    renderApp('/dashboards?view=view-shared#saved-dashboard')
    const savedDashboard = await screen.findByRole('combobox', { name: /saved dashboard/i })
    await waitFor(() => expect(savedDashboard).toHaveValue('view-shared'))
    const snapshot = screen.getByRole('region', { name: /selected saved snapshot/i })
    expect(snapshot).toHaveTextContent('Executive weekly evidence')
    expect(snapshot).toHaveTextContent('executive preset')
    expect(snapshot).toHaveTextContent('2 exact values')
    expect(screen.queryByRole('alert', { name: /unavailable/i })).not.toBeInTheDocument()
  })
})

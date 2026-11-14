// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { expect, test, vi } from 'vitest'
import { screen, within, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

for (const tenant of [
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000002',
]) {
  test(`saves an explicit monthly pack and exact capacity assumptions in tenant ${tenant}`, async () => {
    const fallback = defaultFetch()
    const saved: Array<Record<string, unknown>> = []
    const views: Array<Record<string, unknown>> = []
    const reports: Array<Record<string, unknown>> = []
    const schedules: Array<Record<string, unknown>> = []
    const patches: Array<Record<string, unknown>> = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        if (path === '/v1/dashboards') {
          if (init?.method === 'POST') {
            const body = JSON.parse(String(init.body)) as Record<string, unknown>
            saved.push(body)
            const view = {
              ...body,
              id: 'monthly-view',
              tenant_id: tenant,
              owner_id: 'u_test',
              created_at: '2026-11-14T00:00:00Z',
              updated_at: '2026-11-14T00:00:00Z',
            }
            views.push(view)
            return jsonResponse(view, 201)
          }
          return jsonResponse({ items: views })
        }
        if (path === '/v1/dashboard-report-schedules') {
          if (init?.method === 'POST') {
            const body = JSON.parse(String(init.body)) as Record<string, unknown>
            const schedule = {
              ...body,
              id: 'monthly-schedule',
              tenant_id: tenant,
              enabled: true,
              owner_id: 'u_test',
              next_run_at: '2026-12-01T00:00:00Z',
            }
            schedules.push(schedule)
            return jsonResponse(schedule, 201)
          }
          return jsonResponse({
            items: schedules,
            provider_trigger_available: true,
            destinations: [
              {
                id: 'tenant-report-inbox',
                name: 'Tenant inbox',
                kind: 'local',
                outbound: false,
                ready: true,
              },
            ],
          })
        }
        if (
          path === '/v1/dashboard-report-schedules/monthly-schedule' &&
          init?.method === 'PATCH'
        ) {
          const body = JSON.parse(String(init.body)) as Record<string, unknown>
          patches.push(body)
          Object.assign(schedules[0], body)
          return jsonResponse(schedules[0])
        }
        if (path === '/v1/dashboard-reports' && init?.method === 'POST') {
          reports.push(JSON.parse(String(init.body)) as Record<string, unknown>)
          return jsonResponse({ id: 'pack' }, 201)
        }
        return fallback(input, init)
      }),
    )
    renderApp('/dashboards', {
      me: {
        tenant_id: tenant,
        permissions: [
          'metrics.read',
          'metrics.write',
          'entities.read',
          'test.read',
          'incident.read',
          'change.read',
          'events.read',
          'flow.read',
        ],
      },
    })
    const user = userEvent.setup()
    await user.click(
      await screen.findByRole('checkbox', { name: 'Build a monthly client pack (preview)' }),
    )
    const editor = screen.getByRole('region', { name: 'Monthly client pack configuration' })
    await user.clear(within(editor).getByRole('textbox', { name: 'Report timezone' }))
    await user.type(
      within(editor).getByRole('textbox', { name: 'Report timezone' }),
      'Asia/Kolkata',
    )
    fireEvent.change(within(editor).getByLabelText('Report month'), {
      target: { value: '2026-10' },
    })
    await user.click(within(editor).getByRole('button', { name: 'Add monthly capacity target' }))
    expect(screen.getByRole('button', { name: 'Save dashboard' })).toBeDisabled()
    const context = '11111111-1111-4111-8111-111111111111'
    const iface = '22222222-2222-4222-8222-222222222222'
    await user.type(
      within(editor).getByRole('textbox', { name: 'Monthly target 1 routing context ID' }),
      context,
    )
    await user.type(
      within(editor).getByRole('textbox', { name: 'Monthly target 1 canonical interface ID' }),
      iface,
    )
    await user.type(
      within(editor).getByRole('textbox', { name: 'Monthly target 1 threshold (bps)' }),
      '12345678901234567890.125',
    )
    await user.type(
      within(editor).getByRole('textbox', {
        name: 'Monthly target 1 member 1 physical bound (bps)',
      }),
      '18446744073709551615',
    )
    const direction = tenant.endsWith('1') ? 'interval_max' : 'interval_sum'
    const directionControl = within(editor).getByRole('combobox', {
      name: 'Monthly target 1 direction',
    })
    expect(
      Array.from(
        within(directionControl).getAllByRole('option'),
        (option) => (option as HTMLOptionElement).value,
      ),
    ).toEqual(['in', 'out', 'max_directional_percentiles', 'interval_max', 'interval_sum'])
    await user.selectOptions(directionControl, direction)
    await user.click(screen.getByRole('button', { name: 'Save dashboard' }))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(saved[0]).not.toHaveProperty('tenant_id')
    expect(saved[0].definition).not.toHaveProperty('absolute_from')
    expect(saved[0].definition).not.toHaveProperty('metrics')
    expect(saved[0].definition).toMatchObject({
      client_report: {
        timezone: 'Asia/Kolkata',
        month: '2026-10',
        period: 'completed_month',
        capacity_targets: [
          {
            target: { kind: 'interface', context_id: context, interface_id: iface },
            direction,
            capacity_bps: '12345678901234567890.125',
            physical_bounds: [
              { context_id: context, interface_id: iface, max_bps: '18446744073709551615' },
            ],
          },
        ],
      },
    })
    expect(screen.getByRole('region', { name: 'Selected saved snapshot' })).toHaveTextContent(
      'Completed calendar month · Asia/Kolkata',
    )
    expect(screen.getByRole('combobox', { name: 'Cadence' })).toHaveValue('monthly')
    const consent = screen.getByRole('checkbox', {
      name: 'Allow provider-triggered monthly runs for this schedule',
    })
    expect(consent).not.toBeChecked()
    await user.click(consent)
    await user.click(screen.getByRole('button', { name: 'Schedule delivery' }))
    await waitFor(() => expect(schedules).toHaveLength(1))
    expect(schedules[0]).toMatchObject({
      provider_trigger_allowed: true,
      dashboard_id: 'monthly-view',
      destination_id: 'tenant-report-inbox',
    })
    await user.click(await screen.findByRole('button', { name: /Revoke provider trigger for/ }))
    await waitFor(() => expect(patches).toEqual([{ provider_trigger_allowed: false }]))
    await user.click(screen.getByRole('button', { name: 'Generate PDF' }))
    await waitFor(() => expect(reports).toEqual([{ dashboard_id: 'monthly-view', format: 'pdf' }]))
    await user.selectOptions(
      within(editor).getByRole('combobox', { name: 'Monthly report period' }),
      'month_to_date',
    )
    expect(within(editor).getByRole('status')).toHaveTextContent('partial')
    expect(within(editor).getByLabelText('Report month')).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Save dashboard' }))
    await waitFor(() => expect(saved).toHaveLength(2))
    expect(saved[1].definition).toMatchObject({
      client_report: { period: 'month_to_date', timezone: 'Asia/Kolkata' },
    })
    expect((saved[1].definition as { client_report: unknown }).client_report).not.toHaveProperty(
      'month',
    )
  })
}

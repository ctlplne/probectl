// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
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
    const portableManifest = {
      api_version: 'probectl.io/dashboard/v1',
      kind: 'Dashboard',
      metadata: { name: 'Imported fleet posture' },
      spec: {
        preset: 'operator',
        shared: false,
        definition: {
          absolute_from: '2026-07-14T11:00:00Z',
          absolute_to: '2026-07-14T12:00:00Z',
          provenance: ['native control-plane APIs'],
          redaction_state: 'secrets removed',
          coverage_limitations: ['offline collectors omitted'],
          metrics: [{ name: 'Active tests', value: '7' }],
        },
      },
    }

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
        if (path === '/v1/dashboard-manifests/import' && method === 'POST') {
          const confirm = body?.confirm === true
          const response: Record<string, unknown> = {
            status: confirm ? 'created' : 'preview',
            manifest: portableManifest,
            preview: {
              name: 'Imported fleet posture',
              preset: 'operator',
              shared: false,
              absolute_from: '2026-07-14T11:00:00Z',
              absolute_to: '2026-07-14T12:00:00Z',
              metric_count: 1,
              provenance_count: 1,
              coverage_limitation_count: 1,
            },
          }
          if (confirm) {
            const imported = {
              id: 'view-imported',
              tenant_id: '00000000-0000-0000-0000-000000000001',
              owner_id: 'u_test',
              name: 'Imported fleet posture',
              preset: 'operator',
              shared: false,
              definition: {
                ...portableManifest.spec.definition,
                metrics: { 'Active tests': '7' },
              },
              created_at: '2026-07-14T12:02:00Z',
              updated_at: '2026-07-14T12:02:00Z',
            }
            views.push(imported)
            response.dashboard = imported
          }
          return jsonResponse(response, confirm ? 201 : 200)
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

    renderApp('/dashboards', { me: { permissions: ['metrics.read', 'metrics.write'] } })
    const user = userEvent.setup()
    const scope = await screen.findByRole('region', { name: /dashboard scope and preset/i })
    expect(within(scope).getByText('Acme Industries')).toBeInTheDocument()
    expect(within(scope).getByText('00000000-0000-0000-0000-000000000001')).toBeInTheDocument()
    expect(within(scope).getByText(/absolute time · utc/i)).toBeInTheDocument()
    expect(within(scope).getByText(/last 1 hour coordinated/i)).toBeInTheDocument()
    expect(scope.querySelector('[data-dashboard-scope-context]')).toContainElement(
      scope.querySelector('[data-dashboard-tenant-id]'),
    )
    expect(scope.querySelector('[data-dashboard-scope-context]')).toContainElement(
      scope.querySelector('[data-dashboard-time-range]'),
    )

    const operator = within(scope).getByRole('button', { name: 'Operator' })
    const executive = within(scope).getByRole('button', { name: 'Executive' })
    expect(operator).toHaveAttribute('aria-pressed', 'true')
    await user.selectOptions(
      within(scope).getByRole('combobox', { name: /relative time scope/i }),
      '6h',
    )
    expect(within(scope).getByText(/last 6 hours coordinated/i)).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /active tests dashboard/i })).toBeInTheDocument()
    // Cost trend upgraded to the S11 TimeSeries; in jsdom (no canvas) its
    // accessible representation is the sampled data-table twin.
    expect(screen.getByRole('table', { name: /cost trend/i })).toBeInTheDocument()

    await user.click(executive)
    expect(executive).toHaveAttribute('aria-pressed', 'true')
    await user.click(within(scope).getByText(/coverage, provenance, and redaction details/i))
    expect(within(scope).getByText('Coverage gaps')).toBeVisible()

    expect(screen.queryByRole('table', { name: /active tests dashboard/i })).not.toBeInTheDocument()
    expect(screen.getByRole('table', { name: /cost trend/i })).toBeInTheDocument()

    await user.click(screen.getByRole('checkbox', { name: /share inside this tenant/i }))
    await user.click(screen.getByRole('button', { name: /save dashboard/i }))
    expect(await screen.findByText(/tenant-authenticated share link/i)).toBeInTheDocument()
    // WEB-07: the copyable share link must carry the /ui basename or it 404s.
    expect(screen.getByText(/\/ui\/dashboards\?view=/)).toBeInTheDocument()
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
      metrics: expect.objectContaining({ 'Relative scope': '6h', 'Active tests': '1' }),
    })
    const savedDefinition = saved?.body?.definition as
      | { absolute_from?: string; absolute_to?: string }
      | undefined
    expect(
      Date.parse(savedDefinition?.absolute_to ?? '') -
        Date.parse(savedDefinition?.absolute_from ?? ''),
    ).toBe(6 * 60 * 60 * 1000)
    expect(screen.getByRole('link', { name: /export manifest/i })).toHaveAttribute(
      'href',
      '/v1/dashboards/view-1/manifest',
    )

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

    expect(screen.queryByRole('button', { name: /confirm import/i })).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: /manifest json/i }), {
      target: { value: JSON.stringify(portableManifest) },
    })
    await user.click(screen.getByRole('button', { name: /preview import/i }))
    const preview = await screen.findByRole('region', { name: /dashboard import preview/i })
    expect(preview).toHaveTextContent('preview only · not created')
    expect(preview).toHaveTextContent('Imported fleet posture')
    const previewRequest = requests.find(
      (request) =>
        request.path === '/v1/dashboard-manifests/import' && request.body?.confirm === false,
    )
    expect(previewRequest?.body).not.toHaveProperty('tenant_id')
    expect(
      views.some((view) => view.id === 'view-imported'),
      'preview must not create a dashboard',
    ).toBe(false)
    await user.click(screen.getByRole('button', { name: /confirm import/i }))
    await screen.findByText(/a new tenant-scoped dashboard was created/i)
    expect(
      requests.some(
        (request) =>
          request.path === '/v1/dashboard-manifests/import' && request.body?.confirm === true,
      ),
    ).toBe(true)

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
    expect(screen.getByRole('button', { name: /save dashboard/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /preview import/i })).toBeDisabled()
    expect(screen.getByText(/read-only access: export is available/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /export manifest/i })).toHaveAttribute(
      'href',
      '/v1/dashboards/view-shared/manifest',
    )
    expect(screen.queryByRole('alert', { name: /unavailable/i })).not.toBeInTheDocument()
  })
})

test.each([
  { enabled: true, writable: true, failed: false },
  { enabled: false, writable: true, failed: false },
  { enabled: true, writable: false, failed: false },
  { enabled: true, writable: true, failed: true },
])(
  'schedule lifecycle preserves authority and confirmed state: %j',
  async ({ enabled, writable, failed }) => {
    const fallback = defaultFetch()
    let current = enabled
    const mutations: unknown[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        if (path === '/v1/dashboard-report-schedules')
          return jsonResponse({
            items: Array.from({ length: 5 }, (_, i) => ({
              id: `schedule-${i}`,
              name: `Owned schedule ${i}`,
              format: 'csv',
              cadence: 'weekly',
              enabled: current,
              next_run_at: '2026-07-21T12:00:00Z',
            })),
            destinations: [],
            outbound_default: false,
          })
        if (path === '/v1/dashboard-report-schedules/schedule-4' && init?.method === 'PATCH') {
          const body = JSON.parse(String(init.body)) as { enabled: boolean }
          mutations.push(body)
          if (failed)
            return jsonResponse(
              { error: { code: 'internal', message: 'Schedule update failed' } },
              500,
            )
          current = body.enabled
          return jsonResponse({ id: 'schedule-4', enabled: current })
        }
        return fallback(input, init)
      }),
    )
    renderApp('/dashboards', {
      me: { permissions: writable ? ['metrics.read', 'metrics.write'] : ['metrics.read'] },
    })
    const label = `${enabled ? 'Pause' : 'Resume'} Owned schedule 4`
    const button = await screen.findByRole('button', { name: label })
    if (!writable) {
      expect(button).toBeDisabled()
      expect(mutations).toHaveLength(0)
      return
    }
    await userEvent.click(button)
    await waitFor(() => expect(mutations).toEqual([{ enabled: !enabled }]))
    if (failed) {
      expect(await screen.findByText(/Schedule update failed/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: label })).toBeEnabled()
    } else {
      expect(
        await screen.findByRole('button', {
          name: `${enabled ? 'Resume' : 'Pause'} Owned schedule 4`,
        }),
      ).toBeEnabled()
    }
  },
)

// UI fixture proof only. Real authenticated service and rendered release
// acceptance are separate required checks for source-backed reports.
test.each([
  {
    tenant: '00000000-0000-0000-0000-000000000001',
    source: '00000000-0000-0000-0000-000000000011',
    name: 'Lane A',
  },
  {
    tenant: '00000000-0000-0000-0000-000000000002',
    source: '00000000-0000-0000-0000-000000000022',
    name: 'Lane B',
  },
])(
  'saved report sources and native bindings stay explicit in $name',
  async ({ tenant, source, name }) => {
    const fallback = defaultFetch()
    const requests: Array<{ path: string; body: Record<string, unknown> }> = []
    const views: Array<Record<string, unknown>> = []
    const sourceName = `${name} owned query`
    const manifest = {
      api_version: 'probectl.io/dashboard/v1',
      kind: 'Dashboard',
      metadata: { name: 'Portable source report' },
      spec: {
        preset: 'operator',
        shared: false,
        definition: {
          provenance: ['saved source'],
          redaction_state: 'current source policy',
          coverage_limitations: ['selected source rows'],
          metrics: [],
          flow_sources: [{ slot: 'flow-1' }],
        },
      },
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        if (path === '/v1/explorer/flow-views')
          return jsonResponse({
            items: [
              {
                id: source,
                version: '7',
                owner_id: 'u_test',
                definition: { name: sourceName, visibility: 'private' },
              },
            ],
          })
        if (path === '/v1/dashboards') {
          if (method === 'POST') {
            const body = JSON.parse(String(init?.body)) as Record<string, unknown>
            requests.push({ path, body })
            const view = {
              id: `${name}-view`,
              tenant_id: tenant,
              owner_id: 'u_test',
              ...body,
              created_at: '2026-11-04T12:00:00Z',
              updated_at: '2026-11-04T12:00:00Z',
            }
            views.push(view)
            return jsonResponse(view, 201)
          }
          return jsonResponse({ items: views })
        }
        if (path === '/v1/dashboard-report-schedules')
          return jsonResponse({ items: [], destinations: [], outbound_default: false })
        if (path === '/v1/dashboard-report-artifacts') return jsonResponse({ items: [] })
        if (path === '/v1/dashboard-manifests/import' && method === 'POST') {
          const body = JSON.parse(String(init?.body)) as Record<string, unknown>
          requests.push({ path, body })
          return jsonResponse({
            status: 'preview',
            manifest: body.manifest,
            preview: {
              name: 'Portable source report',
              preset: 'operator',
              shared: false,
              source_count: 1,
              metric_count: 0,
              provenance_count: 1,
              coverage_limitation_count: 1,
            },
          })
        }
        return fallback(input, init)
      }),
    )
    renderApp('/dashboards', {
      me: {
        tenant_id: tenant,
        tenant_name: name,
        permissions: ['metrics.read', 'metrics.write', 'ai.query', 'flow.read', 'tags.read'],
      },
    })
    const user = userEvent.setup()
    await user.click(await screen.findByRole('checkbox', { name: 'Build from saved flow queries' }))
    expect(screen.getByRole('button', { name: 'Save dashboard' })).toBeDisabled()
    const sources = screen.getByRole('region', { name: 'Report saved flow sources' })
    await user.click(await within(sources).findByRole('button', { name: `Open ${sourceName}` }))
    expect(
      within(sources).getByRole('list', { name: 'Selected report sources' }),
    ).toHaveTextContent(`${sourceName} · version 7`)
    await user.click(screen.getByRole('button', { name: 'Save dashboard' }))
    await waitFor(() =>
      expect(requests.some((request) => request.path === '/v1/dashboards')).toBe(true),
    )
    const saved = requests.find((request) => request.path === '/v1/dashboards')!.body
    expect(saved).not.toHaveProperty('tenant_id')
    expect(saved).not.toHaveProperty('owner_id')
    expect(saved.definition).toMatchObject({ flow_sources: [{ id: source, version: '7' }] })
    expect(saved.definition).not.toHaveProperty('metrics')
    expect(saved.definition).not.toHaveProperty('absolute_from')
    expect(saved.definition).not.toHaveProperty('absolute_to')
    const text = screen.getByRole('textbox', { name: 'Manifest JSON' })
    fireEvent.change(text, { target: { value: JSON.stringify(manifest) } })
    const preview = screen.getByRole('button', { name: 'Preview import' })
    expect(preview).toBeDisabled()
    const bindings = screen.getByRole('region', { name: 'Destination report source bindings' })
    await user.click(await within(bindings).findByRole('button', { name: `Open ${sourceName}` }))
    expect(
      within(bindings).getByRole('list', { name: 'Bound report source slots' }),
    ).toHaveTextContent(`flow-1: ${sourceName} · version 7`)
    await user.click(preview)
    expect(await screen.findByRole('button', { name: 'Confirm import' })).toBeEnabled()
    const imported = requests.find(
      (request) => request.path === '/v1/dashboard-manifests/import',
    )!.body
    expect(imported).toMatchObject({
      confirm: false,
      source_bindings: { 'flow-1': { id: source, version: '7' } },
    })
    expect(imported).not.toHaveProperty('tenant_id')
    expect(imported).not.toHaveProperty('owner_id')
    expect(JSON.stringify(imported.manifest)).not.toContain(source)
    expect(screen.getByRole('region', { name: 'Dashboard import preview' })).toHaveTextContent(
      '1 explicitly bound saved flow sources',
    )
    fireEvent.change(text, {
      target: {
        value: JSON.stringify({ ...manifest, metadata: { name: 'Different source report' } }),
      },
    })
    expect(screen.getByRole('button', { name: 'Preview import' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Confirm import' })).not.toBeInTheDocument()
    expect(screen.getByRole('list', { name: 'Bound report source slots' })).toHaveTextContent(
      'Not bound',
    )
  },
)

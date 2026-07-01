import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

interface SavedView {
  id: string
  tenant_id: string
  owner_id: string
  surface: string
  name: string
  filters: Record<string, string>
  created_at: string
  updated_at: string
}

function stubSavedViews() {
  const base = defaultFetch()
  const views = new Map<string, SavedView[]>()
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://probectl.test')
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/inventory/views' && method === 'GET') {
      const surface = url.searchParams.get('surface') ?? ''
      return jsonResponse({ items: views.get(surface) ?? [] })
    }
    if (path === '/v1/inventory/views' && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as {
        surface: string
        name: string
        filters: Record<string, string>
      }
      const view: SavedView = {
        id: `${body.surface}-${(views.get(body.surface)?.length ?? 0) + 1}`,
        tenant_id: '00000000-0000-0000-0000-000000000001',
        owner_id: 'u_test',
        surface: body.surface,
        name: body.name,
        filters: body.filters,
        created_at: '2026-07-01T00:00:00Z',
        updated_at: '2026-07-01T00:00:00Z',
      }
      views.set(body.surface, [view, ...(views.get(body.surface) ?? [])])
      return jsonResponse(view, 201)
    }
    return base(input, init)
  })
  vi.stubGlobal('fetch', fetcher)
  return { fetcher, views }
}

describe('saved list views', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  test('Targets serialize filters in the URL and save/apply named presets', async () => {
    const { views } = stubSavedViews()
    renderApp('/targets?q=edge&type=dns')
    expect(await screen.findByText('edge-dns')).toBeDefined()
    expect(screen.queryByText('api-gw')).toBeNull()

    await userEvent.type(screen.getByLabelText('View name'), 'DNS edge')
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await waitFor(() => expect(views.get('targets')?.[0].filters).toEqual({ q: 'edge', type: 'dns' }))

    await userEvent.clear(screen.getByLabelText('Find'))
    await userEvent.type(screen.getByLabelText('Find'), 'api')
    await userEvent.selectOptions(screen.getByLabelText('Type'), 'tcp')
    expect(await screen.findByText('api-gw')).toBeDefined()

    await userEvent.selectOptions(screen.getByLabelText('Saved views'), 'targets-1')
    expect(screen.getByLabelText('Find')).toHaveValue('edge')
    expect(screen.getByLabelText('Type')).toHaveValue('dns')
  })

  test('Agents save and restore URL-backed fleet filters', async () => {
    const { views } = stubSavedViews()
    renderApp('/admin?agent_status=online&agent_capability=ebpf')
    expect(await screen.findByText('agent-1')).toBeDefined()

    await userEvent.type(screen.getByLabelText('View name'), 'Online eBPF')
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await waitFor(() =>
      expect(views.get('agents')?.[0].filters).toEqual({
        agent_status: 'online',
        agent_capability: 'ebpf',
      }),
    )

    await userEvent.selectOptions(screen.getByLabelText('Status'), 'offline')
    expect(within(screen.getByRole('table', { name: 'Registered agents' })).queryByText('agent-1')).toBeNull()

    await userEvent.selectOptions(screen.getByLabelText('Saved views'), 'agents-1')
    expect(screen.getByLabelText('Status')).toHaveValue('online')
    expect(screen.getByLabelText('Capability')).toHaveValue('ebpf')
  })

  test('Incidents save and restore status/severity presets without losing the incident deep link', async () => {
    const { views } = stubSavedViews()
    renderApp('/incidents?incident_status=open&incident_severity=warning')
    expect(await screen.findByRole('button', { name: /checkout latency burn/i })).toBeDefined()

    await userEvent.type(screen.getByLabelText('View name'), 'Open warning')
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await waitFor(() =>
      expect(views.get('incidents')?.[0].filters).toEqual({
        incident_status: 'open',
        incident_severity: 'warning',
      }),
    )

    await userEvent.selectOptions(screen.getByLabelText('Status'), 'resolved')
    expect(await screen.findByText('No matching incidents')).toBeDefined()

    await userEvent.selectOptions(screen.getByLabelText('Saved views'), 'incidents-1')
    expect(screen.getByLabelText('Status')).toHaveValue('open')
    expect(screen.getByLabelText('Severity')).toHaveValue('warning')
  })

  test('Alerts save and restore active-alert filters', async () => {
    const { views } = stubSavedViews()
    renderApp('/alerts?alert_q=checkout&alert_severity=warning')
    expect(await screen.findByText(/target=checkout/)).toBeDefined()

    await userEvent.type(screen.getByLabelText('View name'), 'Checkout warning')
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await waitFor(() =>
      expect(views.get('alerts')?.[0].filters).toEqual({
        alert_q: 'checkout',
        alert_severity: 'warning',
      }),
    )

    await userEvent.selectOptions(screen.getByLabelText('Severity'), 'critical')
    expect(within(screen.getByRole('table', { name: 'Active alerts' })).queryByText(/target=checkout/)).toBeNull()

    await userEvent.selectOptions(screen.getByLabelText('Saved views'), 'alerts-1')
    expect(screen.getByLabelText('Find')).toHaveValue('checkout')
    expect(screen.getByLabelText('Severity')).toHaveValue('warning')
  })
})

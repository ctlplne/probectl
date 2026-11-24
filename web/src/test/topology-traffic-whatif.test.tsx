// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import type { TopologyFailurePortSeries, TopologyFailureTraffic } from '../api/sdk.gen'
import type { TopoEdge, TopoNode } from '../api/topology'
import { Providers } from '../App'
import { TopologyPage } from '../routes/TopologyPage'
import { TopologyTrafficWhatIf } from '../routes/TopologyTrafficWhatIf'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { TenantReaderFrame } from './tenantReaderFrame'

const contextID = '00000000-0000-4000-8000-000000000201'
const tenantA = '00000000-0000-4000-8000-000000000101'
const tenantB = '00000000-0000-4000-8000-000000000102'
const from = '2026-11-24T12:00:00.000Z'
const to = '2026-11-24T12:15:00.000Z'
const until = '2026-11-24T13:15:00.000Z'
const fromNode: TopoNode = { id: 'device:first', kind: 'device', label: 'first router' }
const toNode: TopoNode = { id: 'device:second', kind: 'device', label: 'second router' }
const edges: TopoEdge[] = [{ from: fromNode.id, to: toNode.id, kind: 'physical' }]

function port(interfaceID: string, direction: 'in' | 'out'): TopologyFailurePortSeries {
  return {
    interface_id: interfaceID,
    direction,
    current: {
      interface_id: interfaceID,
      direction,
      status: 'projected',
      added_bps: '0',
      removed_bps: '125',
      measured_bps: '500',
      projected_bps: '375',
      utilization_ratio: '3/4',
    },
    observed_samples: 3,
    projected_samples: 3,
    runout_status: 'insufficient_history',
  }
}

function traffic(ports: TopologyFailurePortSeries[]): TopologyFailureTraffic {
  return {
    context_id: contextID,
    failed_ports: [],
    flow_records: 9,
    from,
    model: 'directional flow and counters',
    projection: {
      from,
      to,
      samples: 3,
      ports,
      complete: false,
      affected_bytes: '4300',
      rerouted_bytes: '4100',
      unresolved_bytes: '150',
      unrouted_bytes: '50',
    },
    reason: 'traffic_or_capacity_coverage_incomplete',
    status: 'partial',
    to,
    unattributed_rows: 2,
  }
}

test('projects a selected link by direction and exports the exact simulation inputs', async () => {
  const user = userEvent.setup()
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  const projected = port('retained-egress', 'out')
  projected.projected_peak = { from, to, bps: '420' }
  projected.at_capacity = true
  const failed = port('disconnected-ingress', 'in')
  failed.current = { ...failed.current, status: 'failed', projected_bps: undefined }
  const unknown = port('unknown-ingress', 'in')
  unknown.current = { ...unknown.current, measured_bps: undefined, utilization_ratio: 'x/y' }
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    expect(pathOf(input)).toBe('/v1/topology/whatif')
    expect(init?.method).toBe('POST')
    expect(new Headers(init?.headers).get('X-Probectl-Tenant')).toBe(tenantA)
    return Promise.resolve(jsonResponse({ traffic: traffic([projected, failed, unknown]) }))
  })
  vi.stubGlobal('fetch', fetcher)
  render(
    <QueryClientProvider client={client}>
      <TenantReaderFrame tenant={tenantA}>
        <TopologyTrafficWhatIf
          contextID={contextID}
          node={fromNode}
          edges={edges}
          nodeLabels={new Map([[fromNode.id, fromNode.label]])}
        />
      </TenantReaderFrame>
    </QueryClientProvider>,
  )

  const form = within(screen.getByRole('form', { name: 'Traffic simulation inputs' }))
  const target = `${fromNode.id}|physical|${toNode.id}`
  await user.selectOptions(form.getByLabelText('Failed element'), target)
  await user.type(form.getByLabelText('Failed interface ID'), 'uplink-1')
  fireEvent.change(form.getByLabelText('Traffic window start (UTC)'), {
    target: { value: from.slice(0, 16) },
  })
  fireEvent.change(form.getByLabelText('Traffic window end (UTC)'), {
    target: { value: to.slice(0, 16) },
  })
  fireEvent.change(form.getByLabelText('Runout horizon (UTC)'), {
    target: { value: from.slice(0, 16) },
  })
  const simulate = form.getByRole('button', { name: 'Simulate traffic impact' })
  await user.click(simulate)
  expect(form.getByRole('alert')).toHaveTextContent('optional later runout horizon')
  expect(fetcher).not.toHaveBeenCalled()
  fireEvent.change(form.getByLabelText('Runout horizon (UTC)'), {
    target: { value: until.slice(0, 16) },
  })
  fireEvent.change(form.getByLabelText('Maximum counter poll gap'), { target: { value: '3m' } })
  await user.click(simulate)

  const result = within(await screen.findByRole('region', { name: 'Traffic simulation results' }))
  expect(result.getByText('4100 bytes')).toBeInTheDocument()
  expect(result.getByText('2 flow records lack usable original attribution.')).toBeInTheDocument()
  expect(result.getByText(/some flow, route, or counter evidence is missing/i)).toBeInTheDocument()
  const table = within(result.getByRole('table', { name: 'Directional link traffic projection' }))
  const retained = within(table.getByRole('row', { name: /retained-egress/ }))
  expect(retained.getByText('375 bit/s')).toBeInTheDocument()
  expect(retained.getByText('75.0%')).toBeInTheDocument()
  expect(retained.getByText('420 bit/s')).toBeInTheDocument()
  expect(retained.getByText('At or above capacity')).toBeInTheDocument()
  expect(table.getByRole('row', { name: /disconnected-ingress.*Failed/ })).toBeInTheDocument()
  expect(
    table.getByRole('row', { name: /unknown-ingress.*insufficient history/ }),
  ).toBeInTheDocument()

  const payload = {
    target,
    context_id: contextID,
    failure_interface_id: 'uplink-1',
    traffic_from: from,
    traffic_to: to,
    maximum_poll_gap: '3m',
    runout_until: until,
  }
  expect(fetcher).toHaveBeenCalledOnce()
  expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual(payload)
  const exportLink = screen.getByRole('link', { name: 'Export audited traffic simulation' })
  expect(exportLink).toHaveAttribute('download')
  const url = new URL(exportLink.getAttribute('href') ?? '', window.location.origin)
  expect(url.pathname).toBe('/v1/topology/whatif/export')
  expect(Object.fromEntries(url.searchParams)).toEqual(payload)
})

test('drops an in-flight traffic projection when the authenticated tenant changes', async () => {
  const fallback = defaultFetch()
  const user = userEvent.setup()
  let tenant = tenantA
  let finishFirst: ((response: Response) => void) | undefined
  const projectedRequests: string[] = []
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    switch (pathOf(input)) {
      case '/v1/entity-contexts':
        return Promise.resolve(
          jsonResponse({
            items: [{ context_id: contextID, site_label: 'Local site', vrf_label: 'Default' }],
            scope: { tenant_id: tenant },
          }),
        )
      case '/v1/topology':
        return Promise.resolve(
          jsonResponse({ topology_running: true, nodes: [fromNode, toNode], edges }),
        )
      case '/v1/topology/whatif': {
        const credentialTenant = new Headers(init?.headers).get('X-Probectl-Tenant')
        expect(credentialTenant).toBe(tenant)
        projectedRequests.push(tenant)
        if (tenant === tenantB) {
          return Promise.resolve(
            jsonResponse({ traffic: traffic([port('second-tenant-port', 'out')]) }),
          )
        }
        return new Promise<Response>((resolve) => {
          finishFirst = resolve
        })
      }
      default:
        return fallback(input, init)
    }
  })

  const view = () => (
    <Providers>
      <MemoryRouter initialEntries={[`/topology?entity_context=${contextID}`]}>
        <TenantReaderFrame
          tenant={tenant}
          permissions={[
            'flow.read',
            'entities.read',
            'metrics.read',
            'events.read',
            'topology.read',
          ]}
        >
          <TopologyPage />
        </TenantReaderFrame>
      </MemoryRouter>
    </Providers>
  )
  const rendered = render(view())
  await user.click(await screen.findByRole('button', { name: 'device first router' }))
  await user.click(await screen.findByRole('button', { name: 'Simulate traffic impact' }))
  await waitFor(() => expect(finishFirst).toBeTypeOf('function'))
  tenant = tenantB
  rendered.rerender(view())
  await act(async () => {
    finishFirst?.(jsonResponse({ traffic: traffic([port('first-tenant-port', 'out')]) }))
  })
  expect(
    await screen.findByText('Select a routing context and a device or hop on the live topology.'),
  ).toBeInTheDocument()
  expect(screen.queryByText('first-tenant-port')).not.toBeInTheDocument()
  expect(
    screen.queryByRole('link', { name: 'Export audited traffic simulation' }),
  ).not.toBeInTheDocument()
  await user.selectOptions(
    screen.getByLabelText('Canonical routing context'),
    await screen.findByRole('option', { name: 'Local site / Default' }),
  )
  await user.click(await screen.findByRole('button', { name: 'device first router' }))
  await user.click(await screen.findByRole('button', { name: 'Simulate traffic impact' }))
  expect(await screen.findByText('second-tenant-port')).toBeInTheDocument()
  expect(screen.queryByText('first-tenant-port')).not.toBeInTheDocument()
  expect(projectedRequests).toEqual([tenantA, tenantB])
})

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { expect, test, vi } from 'vitest'
import { ChangeEffects } from '../routes/ChangeEffects'
import { TenantReaderFrame } from './tenantReaderFrame'

test('change comparison keeps exact ratios, unknown coverage and a late response outside the next tenant', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const permissions = [
    'change.read',
    'flow.read',
    'entities.read',
    'metrics.read',
    'events.read',
    'test.read',
  ]
  let tenant = 'primary'
  let finishPrimary: ((value: Response) => void) | undefined
  const response = (mean: string) =>
    new Response(
      JSON.stringify({
        contract_version: 'probectl.change-effects.v1',
        original: { id: 'original' },
        before: { coverage: 'unavailable_source' },
        after: { coverage: 'unavailable_source' },
        tests: [
          {
            context_id: tenant,
            entity_id: 'router',
            test_id: 'test',
            agent_id: 'agent',
            before: { loss_ratio: '1/3', latency: { mean_nanos: mean } },
            after: {},
          },
        ],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    )
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      tenant === 'primary'
        ? new Promise<Response>((resolve) => {
            finishPrimary = resolve
          })
        : Promise.resolve(response('9007199254740993/7')),
    ),
  )
  const view = () => (
    <QueryClientProvider client={client}>
      <TenantReaderFrame tenant={tenant} permissions={permissions}>
        <ChangeEffects id="original" from="2026-11-01T00:00:00Z" to="2026-11-15T00:00:00Z" />
      </TenantReaderFrame>
    </QueryClientProvider>
  )
  const user = userEvent.setup()
  const rendered = render(view())
  try {
    await user.click(screen.getByRole('button', { name: 'Compare original measurements' }))
    await waitFor(() => expect(finishPrimary).toBeTypeOf('function'))
    tenant = 'paired'
    rendered.rerender(view())
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Compare original measurements' }))
    await screen.findByText('9007199254740993/7')
    expect(screen.getByText('1/3')).toBeInTheDocument()
    expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0)
    expect(
      screen.getByText(
        'Traffic coverage: before No current owned source; after No current owned source.',
      ),
    ).toBeInTheDocument()
    finishPrimary?.(response('543210987654321/9'))
    await waitFor(() => expect(screen.queryByText('543210987654321/9')).not.toBeInTheDocument())
    expect(screen.getByText('9007199254740993/7')).toBeInTheDocument()
  } finally {
    rendered.unmount()
    client.clear()
    vi.unstubAllGlobals()
  }
})

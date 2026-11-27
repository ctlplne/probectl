// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { FlowServiceSources } from '../routes/FlowServiceSources'
import { TenantReaderFrame } from './tenantReaderFrame'
import { jsonResponse } from './fetchStub'

function sourceResult(label: string) {
  return {
    ip: '192.0.2.7',
    services: [
      {
        publisher: label,
        version: 'native-version',
        digest: 'a'.repeat(64),
        fetched_at: new Date(Date.now() - 60000).toISOString(),
        valid_until: new Date(Date.now() + 60000).toISOString(),
        status: 'matched',
        matches: Array.from({ length: 23 }, (_, index) => ({
          prefix: '192.0.2.0/24',
          service: `${label} candidate ${index + 1}`,
          region: '',
        })),
      },
      {
        publisher: 'aged-source',
        version: 'old-version',
        digest: 'b'.repeat(64),
        fetched_at: '2020-01-01T00:00:00Z',
        valid_until: '2020-01-02T00:00:00Z',
        status: 'stale',
        matches: [],
      },
      {
        publisher: 'unreachable-source',
        version: 'last-known-version',
        digest: 'c'.repeat(64),
        fetched_at: new Date(Date.now() - 3_600_000).toISOString(),
        valid_until: '',
        status: 'unavailable',
        matches: [],
      },
    ],
  }
}

function View({ tenant = 'red', permissions = ['flow.read'] }) {
  return (
    <TenantReaderFrame tenant={tenant} permissions={permissions}>
      <FlowServiceSources />
    </TenantReaderFrame>
  )
}

test('shows complete source candidates and original clocks, then withholds expired matches', async () => {
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] })
  try {
    const value = sourceResult('published-range')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(value)),
    )
    render(<View />)
    fireEvent.change(screen.getByLabelText('Address for service sources'), {
      target: { value: value.ip },
    })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Look up service sources' }))
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(screen.getByText('published-range candidate 23')).toBeInTheDocument()
    expect(screen.getByText(value.services[0].fetched_at)).toBeInTheDocument()
    expect(screen.getByText(value.services[0].valid_until)).toBeInTheDocument()
    expect(screen.getByText('native-version')).toBeInTheDocument()
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument()
    expect(screen.getAllByText(/Unknown region/)).toHaveLength(23)
    expect(screen.getAllByText('Not published').length).toBeGreaterThan(0)
    expect(screen.getByText('aged-source')).toBeInTheDocument()
    expect(screen.getByText('unreachable-source')).toBeInTheDocument()
    expect(screen.getByText('1 minute ago')).toBeInTheDocument()
    expect(screen.getByText('1 hour ago')).toBeInTheDocument()
    expect(screen.getAllByText('Address attribution is unknown.')).toHaveLength(2)
    const [url, init] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toBe('/v1/opendata/enrichment?ip=192.0.2.7')
    expect(init?.credentials).toBe('same-origin')
    await act(() => vi.advanceTimersByTimeAsync(61000))
    expect(screen.queryByText('published-range candidate 23')).not.toBeInTheDocument()
    expect(screen.getByText(value.services[0].fetched_at)).toBeInTheDocument()
    expect(screen.getByText('2 minutes ago')).toBeInTheDocument()
    expect(screen.getAllByText('Address attribution is unknown.')).toHaveLength(3)
  } finally {
    vi.useRealTimers()
  }
})

test('two tenant readers discard prior addresses, late responses and withdrawn access', async () => {
  let finishLate: ((response: Response) => void) | undefined
  let calls = 0
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      calls++
      if (calls === 1) return jsonResponse(sourceResult('red-only'))
      if (calls === 2)
        return new Promise<Response>((resolve) => {
          finishLate = resolve
        })
      return jsonResponse(sourceResult('blue-only'))
    }),
  )
  const view = render(<View />)
  await userEvent.type(screen.getByLabelText('Address for service sources'), '192.0.2.7')
  await userEvent.click(screen.getByRole('button', { name: 'Look up service sources' }))
  await screen.findByText('red-only candidate 23')
  await userEvent.click(screen.getByRole('button', { name: 'Look up service sources' }))
  await waitFor(() => expect(finishLate).toBeDefined())
  view.rerender(<View tenant="blue" />)
  expect(screen.getByLabelText('Address for service sources')).toHaveValue('')
  expect(screen.queryByText(/red-only/)).not.toBeInTheDocument()
  await act(async () => {
    finishLate?.(jsonResponse(sourceResult('late-red-only')))
  })
  expect(screen.queryByText(/red-only/)).not.toBeInTheDocument()
  await userEvent.type(screen.getByLabelText('Address for service sources'), '192.0.2.7')
  await userEvent.click(screen.getByRole('button', { name: 'Look up service sources' }))
  await screen.findByText('blue-only candidate 23')
  view.rerender(<View tenant="blue" permissions={[]} />)
  expect(screen.queryByText(/blue-only/)).not.toBeInTheDocument()
  expect(screen.queryByLabelText('Address for service sources')).not.toBeInTheDocument()
})

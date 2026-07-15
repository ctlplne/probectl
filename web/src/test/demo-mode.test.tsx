// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { apiFetch, setDemoTransportIsolation } from '../api/client'
import { defaultFetch } from './fetchStub'
import { renderApp } from './renderApp'

afterEach(() => setDemoTransportIsolation(false))

function requestedPaths(fetcher: ReturnType<typeof vi.fn>): string[] {
  return fetcher.mock.calls.map(([input]) => {
    const raw =
      typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url
    return new URL(raw, 'https://probectl.test').pathname
  })
}

describe('transport-isolated demo mode', () => {
  test('is persistent, unmistakable, and never mounts live tenant routes', async () => {
    const fetcher = defaultFetch() as ReturnType<typeof vi.fn>
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets?demo=1')

    expect(
      await screen.findByRole('heading', { name: /sample network workspace/i }),
    ).toBeInTheDocument()
    expect(screen.getByLabelText(/demo mode is active/i)).toBeInTheDocument()
    expect(screen.getAllByText('Demo data')).toHaveLength(4)
    expect(screen.queryByRole('heading', { name: /targets & tests/i })).toBeNull()
    expect(requestedPaths(fetcher)).not.toContain('/v1/tests')
    expect(requestedPaths(fetcher)).not.toContain('/v1/alerts')

    await userEvent.click(screen.getByRole('link', { name: /incidents/i }))
    expect(screen.getByLabelText(/demo mode is active/i)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /sample network workspace/i })).toBeInTheDocument()
    expect(requestedPaths(fetcher)).not.toContain('/v1/incidents')
  })

  test('Shift+D exits in one keyboard command and only then permits the live route query', async () => {
    const fetcher = defaultFetch() as ReturnType<typeof vi.fn>
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets?demo=1')
    await screen.findByLabelText(/demo mode is active/i)

    fireEvent.keyDown(document, { key: 'D', shiftKey: true })

    await waitFor(() => expect(screen.queryByLabelText(/demo mode is active/i)).toBeNull())
    expect(await screen.findByRole('heading', { name: /targets & tests/i })).toBeInTheDocument()
    await waitFor(() => expect(requestedPaths(fetcher)).toContain('/v1/tests'))
    expect(screen.queryByLabelText(/sample preview/i)).toBeNull()
  })

  test('the API client fails closed if a future demo component attempts a live request', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    setDemoTransportIsolation(true)

    await expect(apiFetch('/alerts')).rejects.toThrow(/live tenant APIs are disabled/i)
    expect(fetcher).not.toHaveBeenCalled()
  })
})

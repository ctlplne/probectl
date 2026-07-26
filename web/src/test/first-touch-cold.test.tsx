// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { coldFetch } from './fetchStub'
import { renderApp } from './renderApp'

/**
 * Install day, pinned: a freshly deployed control plane (cold fixture
 * profile) must greet the operator with honest states that lead somewhere —
 * and the big empty screens offer the isolated sample tour as a secondary
 * path. No screen may leak populated fixture data in the cold profile.
 */
describe('cold start — the first thirty minutes', () => {
  test('dashboards: honest cold state, no populated leak, sample bridge present', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/dashboards')

    expect(await screen.findByRole('heading', { name: /^dashboards$/i })).toBeInTheDocument()
    // No populated fixture rows may leak into the cold profile.
    expect(screen.queryByText('checkout latency burn')).toBeNull()
    // At least one cold surface offers the sample tour bridge.
    expect((await screen.findAllByRole('link', { name: /see a sample/i })).length).toBeGreaterThan(
      0,
    )
  })

  test('incidents: empty state carries the sample bridge, and it lands in the tour', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/incidents')

    expect(await screen.findByRole('heading', { name: /^incidents$/i })).toBeInTheDocument()
    const bridge = await screen.findByRole('link', { name: /see a sample/i })

    await userEvent.click(bridge)
    // Same route, now populated by the isolated tour — banner unmistakable.
    expect(await screen.findByLabelText(/demo mode is active/i)).toBeInTheDocument()
    expect(screen.getByText('Checkout latency regression')).toBeInTheDocument()
  })

  test('topology: cold graph is a truthful state, not an empty canvas', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/topology')

    expect(await screen.findByRole('heading', { name: /topology/i })).toBeInTheDocument()
    expect(screen.queryByText('edge-r1')).toBeNull()
  })

  test('targets: the real primary action (create a test) survives the cold profile', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/targets')

    expect(await screen.findByRole('heading', { name: /targets & tests/i })).toBeInTheDocument()
    expect(screen.queryByText('checkout-http')).toBeNull()
  })

  test('onboarding: derives step one from the cold lists, never complete', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/onboarding')

    const heading = await screen.findByRole('heading', { name: /first-run setup/i })
    expect(heading).toBeInTheDocument()
    expect(screen.queryByText(/all set|setup complete/i)).toBeNull()
  })

  test('cost: blocked engine points to native flow readiness', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/cost')

    const action = await screen.findByRole('button', { name: 'Open flow readiness' })
    await userEvent.click(action)

    expect(await screen.findByRole('heading', { name: /^planes$/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /flow/i })).toHaveAttribute('aria-selected', 'true')
  })

  test('SLOs: empty state opens the filtered local OpenAPI catalog', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/slos')

    const action = await screen.findByRole('button', { name: 'Open OpenSLO API' })
    await userEvent.click(action)

    expect(await screen.findByRole('heading', { name: /^api docs$/i })).toBeInTheDocument()
    expect(await screen.findByLabelText('Filter operations')).toHaveValue('slos')
    const operations = await screen.findByRole('table', { name: 'API operations' })
    expect(within(operations).getByText('/v1/slos')).toBeInTheDocument()
  })

  test('API docs: cold fixture serves the shipping operation catalog', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/docs/api')

    const operations = await screen.findByRole('table', { name: 'API operations' })
    expect(within(operations).getByText('/v1/cost/summary')).toBeInTheDocument()
    expect(within(operations).getByText('/v1/slos')).toBeInTheDocument()
    expect(screen.queryByText('Could not load /openapi.json.')).toBeNull()
  })
})

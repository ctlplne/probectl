// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { pivotHref } from '../routes/pivotContext'
import { pathRounds, stubPathHistoryFetch } from './pathHistoryFixture'
import type { MeasuredRequest } from './journeys/measurement'

function stubClipboard() {
  const writeText = vi.fn().mockResolvedValue(undefined)
  Object.defineProperty(window.navigator, 'clipboard', {
    configurable: true,
    value: { writeText },
  })
  return writeText
}

describe('path history', () => {
  test('current path identity keeps paired tenants with the same private hop separate', async () => {
    const red = {
      tenant: '00000000-0000-4000-8000-000000000101',
      context: '00000000-0000-4000-8000-000000000201',
      entity: '00000000-0000-4000-8000-000000000301',
    }
    const blue = {
      tenant: '00000000-0000-4000-8000-000000000102',
      context: '00000000-0000-4000-8000-000000000202',
      entity: '00000000-0000-4000-8000-000000000302',
    }
    const redRequests: MeasuredRequest[] = []
    stubPathHistoryFetch(redRequests, red)
    renderApp('/path', {
      me: { tenant_id: red.tenant, permissions: ['test.read', 'entities.read', 'agent.write'] },
    })
    const redCard = (await screen.findByText(red.entity)).closest('[data-path-entities]')
    expect(redCard).toHaveTextContent('10.0.0.2')
    expect(redRequests.every((request) => !request.url.includes('tenant_id='))).toBe(true)
    cleanup()

    const blueRequests: MeasuredRequest[] = []
    stubPathHistoryFetch(blueRequests, blue)
    renderApp('/path', {
      me: { tenant_id: blue.tenant, permissions: ['test.read', 'entities.read', 'agent.write'] },
    })
    const blueCard = (await screen.findByText(blue.entity)).closest('[data-path-entities]')
    expect(blueCard).toHaveTextContent('10.0.0.2')
    expect(blueCard).not.toHaveTextContent(red.entity)
    expect(blueRequests.every((request) => !request.url.includes('tenant_id='))).toBe(true)
  })

  test('keeps an unbound private-address path unresolved on the identity surface', async () => {
    stubPathHistoryFetch()
    renderApp('/path', { me: { permissions: ['test.read', 'entities.read', 'agent.write'] } })
    const card = await screen.findByText('Current path identity')
    await waitFor(() =>
      expect(card.closest('[data-path-entities]')).toHaveTextContent(
        'Routing context not assigned',
      ),
    )
    expect(screen.queryByRole('table', { name: /latest path responders/i })).not.toBeInTheDocument()
  })

  test('asks for a fresh trace after assigning a routing context', async () => {
    const context = '00000000-0000-4000-8000-000000000209'
    stubPathHistoryFetch([], undefined, context)
    renderApp('/path', { me: { permissions: ['test.read', 'entities.read', 'agent.write'] } })
    const card = await screen.findByText('Current path identity')
    await waitFor(() =>
      expect(card.closest('[data-path-entities]')).toHaveTextContent('Run a new path discovery'),
    )
    await waitFor(() =>
      expect(
        within(card.closest('[data-path-entities]') as HTMLElement).getByLabelText(
          'Routing context for this test',
        ),
      ).toHaveValue(context),
    )
    expect(screen.queryByRole('table', { name: /latest path responders/i })).not.toBeInTheDocument()
  })

  test('scrubs rounds and distinguishes common, changed, and unique responders', async () => {
    const user = userEvent.setup()
    stubPathHistoryFetch()
    renderApp('/path')

    const history = await screen.findByRole('region', {
      name: /path history and comparison/i,
    })
    expect(screen.getByRole('group', { name: /network path to 9\.9\.9\.9/i })).toHaveTextContent(
      '10.0.0.3',
    )

    await user.selectOptions(within(history).getByLabelText(/compare with/i), 'round-previous')
    const summary = await screen.findByRole('status', { name: /path comparison summary/i })
    expect(summary).toHaveTextContent('2 common')
    expect(summary).toHaveTextContent('1 changed')
    expect(summary).toHaveTextContent('1 unique to selected')
    expect(summary).toHaveTextContent('1 unique to comparison')

    const comparison = screen.getByRole('table', {
      name: /side-by-side selected path round comparison/i,
    })
    expect(within(comparison).getByText('10.0.0.3').closest('tr')).toHaveTextContent(
      /unique to selected/i,
    )
    expect(within(comparison).getByText('10.0.0.4').closest('tr')).toHaveTextContent(
      /unique to comparison/i,
    )

    fireEvent.change(screen.getByLabelText(/path history round/i), {
      target: { value: '1' },
    })
    await waitFor(() =>
      expect(screen.getByRole('group', { name: /network path to 9\.9\.9\.9/i })).toHaveTextContent(
        '10.0.0.4',
      ),
    )
  })

  test('uses the shared clock for exact evidence pivots without dropping path context', async () => {
    const user = userEvent.setup()
    stubPathHistoryFetch()
    renderApp('/path')

    const history = await screen.findByRole('region', {
      name: /path history and comparison/i,
    })
    await user.selectOptions(within(history).getByLabelText(/compare with/i), 'round-previous')
    await user.click(screen.getByRole('button', { name: /inspect worst hop/i }))
    await user.click(screen.getByRole('button', { name: /close/i }))

    const incidentLink = await screen.findByRole('link', {
      name: /open incident evidence: loss on one ecmp branch/i,
    })
    const incidentURL = new URL(incidentLink.getAttribute('href')!, 'https://probectl.invalid')
    expect(incidentURL.searchParams.get('ctx_incident')).toBe('inc-path')
    expect(incidentURL.searchParams.get('ctx_from')).toBe('2026-07-14T12:00:00.000Z')
    expect(incidentURL.searchParams.get('ctx_to')).toBe('2026-07-14T12:05:00.000Z')
    expect(incidentURL.searchParams.get('ctx_selected_id')).toBe('2:10.0.0.2')
    expect(incidentURL.searchParams.getAll('ctx_filter')).toEqual(
      expect.arrayContaining([
        'path_test:t1',
        'path_round:round-current',
        'compare_round:round-previous',
      ]),
    )
    expect(incidentURL.search).not.toMatch(/tenant/i)

    const changeLink = screen.getByRole('link', {
      name: /open change evidence: edge route policy deployed/i,
    })
    const changeURL = new URL(changeLink.getAttribute('href')!, 'https://probectl.invalid')
    expect(changeURL.pathname).toBe('/explore')
    expect(changeURL.searchParams.get('filter')).toBe('id:change-path')
    expect(changeURL.searchParams.get('ctx_selected_id')).toBe('2:10.0.0.2')
    expect(changeURL.searchParams.getAll('ctx_filter')).toContain('path_test:t1')
  })

  test('fails closed for copied foreign round IDs and emits an authorized stable link', async () => {
    const user = userEvent.setup()
    const requests: { url: string }[] = []
    const writeText = stubClipboard()
    stubPathHistoryFetch(requests)
    const foreignLink = pivotHref('/path', {
      filters: {
        path_test: 't1',
        path_round: 'foreign-round',
        compare_round: 'foreign-comparison',
      },
      expiresAt: '2099-01-01T00:00:00Z',
    })
    renderApp(foreignLink)

    await screen.findByRole('group', { name: /network path to 9\.9\.9\.9/i })
    await waitFor(() =>
      expect(
        requests.some(
          (request) =>
            request.url.includes('round_id=foreign-round') &&
            request.url.includes('round_id=foreign-comparison'),
        ),
      ).toBe(true),
    )
    expect(screen.queryByText(/foreign-round/i)).not.toBeInTheDocument()

    await user.click(await screen.findByRole('button', { name: /copy stable path link/i }))
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce())
    const copied = String(writeText.mock.calls[0][0])
    expect(copied).toContain(`path_round%3A${pathRounds[0].id}`)
    expect(copied).not.toContain('foreign-round')
    expect(copied).not.toContain('foreign-comparison')
    expect(copied).not.toMatch(/tenant/i)
  })
})

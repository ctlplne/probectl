// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { pivotHref } from '../routes/pivotContext'
import { pathRounds, stubPathHistoryFetch } from './pathHistoryFixture'

function stubClipboard() {
  const writeText = vi.fn().mockResolvedValue(undefined)
  Object.defineProperty(window.navigator, 'clipboard', {
    configurable: true,
    value: { writeText },
  })
  return writeText
}

describe('path history', () => {
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

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import { stubPathFetch } from './pathFixture'

describe('path visualization', () => {
  test('renders the path, marks the lossy hop, and opens the drill-down', async () => {
    const user = userEvent.setup()
    stubPathFetch()
    renderApp('/path')

    await screen.findByRole('heading', { name: /path & topology/i })
    await screen.findByRole('group', { name: /network path to 9\.9\.9\.9/i })

    // The lossy ECMP branch is a focusable node whose accessible name states the loss.
    const lossy = await screen.findByRole('button', { name: /10\.0\.0\.2.*66% loss/i })
    lossy.focus()
    expect(lossy).toHaveFocus()

    // Keyboard-operable: Enter opens the per-hop drill-down with its MPLS labels.
    await user.keyboard('{Enter}')
    const dialog = await screen.findByRole('dialog', { name: /hop 2 .*10\.0\.0\.2/i })
    expect(within(dialog).getByText(/16001/)).toBeInTheDocument()
  })

  test('exposes an accessible per-hop table alternative', async () => {
    stubPathFetch()
    renderApp('/path')
    const table = await screen.findByRole('table', { name: /path to 9\.9\.9\.9 by hop/i })
    expect(within(table).getByText('10.0.0.2')).toBeInTheDocument()
    expect(within(table).getByText('9.9.9.9 (destination)')).toBeInTheDocument()
  })

  test('shows an empty state when no path has been discovered', async () => {
    stubPathFetch(null)
    renderApp('/path')
    expect(await screen.findByText(/no path discovered yet/i)).toBeInTheDocument()
  })

  test('loads additional test pages into the path selector', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://t.invalid')
        const method = init?.method ?? 'GET'
        if (url.pathname === '/v1/tests' && method === 'GET') {
          const after = url.searchParams.get('after')
          if (!after) {
            return jsonResponse({
              items: [
                {
                  id: 't1',
                  name: 'first-path-test',
                  type: 'icmp',
                  target: '1.1.1.1',
                  interval_seconds: 30,
                  timeout_seconds: 3,
                  params: {},
                  enabled: true,
                  created_at: '',
                  updated_at: '',
                },
              ],
              next_cursor: 'cursor-2',
            })
          }
          if (after === 'cursor-2') {
            return jsonResponse({
              items: [
                {
                  id: 't2',
                  name: 'second-path-test',
                  type: 'icmp',
                  target: '9.9.9.9',
                  interval_seconds: 30,
                  timeout_seconds: 3,
                  params: {},
                  enabled: true,
                  created_at: '',
                  updated_at: '',
                },
              ],
            })
          }
        }
        if (url.pathname === '/v1/tests/t1/path') {
          return jsonResponse({ error: { code: 'not_found', message: 'no path' } }, 404)
        }
        return jsonResponse({ error: { code: 'not_found', message: 'no route' } }, 404)
      }),
    )

    renderApp('/path')
    await screen.findByRole('option', { name: 'first-path-test' })
    expect(screen.queryByRole('option', { name: 'second-path-test' })).toBeNull()

    await user.click(screen.getByRole('button', { name: /load more tests/i }))

    expect(await screen.findByRole('option', { name: 'second-path-test' })).toBeInTheDocument()
  })

  test('the path page has no axe violations', async () => {
    stubPathFetch()
    const { container } = renderApp('/path')
    await screen.findByRole('group', { name: /network path/i })
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })
})

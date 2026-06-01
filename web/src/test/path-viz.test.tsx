import { describe, expect, test } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
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

  test('the path page has no axe violations', async () => {
    stubPathFetch()
    const { container } = renderApp('/path')
    await screen.findByRole('group', { name: /network path/i })
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })
})

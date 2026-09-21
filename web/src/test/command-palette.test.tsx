// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { renderApp } from './renderApp'
import {
  JOURNEY_KEYBOARD_ACTIONS,
  JOURNEY_PALETTE_COMMANDS,
  journeyCommandHref,
  renderJourneyCommandReference,
} from '../shell/journeyCommands'
import { parsePivotContext } from '../routes/pivotContext'

describe('command palette (keyboard-first)', () => {
  test('opens with ⌘K, filters, runs the active command on Enter, and restores focus', async () => {
    const user = userEvent.setup()
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })

    const trigger = screen.getByRole('button', { name: /search or run a command/i })
    trigger.focus()
    expect(trigger).toHaveFocus()

    await user.keyboard('{Meta>}k{/Meta}')

    const input = await screen.findByRole('combobox', { name: /search commands/i })
    expect(input).toHaveFocus()
    const listbox = screen.getByRole('listbox')
    expect(listbox).toBeInTheDocument()

    await user.type(input, 'Security')
    const options = within(listbox).getAllByRole('option')
    expect(options[0]).toHaveTextContent(/security/i)
    expect(options[0]).toHaveAttribute('aria-selected', 'true')

    await user.keyboard('{Enter}')

    await screen.findByRole('heading', { name: /^security$/i })
    // The PALETTE is closed (the page itself may legitimately contain selects).
    await waitFor(() =>
      expect(screen.queryByRole('combobox', { name: /search commands/i })).not.toBeInTheDocument(),
    )
    expect(trigger).toHaveFocus()
  })

  test('Escape closes the palette and clears its search for the next invocation', async () => {
    const user = userEvent.setup()
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })

    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: /search commands/i })
    await user.type(input, 'Admin & Settings')
    expect(input).toHaveValue('Admin & Settings')

    await user.keyboard('{Escape}')
    await waitFor(() =>
      expect(screen.queryByRole('combobox', { name: /search commands/i })).not.toBeInTheDocument(),
    )

    await user.keyboard('{Meta>}k{/Meta}')
    expect(await screen.findByRole('combobox', { name: /search commands/i })).toHaveValue('')
  })

  test('traps Tab in the combobox and restores the trigger after safe Escape', async () => {
    const user = userEvent.setup()
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })
    const trigger = screen.getByRole('button', { name: /search or run a command/i })
    trigger.focus()

    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: /search commands/i })
    expect(input).toHaveFocus()
    await user.keyboard('{Tab}')
    expect(input).toHaveFocus()
    await user.keyboard('{Shift>}{Tab}{/Shift}')
    expect(input).toHaveFocus()

    await user.keyboard('{Escape}')
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  test('does not offer tenant switching for a single-tenant session', async () => {
    const user = userEvent.setup()
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })

    expect(screen.getByLabelText(/current tenant:/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /switch tenant/i })).not.toBeInTheDocument()

    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: /search commands/i })
    const listbox = screen.getByRole('listbox')
    await user.type(input, 'Switch tenant')
    expect(within(listbox).queryByRole('option')).not.toBeInTheDocument()
  })

  test('exposes task commands and deep-links into human-gated workflows', async () => {
    const user = userEvent.setup()
    renderApp('/targets', { me: { permissions: ['test.write'] } })
    await screen.findByRole('heading', { name: /targets & tests/i })

    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: /search commands/i })
    const listbox = screen.getByRole('listbox')

    for (const label of [
      'Create test',
      'Discover path',
      'Silence alert',
      'Schedule maintenance',
      'Export audit',
      'Open support bundle',
      'Register collector',
    ]) {
      await user.clear(input)
      await user.type(input, label)
      expect(within(listbox).getAllByRole('option')[0]).toHaveTextContent(label)
    }

    await user.clear(input)
    await user.type(input, 'Create test')
    await user.keyboard('{Enter}')
    expect(await screen.findByRole('dialog', { name: 'Create test' })).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(
      await screen.findByRole('combobox', { name: /search commands/i }),
      'Silence alert',
    )
    await user.keyboard('{Enter}')
    expect(
      await screen.findByRole('dialog', { name: /checkout latency burn/i }),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Silence' })).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(
      await screen.findByRole('combobox', { name: /search commands/i }),
      'Schedule maintenance',
    )
    await user.keyboard('{Enter}')
    expect(
      await screen.findByRole('dialog', { name: 'Schedule maintenance window' }),
    ).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(
      await screen.findByRole('combobox', { name: /search commands/i }),
      'Register collector',
    )
    await user.keyboard('{Enter}')
    expect(await screen.findByRole('dialog', { name: 'Register collector' })).toBeInTheDocument()
  })

  test('lists all journey commands and explains unavailable or unauthorized actions', async () => {
    const user = userEvent.setup()
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })
    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: /search commands/i })
    const listbox = screen.getByRole('listbox')

    const expectedLabels = [
      'Start first real insight',
      'Open incident RCA',
      'Share cited incident RCA',
      'Open canonical Explorer',
      'Compare path rounds',
      'Copy stable path link',
      'Simulate selected topology node',
      'Review unhealthy fleet',
      'Open provider fleet exceptions',
      'Open provider tenant provisioning',
      'Open provider usage showback',
    ]
    for (const label of expectedLabels) {
      await user.clear(input)
      await user.type(input, label)
      expect(within(listbox).getAllByRole('option')[0]).toHaveTextContent(label)
    }

    await user.clear(input)
    await user.type(input, 'Share cited incident RCA')
    const unavailable = within(listbox).getByRole('option')
    expect(unavailable).toHaveAttribute('aria-disabled', 'true')
    expect(unavailable).toHaveTextContent(/unavailable until an incident is open/i)
    await user.keyboard('{Enter}')
    expect(screen.getByRole('combobox', { name: /search commands/i })).toBeInTheDocument()
  })

  test('disables state-changing commands for an explicit read-only authority', async () => {
    const user = userEvent.setup()
    renderApp('/targets', { me: { permissions: ['audit.read'] } })
    await screen.findByRole('heading', { name: /targets & tests/i })
    await user.keyboard('{Meta>}k{/Meta}')
    const input = await screen.findByRole('combobox', { name: /search commands/i })
    await user.type(input, 'Create test')

    const option = within(screen.getByRole('listbox')).getByRole('option')
    expect(option).toHaveAttribute('aria-disabled', 'true')
    expect(option).toHaveTextContent(/current read-only authority/i)
  })

  test('journey deep links preserve only the safe X3 contract', () => {
    const command = JOURNEY_PALETTE_COMMANDS.find(
      (candidate) => candidate.id === 'journey:path-compare',
    )
    expect(command).toBeDefined()
    const href = journeyCommandHref(
      command!,
      '/incidents?tenant_id=foreign&ctx_v=1&ctx_expires=2099-01-01T00%3A00%3A00.000Z&ctx_incident=inc-1&ctx_from=2026-07-14T10%3A00%3A00.000Z&ctx_to=2026-07-14T10%3A05%3A00.000Z&ctx_filter=severity%3Acritical&ctx_selected_kind=evidence&ctx_selected_id=E-1',
      new Date('2026-07-14T10:00:00Z'),
    )
    const url = new URL(href, 'https://probectl.invalid')
    const context = parsePivotContext(url.searchParams, { now: new Date('2026-07-14T10:00:00Z') })

    expect(url.pathname).toBe('/path')
    expect(url.searchParams.get('task')).toBe('compare-rounds')
    expect(context.context).toMatchObject({
      incidentId: 'inc-1',
      from: '2026-07-14T10:00:00.000Z',
      to: '2026-07-14T10:05:00.000Z',
      filters: { severity: 'critical' },
      selection: { kind: 'evidence', id: 'E-1' },
    })
    expect(href.toLowerCase()).not.toContain('tenant')
  })

  test('generated reference covers every J1-J6 action and is current', () => {
    const generated = renderJourneyCommandReference()
    const committed = readFileSync(
      resolve(process.cwd(), '../docs/ux/keyboard-command-reference.md'),
      'utf8',
    )

    const normalizeTableSpacing = (value: string) =>
      value
        .split('\n')
        .map((line) =>
          /^\|\s*-+\s*\|/.test(line)
            ? '|---|---|---|---|'
            : line.startsWith('|')
              ? line
                  .split('|')
                  .map((cell) => cell.trim())
                  .join('|')
              : line,
        )
        .join('\n')
    expect(normalizeTableSpacing(committed)).toBe(normalizeTableSpacing(generated))
    for (const journey of ['J1', 'J2', 'J3', 'J4', 'J5', 'J6']) {
      expect(JOURNEY_KEYBOARD_ACTIONS.some((action) => action.journey === journey)).toBe(true)
      expect(JOURNEY_PALETTE_COMMANDS.some((command) => command.journey === journey)).toBe(true)
    }
  })

  test('search input has a tokenized visible focus style', () => {
    const css = readFileSync(resolve(process.cwd(), 'src/shell/CommandPalette.module.css'), 'utf8')

    expect(css).toMatch(
      /\.input:focus-visible\s*{[^}]*outline:\s*var\(--focus-ring-width\)\s+solid\s+var\(--color-focus\);[^}]*outline-offset:\s*var\(--focus-ring-offset\);/s,
    )
  })
})

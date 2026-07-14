// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { renderApp } from './renderApp'

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

  test('Escape closes the palette', async () => {
    const user = userEvent.setup()
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })

    await user.keyboard('{Meta>}k{/Meta}')
    expect(await screen.findByRole('combobox', { name: /search commands/i })).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await waitFor(() =>
      expect(screen.queryByRole('combobox', { name: /search commands/i })).not.toBeInTheDocument(),
    )
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
    renderApp('/targets')
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

  test('search input has a tokenized visible focus style', () => {
    const css = readFileSync(resolve(process.cwd(), 'src/shell/CommandPalette.module.css'), 'utf8')

    expect(css).toMatch(
      /\.input:focus-visible\s*{[^}]*outline:\s*2px\s+solid\s+var\(--color-focus\);[^}]*outline-offset:\s*2px;/s,
    )
  })
})

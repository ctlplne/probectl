import { describe, expect, test } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
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
    expect(screen.getByRole('listbox')).toBeInTheDocument()

    await user.type(input, 'Security')
    const options = screen.getAllByRole('option')
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
    expect(await screen.findByRole('combobox')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('combobox')).not.toBeInTheDocument())
  })

  test('search input has a tokenized visible focus style', () => {
    const css = readFileSync(resolve(process.cwd(), 'src/shell/CommandPalette.module.css'), 'utf8')

    expect(css).toMatch(
      /\.input:focus-visible\s*{[^}]*outline:\s*2px\s+solid\s+var\(--color-focus\);[^}]*outline-offset:\s*2px;/s,
    )
  })
})

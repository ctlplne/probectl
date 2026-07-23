// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '../theme/ThemeProvider'
import { useTheme } from '../theme/useTheme'

function Probe() {
  const { theme, toggleTheme } = useTheme()
  return (
    <button type="button" onClick={toggleTheme}>
      theme:{theme}
    </button>
  )
}

function colorTokensFor(css: string, selector: string): Set<string> {
  // Grab the declaration block whose selector list contains `selector`.
  const re = new RegExp(`([^}]*${selector.replace(/[[\]'.]/g, '\\$&')}[^{]*)\\{([^}]*)\\}`)
  const block = re.exec(css)?.[2] ?? ''
  const names = block.match(/--color-[a-z0-9-]+/g) ?? []
  return new Set(names)
}

describe('deployment theming', () => {
  test('toggling theme swaps the active token set on <html>', async () => {
    const user = userEvent.setup()
    render(
      <ThemeProvider initialTheme="dark">
        <Probe />
      </ThemeProvider>,
    )
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    await user.click(screen.getByRole('button'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('aurora')
  })

  test('every theme defines the same color tokens, so a swap re-themes the whole UI', () => {
    const css = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8')
    const dark = colorTokensFor(css, "[data-theme='dark']")
    const aurora = colorTokensFor(css, "[data-theme='aurora']")
    const ember = colorTokensFor(css, "[data-theme='ember']")

    expect(dark.size).toBeGreaterThan(10)
    expect([...aurora].sort()).toEqual([...dark].sort())
    expect([...ember].sort()).toEqual([...dark].sort())
  })
})

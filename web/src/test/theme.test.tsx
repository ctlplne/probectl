// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test, vi } from 'vitest'
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

// DPR-247: escape EVERY regex metacharacter, not four of them. CodeQL
// js/incomplete-sanitization is right about the pattern even though the input here
// is a test literal: `[[\]'.]` misses ( ) * + ? { } | ^ $ - and backslash, so a
// selector containing any of them would build a regex that silently matches the
// wrong declaration block — a contrast test that passes while testing nothing.
const escapeForRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')

function colorTokensFor(css: string, selector: string): Set<string> {
  // Grab the declaration block whose selector list contains `selector`.
  const re = new RegExp(`([^}]*${escapeForRegExp(selector)}[^{]*)\\{([^}]*)\\}`)
  const block = re.exec(css)?.[2] ?? ''
  const names = block.match(/--color-[a-z0-9-]+/g) ?? []
  return new Set(names)
}

describe('deployment theming', () => {
  test('reads and writes the browser-scoped theme preference', () => {
    const getItem = vi.fn(() => 'ember')
    const setItem = vi.fn()
    const original = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      enumerable: true,
      value: { getItem, setItem },
    })

    try {
      render(
        <ThemeProvider initialTheme="dark">
          <Probe />
        </ThemeProvider>,
      )

      expect(screen.getByRole('button')).toHaveTextContent('theme:ember')
      expect(getItem).toHaveBeenCalledWith('probectl.theme')
      expect(setItem).toHaveBeenCalledWith('probectl.theme', 'ember')
    } finally {
      if (original) Object.defineProperty(window, 'localStorage', original)
      else Reflect.deleteProperty(window, 'localStorage')
    }
  })

  test('does not invoke a non-browser storage placeholder', () => {
    const getStorage = vi.fn(() => {
      throw new Error('placeholder must not be invoked')
    })
    const original = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      enumerable: false,
      get: getStorage,
    })

    try {
      render(
        <ThemeProvider initialTheme="dark">
          <Probe />
        </ThemeProvider>,
      )

      expect(screen.getByRole('button')).toHaveTextContent('theme:dark')
      expect(getStorage).not.toHaveBeenCalled()
    } finally {
      if (original) Object.defineProperty(window, 'localStorage', original)
      else Reflect.deleteProperty(window, 'localStorage')
    }
  })

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

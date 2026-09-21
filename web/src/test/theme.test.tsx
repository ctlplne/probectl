// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
  const names = block.match(/--[a-z0-9-]+/g) ?? []
  return new Set(names)
}

describe('deployment theming', () => {
  test('reads and writes the browser-scoped theme preference', () => {
    const getItem = vi.fn(() => 'dark')
    const setItem = vi.fn()
    const original = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      enumerable: true,
      value: { getItem, setItem },
    })

    try {
      render(
        <ThemeProvider initialTheme="light">
          <Probe />
        </ThemeProvider>,
      )

      expect(screen.getByRole('button')).toHaveTextContent('theme:dark')
      expect(getItem).toHaveBeenCalledWith('probectl.theme')
      expect(setItem).toHaveBeenCalledWith('probectl.theme', 'dark')
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
      <ThemeProvider initialTheme="light">
        <Probe />
      </ThemeProvider>,
    )
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    await user.click(screen.getByRole('button'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    // Tailwind's dark: utilities key off the CLASS, so the attribute alone
    // would leave every utility-styled surface in its light form.
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })

  test('both themes define the same tokens, so a swap re-themes the whole UI', () => {
    const css = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8')
    // Light is :root (the default operator theme); dark overrides it.
    const light = colorTokensFor(css, 'color-scheme: light')
    const dark = colorTokensFor(css, "[data-theme='dark']")

    expect(light.size).toBeGreaterThan(30)
    expect([...dark].sort()).toEqual([...light].sort())
  })
})

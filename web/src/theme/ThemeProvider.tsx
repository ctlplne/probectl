// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { createContext, useCallback, useEffect, useState, type ReactNode } from 'react'

export type ThemeName = 'dark' | 'aurora' | 'ember'

const THEMES: ThemeName[] = ['dark', 'aurora', 'ember']
const STORAGE_KEY = 'probectl.theme'

export interface ThemeContextValue {
  theme: ThemeName
  themes: ThemeName[]
  setTheme: (t: ThemeName) => void
  toggleTheme: () => void
}

// eslint-disable-next-line react-refresh/only-export-components
export const ThemeContext = createContext<ThemeContextValue | null>(null)

function isTheme(v: unknown): v is ThemeName {
  return THEMES.includes(v as ThemeName)
}

function browserStorage(): Storage | undefined {
  if (typeof window === 'undefined') return undefined
  const descriptor = Object.getOwnPropertyDescriptor(window, 'localStorage')
  // Node 26 exposes a non-enumerable experimental global with this name. In a
  // jsdom fallback it can replace the browser Web Storage attribute, and merely
  // invoking its getter emits a warning. Web-IDL Window attributes are
  // enumerable, so reject the non-browser placeholder without touching it.
  if (descriptor && descriptor.enumerable === false) return undefined
  try {
    return window.localStorage
  } catch {
    return undefined
  }
}

function readInitial(fallback: ThemeName): ThemeName {
  try {
    const stored = browserStorage()?.getItem(STORAGE_KEY)
    if (isTheme(stored)) return stored
  } catch {
    /* storage unavailable — fall back */
  }
  return fallback
}

/**
 * ThemeProvider applies the active theme to <html data-theme>, which selects the
 * token set. Deployment-level operator overrides layer onto these tokens with
 * no component changes. The single intentional use of
 * localStorage is the operator's theme preference (CLAUDE.md §7 guardrail 11).
 */
export function ThemeProvider({
  children,
  initialTheme = 'dark',
}: {
  children: ReactNode
  initialTheme?: ThemeName
}) {
  const [theme, setThemeState] = useState<ThemeName>(() => readInitial(initialTheme))

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try {
      browserStorage()?.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore */
    }
  }, [theme])

  const setTheme = useCallback((t: ThemeName) => setThemeState(t), [])
  // Cycles the shipped set in order (dark → aurora → ember → dark …).
  const toggleTheme = useCallback(
    () => setThemeState((t) => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length]),
    [],
  )

  return (
    <ThemeContext.Provider value={{ theme, themes: THEMES, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}
